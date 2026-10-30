"""Engine holds all fasten runtime state.

``fasten.init``, ``fasten.emit`` and the other module functions use a default
Engine. Construct more when one process needs separate configurations:

    tenant_a = fasten.Engine()
    tenant_a.init(tenant_id="tenant-a", audit_store=store_a, ...)
    tenant_a.emit(code="ORDER_PLACED", ...)

    tenant_b = fasten.Engine()
    tenant_b.init(tenant_id="tenant-b", audit_store=store_b, ...)
    tenant_b.emit(code="ORDER_PLACED", ...)
"""
from __future__ import annotations

import atexit
import dataclasses
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .attrs import AuditRow
from .canonical_ts import canonical_now, parse_canonical
from .chain import ChainVerifyResult, _canonical_json, _row_hash, seal, verify_chain
from .codes import Severity, meta_of
from .context import current_request_id, mint_id
from . import core_ffi as _ffi
from .redact import Redactor
from .transport.stdout import StdoutTransport

# The chain helpers live in fasten.chain; re-exported here for existing imports.
__all__ = [
    "AuditStoreError",
    "ChainVerifyResult",
    "Engine",
    "FastenConfig",
    "verify_chain",
    "seal",
    "_row_hash",
    "_canonical_json",
]


class AuditStoreError(RuntimeError):
    """Raised by ``emit()`` in ``raise`` mode when the store insert fails."""


@dataclasses.dataclass
class FastenConfig:
    """Resolved fasten runtime configuration. Build via init_config(); apply via Engine.start()."""
    service_id: str
    node_id: str
    tenant_id: Optional[str]
    audit_store: Any
    api_store: Any
    syslog_store: Any
    redact_replacement: str
    extra_redact_keys: Optional[list[str]]
    extra_value_redact_patterns: Optional[list[tuple[str, str, str]]]
    audit_store_failure_strategy: str
    queue_capacity: int
    queue_retry_initial_ms: int
    queue_retry_max_ms: int
    queue_retry_jitter: bool
    queue_drain_max_attempts: int
    search_enabled: bool
    # Age-based purge of the api/sys stream stores, as duration strings
    # ("7d", "24h"). None disables.
    retention_api: Optional[str]
    retention_syslog: Optional[str]
    # Audit rows of pii codes older than this have detail and detail_salt
    # destroyed. Audit rows are never deleted, since that would break the
    # chain (spec 7.1).
    retention_pii: Optional[str]
    # Streams ("api", "sys") expected to have a store. If set, start() fails
    # unless it matches the attached stores exactly. None means "whatever has
    # a store". Audit persistence is controlled by audit_store alone.
    persist_streams: Optional[frozenset[str]]


def _pick(arg: Optional[str], env_name: str, default: str = "") -> str:
    if arg is not None:
        return arg
    v = os.environ.get(env_name)
    return v if v is not None else default


def _store_from_dsn(dsn: str) -> Any:
    """Return the correct store implementation for a given DSN."""
    if dsn.startswith(("postgres://", "postgresql://")):
        from .store.postgres import PostgresStore
        return PostgresStore.from_dsn(dsn)
    from .store.sqlite import SQLiteStore
    return SQLiteStore.from_dsn(dsn)


_STREAM_DSN_SCHEMES = ("sqlite", "postgres", "postgresql", "")


def _stream_store_from_dsn(dsn: str, default_table: str) -> Any:
    """Build an api/sys stream store from a DSN.

    ``postgres://`` and ``postgresql://`` give a PostgresStreamStore;
    ``sqlite:///path`` or a bare path gives a SQLite StreamStore. Any other
    scheme (e.g. ``postgresql+psycopg://``) raises ValueError rather than
    quietly becoming a local SQLite file.
    """
    from urllib.parse import parse_qs, urlparse

    u = urlparse(dsn)
    scheme = u.scheme.lower()
    if scheme not in _STREAM_DSN_SCHEMES:
        raise ValueError(
            f"fasten: stream DSN scheme {scheme!r} not supported "
            f"(dsn={dsn!r}). Use sqlite:///./streams.db, postgres://..., or a "
            "bare filesystem path."
        )
    if scheme in ("postgres", "postgresql"):
        from .store.stream_postgres import PostgresStreamStore
        return PostgresStreamStore.from_dsn(dsn, default_table)
    from .store.stream import StreamStore

    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    # SQLAlchemy-style paths: strip only the one separator slash, so
    # sqlite:///rel.db is relative and sqlite:////abs/path.db is absolute.
    path = u.path
    if u.scheme and path.startswith("/"):
        path = path[1:]
    if not path:
        raise ValueError(
            f"fasten: stream DSN {dsn!r} has no path. Use sqlite:///./streams.db"
        )
    return StreamStore(path=path, table=q.get("table", default_table),
                       wal=q.get("wal", "true") != "false")


class Engine:
    """One fasten runtime: service identity, redactor, stores, transport and
    the audit queue drainer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._boot_request_id: Optional[str] = None

        self._service_id: str = ""
        self._node_id: str = ""
        self._tenant_id: Optional[str] = None
        self._audit_store: Any = None
        self._api_store: Any = None
        self._syslog_store: Any = None
        self._stdout: Optional[StdoutTransport] = None
        self._redactor: Redactor = Redactor()
        self._failure_strategy: str = "queue"
        self._search_enabled: bool = False
        self._stdlib_logger = logging.getLogger("fasten")

        self._unchained_store_logged: bool = False
        self._audit_chain_unavailable: bool = False
        # The fasten-core drainer does not allocate monotonic_seq/prev_hash
        # (spec 2.1), so emit() stores audit rows directly while this is False.
        self._drainer_allocates: bool = False
        self._drainer_bypass_logged: bool = False
        self._drainer_handle: Any = None          # FastenStore* (ctypes void ptr)
        self._drainer_callback: Any = None        # must outlive the handle
        self._drainer_lock = threading.Lock()
        self._atexit_registered = False
        self._last_init_at: Optional[datetime] = None

        # Set when an audit insert failed and was dropped. Kept here as well
        # as on the store because AuditRepository does not require
        # note_write_failure(). Stays set until the next start().
        self._audit_write_swallowed: bool = False

        # One purger thread per configured stream; see retention.start_purger.
        self._retention_stop: threading.Event = threading.Event()
        self._retention_threads: list[threading.Thread] = []

        self.log: _Logger = _Logger(self)

    def init_config(
        self,
        service_id: Optional[str] = None,
        node_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        audit_store: Any = None,
        api_store: Any = None,
        syslog_store: Any = None,
        extra_redact_keys: Optional[list[str]] = None,
        redact_replacement: Optional[str] = None,
        extra_value_redact_patterns: Optional[list[tuple[str, str, str]]] = None,
        audit_store_failure_strategy: str = "queue",
        queue_capacity: int = 100,
        queue_retry_initial_ms: int = 100,
        queue_retry_max_ms: int = 60_000,
        queue_retry_jitter: bool = True,
        queue_drain_max_attempts: int = 50,
        search_enabled: bool = False,
        retention_api: Optional[str] = None,
        retention_syslog: Optional[str] = None,
        retention_pii: Optional[str] = None,
        persist_streams: Optional[list[str] | set[str] | frozenset[str]] = None,
    ) -> FastenConfig:
        """Resolve arguments and environment variables into a FastenConfig.

        Starts no threads, so it is safe to call before the event loop
        exists. If a DSN comes from the environment, the store is built here,
        which opens a connection and creates the table.
        """
        svc = _pick(service_id, "FASTEN_SERVICE_ID")
        node = _pick(node_id, "FASTEN_NODE_ID")
        if not svc or not node:
            raise RuntimeError("fasten.init_config: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required")

        env_tid = os.environ.get("FASTEN_TENANT_ID")
        tid = tenant_id if tenant_id is not None else (env_tid or None)

        resolved_store = audit_store
        if resolved_store is None:
            dsn = os.environ.get("FASTEN_AUDIT_DSN")
            if dsn:
                resolved_store = _store_from_dsn(dsn)
            # With neither, rows only go to stdout.

        # Without a store the api/sys streams are kept in memory only.
        resolved_api_store = api_store
        if resolved_api_store is None:
            dsn = os.environ.get("FASTEN_API_DSN")
            if dsn:
                resolved_api_store = _stream_store_from_dsn(dsn, "api_log")

        resolved_syslog_store = syslog_store
        if resolved_syslog_store is None:
            dsn = os.environ.get("FASTEN_SYSLOG_DSN")
            if dsn:
                resolved_syslog_store = _stream_store_from_dsn(dsn, "syslog")

        raw_keys = extra_redact_keys or (
            os.environ.get("FASTEN_REDACT_KEYS", "").split(",")
            if os.environ.get("FASTEN_REDACT_KEYS") else None
        )
        replacement = _pick(redact_replacement, "FASTEN_REDACT_REPLACEMENT", "***")

        env_strategy = os.environ.get("FASTEN_AUDIT_STORE_FAILURE_STRATEGY")
        strategy = (env_strategy or audit_store_failure_strategy or "queue").lower()
        if strategy not in ("queue", "raise"):
            raise RuntimeError(
                f"fasten.init_config: audit_store_failure_strategy must be 'queue' or 'raise' "
                f"(got {strategy!r})"
            )

        # Search also needs a syslog store; without one, reads report
        # "search requires sys persistence".
        env_search = os.environ.get("FASTEN_SEARCH_ENABLED")
        search_on = search_enabled or (env_search or "").lower() in ("1", "true", "yes")

        # The environment is used only when the argument is None; an empty
        # value counts as unset.
        ret_api = retention_api if retention_api is not None else (os.environ.get("FASTEN_RETENTION_API") or None)
        ret_sys = retention_syslog if retention_syslog is not None else (os.environ.get("FASTEN_RETENTION_SYSLOG") or None)
        ret_pii = retention_pii if retention_pii is not None else (os.environ.get("FASTEN_RETENTION_PII") or None)

        # Checked against the attached stores in start(), not here.
        env_ps = os.environ.get("FASTEN_PERSIST_STREAMS")
        if persist_streams is not None:
            ps: Optional[frozenset[str]] = frozenset(persist_streams)
        elif env_ps:
            ps = frozenset(s.strip() for s in env_ps.split(",") if s.strip())
        else:
            ps = None
        if ps is not None:
            allowed = {"api", "sys"}
            unknown = ps - allowed
            if unknown:
                raise RuntimeError(
                    f"fasten.init_config: persist_streams={sorted(ps)}: "
                    f"unknown stream(s) {sorted(unknown)}. "
                    f"Only {sorted(allowed)} are valid (audit persistence is "
                    "driven by audit_store, not persist_streams)."
                )

        return FastenConfig(
            service_id=svc,
            node_id=node,
            tenant_id=tid,
            audit_store=resolved_store,
            api_store=resolved_api_store,
            syslog_store=resolved_syslog_store,
            redact_replacement=replacement,
            extra_redact_keys=[k.strip() for k in raw_keys if k.strip()] if raw_keys else None,
            extra_value_redact_patterns=extra_value_redact_patterns,
            audit_store_failure_strategy=strategy,
            queue_capacity=queue_capacity,
            queue_retry_initial_ms=queue_retry_initial_ms,
            queue_retry_max_ms=queue_retry_max_ms,
            queue_retry_jitter=queue_retry_jitter,
            queue_drain_max_attempts=queue_drain_max_attempts,
            search_enabled=search_on,
            retention_api=ret_api,
            retention_syslog=ret_sys,
            retention_pii=ret_pii,
            persist_streams=ps,
        )

    def start(self, cfg: FastenConfig) -> None:
        """Apply a FastenConfig. Can be called again to reconfigure; the
        previous drainer and purger threads are stopped first."""
        # Old purgers would otherwise keep running against the old store.
        self._stop_retention_threads()

        # Every named stream needs a store and every attached store must be
        # named.
        if cfg.persist_streams is not None:
            have = {name for name, store in
                    (("api", cfg.api_store), ("sys", cfg.syslog_store))
                    if store is not None}
            named = set(cfg.persist_streams)
            missing_store = named - have
            unlisted_store = have - named
            if missing_store or unlisted_store:
                bits = []
                if missing_store:
                    bits.append(
                        f"named in persist_streams but no store attached: "
                        f"{sorted(missing_store)}"
                    )
                if unlisted_store:
                    bits.append(
                        f"store attached but not in persist_streams: "
                        f"{sorted(unlisted_store)}"
                    )
                raise RuntimeError(
                    "fasten.init: persist_streams / stores mismatch: " + "; ".join(bits)
                )

        self._service_id = cfg.service_id
        self._node_id    = cfg.node_id
        self._tenant_id  = cfg.tenant_id
        self._audit_store = cfg.audit_store
        self._api_store   = cfg.api_store
        self._syslog_store = cfg.syslog_store
        # A gap in the previous store's history says nothing about this one.
        self._audit_write_swallowed = False

        # No chain state lives in the engine: the store allocates seq and
        # prev_hash inside the insert transaction (spec 2.1).

        self._redactor = Redactor(
            extra_keys=cfg.extra_redact_keys,
            replacement=cfg.redact_replacement,
            extra_value_patterns=cfg.extra_value_redact_patterns,
        )
        # Stamped on context-less stream rows until the first real request.
        from .context import mint_sentinel
        self._boot_request_id = mint_sentinel("boot", cfg.service_id)
        self._stdout = StdoutTransport(
            api_store=self._api_store,
            syslog_store=self._syslog_store,
            service_id=cfg.service_id,
            boot_request_id=self._boot_request_id,
            redactor=self._redactor,
        )
        self._failure_strategy = cfg.audit_store_failure_strategy
        self._search_enabled = cfg.search_enabled

        if cfg.audit_store_failure_strategy == "queue":
            self._install_drainer(
                store=self._audit_store,
                capacity=cfg.queue_capacity,
                retry_initial_ms=cfg.queue_retry_initial_ms,
                retry_max_ms=cfg.queue_retry_max_ms,
                retry_jitter=cfg.queue_retry_jitter,
                max_attempts=cfg.queue_drain_max_attempts,
            )
        else:
            self._uninstall_drainer()

        self._start_retention_threads(
            api_ret=cfg.retention_api, sys_ret=cfg.retention_syslog,
            pii_ret=cfg.retention_pii,
        )
        self._last_init_at = datetime.now(timezone.utc)

    def _start_retention_threads(
        self, *, api_ret: Optional[str], sys_ret: Optional[str],
        pii_ret: Optional[str] = None,
    ) -> None:
        """Start one purger thread per stream that has both a store and a
        retention. The previous threads must already be stopped."""
        from .retention import parse_duration, start_purger

        # New event per generation. Old threads may outlive the 2s join, and
        # clearing a shared event would let them keep running.
        self._retention_stop = threading.Event()

        def _log_err(stream: str, e: Exception) -> None:
            # Type-only — the exception message can carry the offending
            # row value (Postgres NotNullViolation cites the column) and
            # the sys stream is redacted key-pattern only.
            self._drainer_sys_log("error", "retention_purge_failed", {
                "stream": stream, "error_type": type(e).__name__,
            })

        for stream, store, dur_s in (
            ("api", self._api_store, api_ret),
            ("sys", self._syslog_store, sys_ret),
        ):
            if store is None or not dur_s:
                continue
            retention = parse_duration(dur_s)
            t = start_purger(
                store=store, stream=stream, retention=retention,
                stop_event=self._retention_stop, on_error=_log_err,
            )
            self._retention_threads.append(t)

        # Audit rows are only redacted, never deleted. redact_fn goes through
        # redact_expired() so the AUDIT_ROW_REDACTED row is written (spec 7.2).
        if pii_ret and self._audit_store is not None:
            pii_retention = parse_duration(pii_ret)
            self._retention_threads.append(start_purger(
                store=self._audit_store, stream="audit",
                retention=None, pii_retention=pii_retention,
                redact_fn=self.redact_expired,
                stop_event=self._retention_stop, on_error=_log_err,
            ))

    def _stop_retention_threads(self) -> None:
        """Stop and join the purger threads."""
        if not self._retention_threads:
            return
        self._retention_stop.set()
        for t in self._retention_threads:
            t.join(timeout=2.0)
        self._retention_threads = []

    def init(
        self,
        service_id: str | None = None,
        node_id: str | None = None,
        tenant_id: str | None = None,
        audit_store: Any | None = None,
        api_store: Any | None = None,
        syslog_store: Any | None = None,
        extra_redact_keys: list[str] | None = None,
        redact_replacement: str | None = None,
        extra_value_redact_patterns: list[Any] | None = None,
        audit_store_failure_strategy: str = "queue",
        queue_capacity: int = 100,
        queue_retry_initial_ms: int = 100,
        queue_retry_max_ms: int = 60_000,
        queue_retry_jitter: bool = True,
        queue_drain_max_attempts: int = 50,
        search_enabled: bool = False,
        retention_api: str | None = None,
        retention_syslog: str | None = None,
        retention_pii: str | None = None,
        persist_streams: list[str] | set[str] | frozenset[str] | None = None,
    ) -> None:
        """Initialise this Engine. Equivalent to start(init_config(...))."""
        self.start(self.init_config(
            service_id=service_id, node_id=node_id, tenant_id=tenant_id,
            audit_store=audit_store, api_store=api_store, syslog_store=syslog_store,
            extra_redact_keys=extra_redact_keys, redact_replacement=redact_replacement,
            extra_value_redact_patterns=extra_value_redact_patterns,
            audit_store_failure_strategy=audit_store_failure_strategy,
            queue_capacity=queue_capacity, queue_retry_initial_ms=queue_retry_initial_ms,
            queue_retry_max_ms=queue_retry_max_ms, queue_retry_jitter=queue_retry_jitter,
            queue_drain_max_attempts=queue_drain_max_attempts,
            search_enabled=search_enabled,
            retention_api=retention_api, retention_syslog=retention_syslog,
            retention_pii=retention_pii,
            persist_streams=persist_streams,
        ))

    def emit(
        self,
        code: str,
        target: str,
        actor: str = "system",
        actor_kind: str = "service",
        detail: Optional[dict[str, Any]] = None,
        severity: Optional[str | Severity] = None,
        method: Optional[str] = None,
        _durable: bool = False,
    ) -> AuditRow:
        """Emit an audit row for a registered ``code``.

        ``_durable=True`` stores the row synchronously and raises if that
        fails, even in queue mode.

        Raises RuntimeError before init() and ValueError for an unknown code.
        """
        if not self._service_id:
            raise RuntimeError("fasten.init() must be called before emit()")

        meta = meta_of(code)
        if meta is None:
            raise ValueError(f"unknown audit code: {code!r}")

        request_id = current_request_id() or mint_id()
        detail = detail or {}

        if meta.pii_in_detail:
            passthrough = set(meta.detail_passthrough_keys)
            kept = {k: v for k, v in detail.items() if k in passthrough}
            detail = {
                "_redacted": "***",
                "_pii_in_detail": True,
                **self._redactor.redact(kept),
            }
        else:
            detail = self._redactor.redact(detail)

        row = AuditRow(
            id=f"evt-{uuid.uuid4().hex[:20]}",
            origin_id="",
            monotonic_seq=0,  # allocated by the store
            timestamp=datetime.now(timezone.utc),
            code=code,
            action=meta.action,
            severity=str(severity) if severity is not None else str(meta.severity),
            service_id=self._service_id,
            source_node_id=self._node_id,
            tenant_id=self._tenant_id,
            actor=actor,
            actor_kind=actor_kind,
            target=target,
            category=meta.category,
            domain=meta.domain,
            method=method or "sdk",
            request_id=request_id,
            detail=detail,
        )
        row = dataclasses.replace(row, origin_id=row.id)

        # monotonic_seq, prev_hash and hash are set by the store inside the
        # insert transaction (spec 2.1), so several engines on one node share
        # one chain.
        #
        # Write the unsealed row to stdout first so it is logged even if the
        # store blocks or fails; the sealed row follows (spec 8).
        if self._stdout is not None:
            self._stdout.write_audit(row.to_dict())

        if self._audit_store is not None:
            if self._failure_strategy == "queue":
                # Rows queued through the fasten-core drainer would not be
                # sealed (see _drainer_allocates), so store them directly and
                # log that once.
                handle = self._drainer_handle
                if handle is not None and _durable:
                    # Enqueueing returns before the row is stored.
                    handle = None
                if handle is not None and not self._drainer_allocates:
                    if not self._drainer_bypass_logged:
                        self._drainer_bypass_logged = True
                        self._drainer_sys_log(
                            "warn", "drainer_bypassed_for_chain_allocation",
                            {"reason": "fasten-core does not implement spec 2.1"},
                        )
                    handle = None
                if handle is not None:
                    row_json = json.dumps(row.to_dict(), default=str)
                    _ffi.drainer_enqueue(handle, row_json)
                else:
                    try:
                        row = self._allocate_and_store(row)
                    except Exception as e:  # noqa: BLE001
                        if _durable:
                            raise
                        # The stored history now has a gap; record it so
                        # completeness is reported as degraded.
                        self._audit_write_swallowed = True
                        note = getattr(self._audit_store, "note_write_failure", None)
                        if callable(note):
                            note()
                        self._drainer_sys_log("error", "audit_sync_fallback_failed", {
                            # Type-only — see retention_purge_failed comment.
                            "error_type": type(e).__name__,
                            "row_id": row.id,
                        })
            else:
                try:
                    row = self._allocate_and_store(row)
                except Exception as e:  # noqa: BLE001
                    raise AuditStoreError(f"{type(e).__name__}: {e}") from e
        return row

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for queued audit rows to be stored. Returns False on timeout."""
        handle = self._drainer_handle
        if handle is None:
            return True
        return _ffi.drainer_flush(handle, int(timeout * 1000))

    def queue_stats(self) -> Optional[dict[str, Any]]:
        """Drainer health snapshot. Returns None in raise mode."""
        handle = self._drainer_handle
        if handle is None:
            return None
        raw = _ffi.drainer_stats_json(handle)
        if raw is None:
            return None
        return json.loads(raw)

    def transport(self) -> Optional[StdoutTransport]:
        """Active StdoutTransport, or None if init() has not been called."""
        return self._stdout

    def redactor(self) -> Redactor:
        """Active Redactor. Always returns a usable instance (default pre-init)."""
        return self._redactor

    def audit_store(self) -> Any:
        """Active AuditRepository, or None if init() has not been called."""
        return self._audit_store

    def audit_write_swallowed(self) -> bool:
        """True if an audit insert failed and was dropped since the last
        start(). Used by the reader's completeness reporting."""
        return self._audit_write_swallowed

    def persisted_streams(self) -> frozenset[str]:
        """Streams that have a store attached ("audit", "api", "sys"). The
        others are read from the in-memory ring."""
        streams: set[str] = set()
        if self._audit_store is not None:
            streams.add("audit")
        if self._api_store is not None:
            streams.add("api")
        if self._syslog_store is not None:
            streams.add("sys")
        return frozenset(streams)

    def search_enabled(self) -> bool:
        """Whether free-text search (``/logs/search`` and ``q=``) is enabled.
        Off by default because it is a linear scan."""
        return self._search_enabled

    def _require_store(self, op: str) -> Any:
        store = self._audit_store
        if store is None:
            raise RuntimeError(
                f"fasten.{op}() requires an audit store: call init() with "
                "audit_store= or FASTEN_AUDIT_DSN first (stdout-only mode has "
                "no store to read/write)."
            )
        return store

    def list_unshipped(self, limit: int = 100) -> "list[AuditRow]":
        """Rows this engine originated that are not yet shipped, oldest first.
        Rows ingested from another node are excluded so they are not shipped
        twice."""
        return self._require_store("list_unshipped").list_unshipped(
            limit=limit,
            service_id=self._service_id,
            source_node_id=self._node_id,
        )

    def mark_shipped(self, ids: "list[str]") -> None:
        """Mark rows shipped upstream by id. Delegates to the store."""
        self._require_store("mark_shipped").mark_shipped(ids)

    def ingest_replicated(self, rows: "list[AuditRow]") -> Any:
        """Verify a replicated batch and insert its verified prefix in one
        transaction. Does not raise on a chain break."""
        return self._require_store("ingest_replicated").ingest_replicated(rows)

    def last_init_at(self) -> Optional[datetime]:
        """Timestamp of the most recent init() call, or None."""
        return self._last_init_at

    def reset_for_tests(self) -> None:
        """Reset to the pre-init state. For test fixtures only."""
        self._uninstall_drainer()
        # A PII purger would otherwise keep redacting the previous test's store.
        self._stop_retention_threads()
        self._service_id    = ""
        self._node_id       = ""
        self._tenant_id     = None
        self._audit_store   = None
        self._api_store     = None
        self._syslog_store  = None
        self._stdout        = None
        self._redactor      = Redactor()
        self._failure_strategy = "queue"
        self._search_enabled = False
        self._last_init_at  = None

    # Code for the redaction record (spec 7.2). Registered on first use so it
    # only appears in catalogs that need it.
    _REDACTION_DOMAIN = "fasten"
    _REDACTION_CODE = "AUDIT_ROW_REDACTED"

    def _ensure_redaction_code(self) -> None:
        from .codes import Meta, RetentionClass, Severity, meta_of, register
        if meta_of(self._REDACTION_CODE) is not None:
            return
        register(self._REDACTION_DOMAIN, {self._REDACTION_CODE: Meta(
            domain=self._REDACTION_DOMAIN, category="retention", action="redact",
            severity=Severity.WARN,
            description="Audit row detail destroyed under a retention policy",
            emitter="fasten",
            retention_class=RetentionClass.LONG,
        )})

    def redact_expired(
        self,
        *,
        before: datetime,
        codes: "list[str]",
        reason: str = "retention",
    ) -> list[str]:
        """Destroy ``detail`` on expired rows, writing an AUDIT_ROW_REDACTED
        row for each first (spec 7.2).

        Returns the ids of the rows redacted.
        """
        store = self._audit_store
        if store is None or not hasattr(store, "list_redaction_candidates"):
            raise AuditStoreError(
                "fasten.redact_expired: the audit store does not implement "
                "list_redaction_candidates / redact_rows (spec §7.1)"
            )
        # Record before destroying: if the record fails nothing is destroyed,
        # and if the destroy fails the next run retries it.
        self._ensure_redaction_code()
        candidates = list(store.list_redaction_candidates(
            before=before, codes=codes))
        if not candidates:
            return []
        # One row at a time, so a failure can duplicate at most one record.
        redacted: list[str] = []
        for row_id, seq in candidates:
            self.emit(
                code=self._REDACTION_CODE,
                target=row_id,
                # The record must be stored before the destroy.
                _durable=True,
                # redacted_id as well, since seq is only unique per node.
                detail={"redacted_seq": seq, "reason": reason,
                        "redacted_id": row_id},
            )
            redacted.extend(store.redact_rows(ids=[row_id]))
        return redacted

    def _allocate_and_store(self, row: AuditRow) -> AuditRow:
        """Insert through the store's allocating method and write the sealed
        row to stdout. Stores without allocate_and_insert_originated get a
        plain insert, unsealed."""
        allocate = getattr(self._audit_store, "allocate_and_insert_originated", None)
        if not callable(allocate):
            # This store predates spec §2.1, so rows go in UNSEALED: no seq, no
            # hash. verify_chain SKIPS hashless rows, so /audit/doctor would
            # otherwise report verified=true over a completely unchained table.
            # Say it once, loudly, and set the degrade flag.
            if not self._unchained_store_logged:
                self._unchained_store_logged = True
                self._audit_chain_unavailable = True
                self._drainer_sys_log("error", "audit_chain_unavailable", {
                    "store": type(self._audit_store).__name__,
                    "reason": "store has no allocate_and_insert_originated "
                              "(spec 2.1); rows are written unsealed",
                })
            self._audit_store.insert(row)
            return row
        sealed = allocate(row)
        if self._stdout is not None and sealed.hash:
            self._stdout.write_audit(sealed.to_dict())
        return sealed

    def _drainer_sys_log(self, level: str, event: str, fields: dict[str, Any]) -> None:
        """Write an internal sys event to stderr, so stdout backpressure
        cannot block the drainer."""
        if self._stdout is None:
            return
        payload: dict[str, Any] = {
            "level": level,
            "event": event,
            "request_id": current_request_id(),
            "service_id": self._service_id or None,
            "timestamp": canonical_now(),
            **fields,
        }
        self._stdout.write_drainer_syslog(payload)

    def _install_drainer(
        self,
        *,
        store: Any,
        capacity: int,
        retry_initial_ms: int,
        retry_max_ms: int,
        retry_jitter: bool,
        max_attempts: int,
    ) -> None:
        # Rows come back from the Rust queue as JSON, so timestamps are
        # strings and must be parsed back to datetime for the store.
        cb_logger = logging.getLogger("fasten")

        def _insert_cb(row_json: bytes, _userdata: int) -> int:
            row_dict: dict[str, Any] = {}
            try:
                row_dict = json.loads(row_json.decode("utf-8"))
                for fld in ("timestamp", "shipped_at"):
                    v = row_dict.get(fld)
                    if isinstance(v, str):
                        row_dict[fld] = parse_canonical(v)
                row = AuditRow(**{k: row_dict[k] for k in AuditRow.__dataclass_fields__ if k in row_dict})
                store.insert(row)
                return 0
            except Exception:  # noqa: BLE001  the drainer reports the dead-letter outcome
                cb_logger.exception(
                    "insert_cb failed for row %s", row_dict.get("id", "<unparsed>"),
                )
                return 1

        cb = _ffi.InsertCallbackFn(_insert_cb)
        new_handle = _ffi.store_from_callback(cb)
        _ffi.drainer_install(
            new_handle,
            capacity=capacity,
            retry_initial_ms=retry_initial_ms,
            retry_max_ms=retry_max_ms,
            retry_jitter=retry_jitter,
            max_attempts=max_attempts,
        )
        with self._drainer_lock:
            old_handle    = self._drainer_handle
            old_callback  = self._drainer_callback
            self._drainer_handle   = new_handle
            self._drainer_callback = cb
        if old_handle is not None:
            _ffi.drainer_flush(old_handle, 5_000)
            _ffi.drainer_close(old_handle)
            _ffi.store_close(old_handle)
        _ = old_callback  # released only after the old drainer is closed
        if not self._atexit_registered:
            atexit.register(self._atexit_flush)
            self._atexit_registered = True

    def _uninstall_drainer(self) -> None:
        with self._drainer_lock:
            old_handle   = self._drainer_handle
            old_callback = self._drainer_callback
            self._drainer_handle   = None
            self._drainer_callback = None
        if old_handle is not None:
            # The drainer thread may call the callback until drainer_close()
            # returns; freeing the ctypes closure earlier crashes the process.
            try:
                _ffi.drainer_close(old_handle)
                _ffi.store_close(old_handle)
            finally:
                del old_callback

    def _atexit_flush(self) -> None:
        handle = self._drainer_handle
        if handle is not None:
            _ffi.drainer_flush(handle, 5_000)
        self._uninstall_drainer()
        self._stop_retention_threads()


class _Logger:
    """Structured sys log writer for an Engine.

    ``bound()`` returns a logger with a name and extra fields attached:

        log = fasten.log.bound("buffer-manager")
        log.info("flush_complete", batch=42)
    """

    def __init__(
        self,
        engine: Engine,
        name: Optional[str] = None,
        bound: Optional[dict[str, Any]] = None,
    ) -> None:
        self._engine = engine
        self._name = name
        self._bound = dict(bound or {})

    def bound(self, name: Optional[str] = None, **fields: Any) -> "_Logger":
        new_name = name if name is not None else self._name
        new_bound = {**self._bound, **fields}
        return _Logger(engine=self._engine, name=new_name, bound=new_bound)

    def _emit(self, level: int, event: str, **fields: Any) -> None:
        eng = self._engine
        payload: dict[str, Any] = {
            "event": event,
            "request_id": current_request_id(),
            "service_id": eng._service_id or None,
            "timestamp": canonical_now(),
            **self._bound,
            **fields,
        }
        if self._name is not None:
            payload["logger"] = self._name

        if eng._stdout is not None:
            eng._stdout.write_syslog({"level": logging.getLevelName(level).lower(), **payload})
        else:
            eng._stdlib_logger.log(
                level,
                json.dumps(payload, default=str),
                extra={"_fasten_internal": True},
            )

    def debug(self,   event: str, **fields: Any) -> None: self._emit(logging.DEBUG,   event, **fields)
    def info(self,    event: str, **fields: Any) -> None: self._emit(logging.INFO,     event, **fields)
    def warn(self,    event: str, **fields: Any) -> None: self._emit(logging.WARNING,  event, **fields)
    def warning(self, event: str, **fields: Any) -> None: self._emit(logging.WARNING,  event, **fields)
    def error(self,   event: str, **fields: Any) -> None: self._emit(logging.ERROR,    event, **fields)
