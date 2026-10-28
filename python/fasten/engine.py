"""
Engine — encapsulates all fasten runtime state.

The module-level free functions (``fasten.init``, ``fasten.emit``, …)
delegate to a module-level default Engine instance.  Applications that
need multiple isolated fasten configurations in one process (multi-tenant
services, test isolation) construct Engine instances directly:

    tenant_a = fasten.Engine()
    tenant_a.init(tenant_id="tenant-a", audit_store=store_a, ...)
    tenant_a.emit(code="ORDER_PLACED", ...)

    tenant_b = fasten.Engine()
    tenant_b.init(tenant_id="tenant-b", audit_store=store_b, ...)
    tenant_b.emit(code="ORDER_PLACED", ...)
"""
from __future__ import annotations

import atexit
import contextlib
import dataclasses
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from .attrs import AuditRow
from .canonical_ts import canonical_now
from .chain import ChainVerifyResult, _canonical_json, _row_hash, seal, verify_chain
from .codes import Severity, meta_of
from .context import current_request_id, mint_id
from . import core_ffi as _ffi
from .redact import Redactor
from .transport.stdout import StdoutTransport

# Re-exported for backwards compatibility: tests and downstream code historically
# imported these from fasten.engine. The canonical home is now fasten.chain.
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
    # FR1 retention (spec §1): background age-based purge on api/sys stream
    # stores. None disables. Strings are duration tokens ("7d", "24h").
    retention_api: Optional[str]
    retention_syslog: Optional[str]
    # #90 PII horizon on the audit store: rows in codes.pii_codes() older than
    # this have detail + detail_salt destroyed. Redaction-only by design — an
    # audit age-purge would delete chain rows, which reads as tampering (§7.1).
    retention_pii: Optional[str]
    # #58 persist_streams: explicit allowlist of streams the operator has
    # opted into persisting. When set, start() asserts that the set matches
    # the streams with stores attached (bidirectional — a named stream
    # without a store or an attached store without the name both fail
    # loudly). When None, persistence is derived from store attachment —
    # a stream reports "store" only when it actually has one. Never
    # includes "audit" (audit persistence is driven by audit_store, not
    # this knob).
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
    """Build a per-stream store (api/sys) from a DSN. Explicit scheme whitelist:

    - ``postgres://`` / ``postgresql://`` → PostgresStreamStore
    - ``sqlite:///path`` or bare path → SQLite-backed StreamStore

    Any other scheme (e.g. ``postgresql+psycopg://``, ``mysql://``) is rejected
    with a clear error. The earlier fall-through accepted every scheme and
    silently created a local SQLite file named after the DSN's path component
    (``postgresql+psycopg://host/db`` → SQLite file ``db``), asserting
    durability over an ephemeral container file — PR #59 finding 11."""
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
    # SQLAlchemy-style sqlite paths: strip only the single URL-separator slash,
    # not every leading slash. sqlite:///rel.db -> rel.db (relative);
    # sqlite:////abs/path.db -> /abs/path.db (absolute). The old lstrip("/")
    # collapsed the four-slash absolute form into a relative path.
    path = u.path
    if u.scheme and path.startswith("/"):
        path = path[1:]
    if not path:
        raise ValueError(
            f"fasten: stream DSN {dsn!r} has no path. Use sqlite:///./streams.db"
        )
    return StreamStore(path=path, table=q.get("table", default_table),
                       wal=q.get("wal", "true") != "false")


@dataclasses.dataclass(eq=False)
class _QueueDrainer:
    """An installed fasten-core drainer and the rows it holds."""

    handle: Any                 # FastenStore* (ctypes void ptr)
    callback: Any               # keeps the ctypes callback alive until close
    # Rows waiting in the drainer, by id. The callback stores this row, not
    # fasten-core's JSON copy, so the store seals what was emitted (spec §2.1).
    pending: dict[str, list[Any]]
    store: Any
    users: int = 0              # calls using the handle; close waits for 0


class Engine:
    """
    A single fasten runtime instance.

    Holds service identity, redactor, audit store, stdout transport, and
    drainer state for one deployment context.  Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._boot_request_id: Optional[str] = None  # sentinel boot-window id

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
        self._drainer: Optional[_QueueDrainer] = None
        self._drainer_lock = threading.Lock()
        self._drainer_idle = threading.Condition(self._drainer_lock)
        self._atexit_registered = False
        self._last_init_at: Optional[datetime] = None

        # Engine-side "at least one audit-store insert was swallowed" flag.
        # Tracked here (not only on the store) because AuditRepository does
        # not require ``note_write_failure``: an adopter-supplied store fails
        # the getattr check below and the swallow would otherwise be
        # invisible, leaving completeness reporting "store" over durable
        # history that has holes. Sticky — a hole doesn't heal.
        self._audit_write_swallowed: bool = False

        # FR1 retention (spec §1). One shutdown event + one thread per
        # configured stream. See fasten.retention.start_purger.
        self._retention_stop: threading.Event = threading.Event()
        self._retention_threads: list[threading.Thread] = []

        self.log: _Logger = _Logger(self)

    # ── Lifecycle ─────────────────────────────────────────────────────────

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
        """Resolve all parameters and environment variables into a FastenConfig.

        Does NOT start any runtime (no thread, no store connection). Safe to
        call from config-loading code that runs before the event loop starts.
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
            # No store and no DSN → stdout-only mode. Rows are written to stdout
            # but not persisted. Matches Go/JS/Rust behaviour where AuditStore is
            # optional. Adopters who need persistence must supply audit_store= or
            # set FASTEN_AUDIT_DSN.

        # api/sys persistence (FR1) — opt-in, SQLite-backed StreamStore. When
        # unset the stream falls back to ring-only (today's behaviour).
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
        for name, value, limit in (
            ("queue_capacity", queue_capacity, 2**64 - 1),
            ("queue_retry_initial_ms", queue_retry_initial_ms, 2**64 - 1),
            ("queue_retry_max_ms", queue_retry_max_ms, 2**64 - 1),
            ("queue_drain_max_attempts", queue_drain_max_attempts, 2**32 - 1),
        ):
            if not 0 <= value <= limit:
                raise RuntimeError(f"fasten.init_config: {name} must be 0..{limit} (got {value!r})")

        # FR3 free-text search is opt-in (§4.1): off unless explicitly enabled,
        # via arg or FASTEN_SEARCH_ENABLED. Enabling it without a syslog store
        # still yields "search requires sys persistence" at read time.
        env_search = os.environ.get("FASTEN_SEARCH_ENABLED")
        search_on = search_enabled or (env_search or "").lower() in ("1", "true", "yes")

        # FR1 retention (§1). Env overrides the arg if arg is None; env
        # empty-string counts as unset.
        ret_api = retention_api if retention_api is not None else (os.environ.get("FASTEN_RETENTION_API") or None)
        ret_sys = retention_syslog if retention_syslog is not None else (os.environ.get("FASTEN_RETENTION_SYSLOG") or None)
        ret_pii = retention_pii if retention_pii is not None else (os.environ.get("FASTEN_RETENTION_PII") or None)

        # #58 persist_streams: explicit stream allowlist. Env supports a
        # comma-separated list; empty-string counts as unset. Validated
        # against the set of stores in start(), not here — init_config
        # never touches runtime state.
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
                    f"fasten.init_config: persist_streams={sorted(ps)} — "
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
        """Wire runtime from a resolved FastenConfig. Idempotent — safe to call
        on re-configuration; flushes and stops the previous drainer first."""
        # Stop any previous retention threads before re-wiring — otherwise a
        # re-Init on the same Engine leaves orphan purgers hammering the old
        # store (which may already be closed).
        self._stop_retention_threads()

        # #58 persist_streams assertion — every named stream needs a store,
        # every attached store needs to be named. Both directions so an
        # operator can't declare persistence without wiring it (silent
        # ring-only under a "store" flag) or wire a store the config didn't
        # opt into (surprise IO on a stream the operator thought was
        # ring-only). Skipped when persist_streams is None.
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
                    "fasten.init: persist_streams / stores mismatch — " + "; ".join(bits)
                )

        # Swap the drainer before switching stores: a row emitted from here on
        # goes to the new store, and the old drainer's rows stay with the old.
        if cfg.audit_store_failure_strategy == "queue" and cfg.audit_store is not None:
            old_drainer = self._install_drainer(
                store=cfg.audit_store,
                capacity=cfg.queue_capacity,
                retry_initial_ms=cfg.queue_retry_initial_ms,
                retry_max_ms=cfg.queue_retry_max_ms,
                retry_jitter=cfg.queue_retry_jitter,
                max_attempts=cfg.queue_drain_max_attempts,
            )
        else:
            old_drainer = self._take_drainer()

        self._service_id = cfg.service_id
        self._node_id    = cfg.node_id
        self._tenant_id  = cfg.tenant_id
        prev_store, self._audit_store = self._audit_store, cfg.audit_store
        self._api_store   = cfg.api_store
        self._syslog_store = cfg.syslog_store
        # Re-init on a fresh store clears the sticky degrade — a hole in the
        # previous store's history doesn't apply to this one.
        if cfg.audit_store is not prev_store:
            self._audit_write_swallowed = False

        # NOTE: no seq / prev_hash seeding here. Allocation is the store's job
        # (spec §2.1) and happens inside the insert transaction, so an engine
        # holds no chain state at all. Seeding here previously cost two store
        # round trips per init() and — worse — implied the engine owned the
        # counter, which is the bug P0-9 fixed.

        self._redactor = Redactor(
            extra_keys=cfg.extra_redact_keys,
            replacement=cfg.redact_replacement,
            extra_value_patterns=cfg.extra_value_redact_patterns,
        )
        # Sentinel invariant: one stable boot-window id per process, in effect
        # for context-less stream rows until the first real request arrives.
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

        if old_drainer is not None:
            # A replaced drainer gets up to 5 s to write what it holds.
            self._retire_drainer(old_drainer, flush_ms=5_000 if self._drainer else 0)

        # FR1 retention (§1). Only when a store is attached AND a retention
        # is set; running a background purger over a nil store is a no-op
        # that would still hit disk on a bare ring-only engine.
        self._start_retention_threads(
            api_ret=cfg.retention_api, sys_ret=cfg.retention_syslog,
            pii_ret=cfg.retention_pii,
        )
        self._last_init_at = datetime.now(timezone.utc)

    def _start_retention_threads(
        self, *, api_ret: Optional[str], sys_ret: Optional[str],
        pii_ret: Optional[str] = None,
    ) -> None:
        """Spawn one purger thread per configured (store, retention) pair.
        Called from start(); the previous set has already been stopped."""
        from .retention import parse_duration, start_purger

        # Fresh event for this generation of threads so old wait() calls on
        # a re-Init don't return prematurely on the new event.
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
            retention = parse_duration(dur_s)   # raises early on malformed input
            t = start_purger(
                store=store, stream=stream, retention=retention,
                stop_event=self._retention_stop, on_error=_log_err,
            )
            self._retention_threads.append(t)

        # #90 audit PII horizon. Separate from the loop above because both
        # arguments differ: retention=None (redaction only, never delete), and
        # redact_fn=self.redact_expired rather than the store method, so the
        # §7.2 AUDIT_ROW_REDACTED row actually gets written.
        if pii_ret and self._audit_store is not None:
            pii_retention = parse_duration(pii_ret)   # raises early
            self._retention_threads.append(start_purger(
                store=self._audit_store, stream="audit",
                retention=None, pii_retention=pii_retention,
                redact_fn=self.redact_expired,
                stop_event=self._retention_stop, on_error=_log_err,
            ))

    def _stop_retention_threads(self) -> None:
        """Wake and join every purger thread. Idempotent."""
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

    # ── Emit ──────────────────────────────────────────────────────────────

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
        """
        Emit an audit row. Anchors auto-filled where possible.

        Raises RuntimeError if init() has not been called.
        Raises ValueError for an unregistered code.
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

        # Build the row with a placeholder seq; the store seals it at insert
        # (see below).
        row = AuditRow(
            id=f"evt-{uuid.uuid4().hex[:20]}",
            origin_id="",
            monotonic_seq=0,  # placeholder — the store allocates (spec §2.1)
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

        # monotonic_seq / prev_hash / hash are NOT assigned here. They are
        # allocated by the store inside the insert transaction (spec §2.1), so
        # that N engine instances on one node produce ONE chain instead of N
        # rows all claiming seq 1. Sealing therefore happens at insert time.
        #
        # Phase 1 of the two-phase stdout contract (spec §8): write the unsealed
        # row before store routing, so it reaches the log stream even if the
        # store path blocks or raises. Phase 2 re-emits it sealed below.
        if self._stdout is not None:
            self._stdout.write_audit(row.to_dict())

        if self._audit_store is not None:
            if self._failure_strategy == "queue":
                # The drainer retries the insert; the store seals the row when
                # it lands (spec §2.1, §8). A durable emit must not return
                # before the row is persisted, so it takes the synchronous path.
                queued = refused = False
                store = self._audit_store
                if not _durable:
                    with self._using_drainer() as d:
                        if d is not None:
                            store = d.store
                            d.pending[row.id] = [row, 0]
                            try:
                                _ffi.drainer_enqueue(d.handle, json.dumps(row.to_dict(), default=str))
                                queued = True
                            except Exception:  # noqa: BLE001 — enqueue refused; store it inline
                                d.pending.pop(row.id, None)
                                refused = True
                if not queued:
                    try:
                        row = self._allocate_and_store(row, store)
                    except Exception as e:  # noqa: BLE001
                        if _durable:
                            # Not hot-path telemetry. The caller is relying on
                            # this row existing before it does something
                            # irreversible, so the failure has to reach it.
                            raise
                        # Swallowed on the hot path → durable history now has a
                        # hole; degrade the audit completeness flag.
                        self._mark_write_lost(store)
                        self._drainer_sys_log("error", "audit_sync_fallback_failed", {
                            # Type-only — see retention_purge_failed comment.
                            "error_type": type(e).__name__,
                            "row_id": row.id,
                        })
                    else:
                        if refused:  # fasten-core may have reported this row abandoned
                            self._drainer_sys_log("info", "audit_drain_stored_inline", {"row_id": row.id})
            else:
                try:
                    row = self._allocate_and_store(row, self._audit_store)
                except Exception as e:  # noqa: BLE001
                    raise AuditStoreError(f"{type(e).__name__}: {e}") from e
        return row

    # ── Queue / drainer ───────────────────────────────────────────────────

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until pending audit rows drain (or timeout). Returns True iff drained."""
        with self._using_drainer() as d:
            if d is None:
                return True
            return _ffi.drainer_flush(d.handle, int(timeout * 1000))

    def queue_stats(self) -> Optional[dict[str, Any]]:
        """Drainer health snapshot. Returns None in raise mode."""
        with self._using_drainer() as d:
            if d is None:
                return None
            raw = _ffi.drainer_stats_json(d.handle)
        if raw is None:
            return None
        return json.loads(raw)

    # ── Public accessors ──────────────────────────────────────────────────

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
        """True iff an audit row failed to reach the current store: a failed
        synchronous fallback, a drainer dead-letter, or a row left when a
        drainer stopped. Sticky until re-init. See the /correlate + /logs
        completeness readers."""
        return self._audit_write_swallowed

    def persisted_streams(self) -> frozenset[str]:
        """Streams backed by the durable store rather than a bounded ring
        (FR4 completeness). A stream joins the set only when it actually has a
        store: ``audit`` when an audit store is configured, ``api``/``sys``
        when a stream store is (FR1). In stdout-only mode (no audit store)
        ``audit`` is absent, so its reads report ``ring`` instead of asserting
        a durable ``store`` that does not exist."""
        streams: set[str] = set()
        if self._audit_store is not None:
            streams.add("audit")
        if self._api_store is not None:
            streams.add("api")
        if self._syslog_store is not None:
            streams.add("sys")
        return frozenset(streams)

    def search_enabled(self) -> bool:
        """Whether FR3 free-text search (``/logs/search`` and ``q=``) is enabled.
        Off by default (§4.1) — an explicit opt-in, since it is a linear scan."""
        return self._search_enabled

    def _require_store(self, op: str) -> Any:
        store = self._audit_store
        if store is None:
            raise RuntimeError(
                f"fasten.{op}() requires an audit store — call init() with "
                "audit_store= or FASTEN_AUDIT_DSN first (stdout-only mode has "
                "no store to read/write)."
            )
        return store

    def list_unshipped(self, limit: int = 100) -> "list[AuditRow]":
        """Rows this engine ORIGINATED that are not yet shipped upstream, oldest
        first. Scoped to the engine's own (service_id, source_node_id) so rows
        ingested from another origin are never re-shipped (that would duplicate
        a foreign sub-chain). Delegates to the store."""
        return self._require_store("list_unshipped").list_unshipped(
            limit=limit,
            service_id=self._service_id,
            source_node_id=self._node_id,
        )

    def mark_shipped(self, ids: "list[str]") -> None:
        """Mark rows shipped upstream by id. Delegates to the store."""
        self._require_store("mark_shipped").mark_shipped(ids)

    def ingest_replicated(self, rows: "list[AuditRow]") -> Any:
        """Verify + insert the verified prefix of a replicated batch (single
        transaction). Delegates to the store; does not raise on a chain break."""
        return self._require_store("ingest_replicated").ingest_replicated(rows)

    def last_init_at(self) -> Optional[datetime]:
        """Timestamp of the most recent init() call, or None."""
        return self._last_init_at

    def reset_for_tests(self) -> None:
        """Reset all runtime state to pre-init defaults.

        Intended for test fixtures that need a clean Engine without
        constructing a new one. Do not call in production code.
        """
        self._uninstall_drainer()
        # Retention threads outlive the reset otherwise. Harmless while the
        # only purgers were age-based on api/sys, but an audit PII purger
        # holds a reference to the old store and keeps redacting into it
        # after the fixture has moved on — a leaked thread mutating a
        # previous test's data.
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

    # ── Internal ──────────────────────────────────────────────────────────

    # spec §7.2: fasten's own code for the redaction event. Registered lazily on
    # first use so adopters who never redact don't carry it in their catalog.
    _REDACTION_DOMAIN = "fasten"
    _REDACTION_CODE = "AUDIT_ROW_REDACTED"

    def _ensure_redaction_code(self) -> None:
        from .codes import Meta, RetentionClass, Severity, meta_of, register
        # Check the RETURN VALUE. meta_of() yields None for an unknown code
        # rather than raising, so `try: meta_of(); return` skipped registration
        # every time and emit() then failed with "unknown audit code".
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
        """Destroy ``detail`` on expired rows AND record that it happened.

        The store redaction alone leaves an honest erasure and a quiet
        redaction indistinguishable — both yield a row whose detail is null.
        Spec §7.2 requires the destruction itself be an originated, chained
        row, so a verifier can see the suffix was altered *because of a
        recorded policy action*.

        Returns the ids of the rows redacted.
        """
        store = self._audit_store
        if store is None or not hasattr(store, "list_redaction_candidates"):
            raise AuditStoreError(
                "fasten.redact_expired: the audit store does not implement "
                "list_redaction_candidates / redact_rows (spec §7.1)"
            )
        # Record BEFORE destroying. Destroy-then-emit leaves destroyed rows
        # with no record if the emit fails, and the retry can't find them.
        # This way an emit failure destroys nothing, and a destroy failure
        # leaves the data intact under a record the next tick converges on.
        self._ensure_redaction_code()
        candidates = list(store.list_redaction_candidates(
            before=before, codes=codes))
        if not candidates:
            return []
        # One row at a time, record then destroy. Emitting the whole batch
        # and then destroying it in one call meant a failed destroy left every
        # row still a candidate, so the next tick re-emitted a record for all
        # of them — duplicate events scaling with the batch. Per row, only the
        # row that failed between its own record and its destroy can repeat.
        redacted: list[str] = []
        for row_id, seq in candidates:
            self.emit(
                code=self._REDACTION_CODE,
                target=row_id,
                # Must persist before the destroy. In queue mode (the default)
                # a plain emit swallows the store failure and returns normally,
                # so rows were destroyed with no record.
                _durable=True,
                # spec §7.2 shape; redacted_id too, since seq is only unique
                # per source node.
                detail={"redacted_seq": seq, "reason": reason,
                        "redacted_id": row_id},
            )
            redacted.extend(store.redact_rows(ids=[row_id]))
        return redacted

    def _allocate_and_store(self, row: AuditRow, store: Any) -> AuditRow:
        """Store-allocated seal (spec §2.1) + phase-2 stdout write (spec §8).

        Falls back to the legacy unallocated insert for adopter repositories that
        predate the protocol method, so a custom store keeps working (unchained)
        rather than raising on the hot path.
        """
        allocate = getattr(store, "allocate_and_insert_originated", None)
        if not callable(allocate):
            # This store predates spec §2.1, so rows go in UNSEALED: no seq, no
            # hash. verify_chain SKIPS hashless rows, so /audit/doctor would
            # otherwise report verified=true over a completely unchained table.
            # Say it once, loudly, and set the degrade flag.
            if not self._unchained_store_logged:
                self._unchained_store_logged = True
                self._audit_chain_unavailable = True
                self._drainer_sys_log("error", "audit_chain_unavailable", {
                    "store": type(store).__name__,
                    "reason": "store has no allocate_and_insert_originated "
                              "(spec 2.1); rows are written unsealed",
                })
            store.insert(row)
            return row
        sealed = allocate(row)
        if self._stdout is not None and sealed.hash:
            try:
                self._stdout.write_audit(sealed.to_dict())
            except Exception:  # noqa: BLE001 — the row is stored; don't report it as failed
                logging.getLogger("fasten").exception("sealed stdout line failed for %s", sealed.id)
        return sealed

    def _mark_write_lost(self, store: Any) -> None:
        """A row didn't reach the store: durable history has a hole. The engine
        flag only covers its current store; re-init onto another store clears it,
        re-init onto the same store keeps it."""
        if store is self._audit_store:
            self._audit_write_swallowed = True
        note = getattr(store, "note_write_failure", None)
        if callable(note):
            note()

    @contextlib.contextmanager
    def _using_drainer(self) -> Iterator[Optional[_QueueDrainer]]:
        """The installed drainer, kept open until the block exits."""
        with self._drainer_lock:
            d = self._drainer
            if d is not None:
                d.users += 1
        try:
            yield d
        finally:
            if d is not None:
                with self._drainer_lock:
                    d.users -= 1
                    self._drainer_idle.notify_all()

    def _drainer_sys_log(self, level: str, event: str, fields: dict[str, Any]) -> None:
        """Route drainer events to stderr (not stdout) to avoid backpressure deadlock."""
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
    ) -> Optional[_QueueDrainer]:
        """Install a new drainer and return the one it replaced, for the
        caller to retire."""
        cb_logger = logging.getLogger("fasten")
        max_attempts = max_attempts or 50   # fasten-core's default for 0
        pending: dict[str, list[Any]] = {}

        def _insert_cb(row_json: bytes, _userdata: int) -> int:
            row_id = "<unparsed>"
            try:
                row_id = json.loads(row_json.decode("utf-8"))["id"]
                entry = pending.get(row_id)
                if entry is None:   # already settled here; nothing to store
                    cb_logger.error("insert_cb: row %s is not pending", row_id)
                    return 0
                entry[1] += 1
                self._allocate_and_store(entry[0], store)
                pending.pop(row_id, None)
                return 0
            except Exception:  # noqa: BLE001 — store / drainer reports the dead-letter outcome
                cb_logger.exception("insert_cb failed for row %s", row_id)
                failed = pending.get(row_id)
                if failed is not None and failed[1] >= max_attempts:
                    pending.pop(row_id, None)  # the drainer dead-letters it now
                    self._mark_write_lost(store)
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
            old = self._drainer
            self._drainer = _QueueDrainer(new_handle, cb, pending, store)
        if not self._atexit_registered:
            atexit.register(self._atexit_flush)
            self._atexit_registered = True
        return old

    def _take_drainer(self) -> Optional[_QueueDrainer]:
        with self._drainer_lock:
            old, self._drainer = self._drainer, None
        return old

    def _uninstall_drainer(self) -> None:
        old = self._take_drainer()
        if old is not None:
            self._retire_drainer(old, flush_ms=0)

    def _retire_drainer(self, d: _QueueDrainer, flush_ms: int) -> None:
        """Stop a drainer that is no longer installed and store what it didn't."""
        if flush_ms:
            _ffi.drainer_flush(d.handle, flush_ms)
        # Close refuses new rows and waits for the drain thread, so the
        # callback is not called after it returns. Calls still using the
        # handle get an error and store their row inline.
        _ffi.drainer_close(d.handle)
        with self._drainer_lock:
            self._drainer_idle.wait_for(lambda: d.users == 0)
        _ffi.store_close(d.handle)
        # Rows still pending were not stored: the drainer abandoned them or
        # gave them one try at shutdown, and may have reported them lost.
        recovered = []
        for row, _ in list(d.pending.values()):
            try:
                self._allocate_and_store(row, d.store)
                recovered.append(row.id)
            except Exception as e:  # noqa: BLE001
                self._mark_write_lost(d.store)
                self._drainer_sys_log("error", "audit_drain_lost_at_stop", {
                    "error_type": type(e).__name__,
                    "row_id": row.id,
                })
        d.pending.clear()
        if recovered:
            self._drainer_sys_log("info", "audit_drain_recovered_at_stop", {"row_ids": recovered})

    def _atexit_flush(self) -> None:
        self.flush(5.0)
        self._uninstall_drainer()
        self._stop_retention_threads()


# ── Logger ────────────────────────────────────────────────────────────────────


class _Logger:
    """Structured syslog writer bound to an Engine instance.

    Per-module loggers via :meth:`bound`:

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
