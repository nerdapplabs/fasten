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
import dataclasses
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .attrs import AuditRow
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


def _stream_store_from_dsn(dsn: str, default_table: str) -> Any:
    """Build a per-stream store (api/sys) from a DSN. SQLite and Postgres are
    both supported: a ``postgres[ql]://`` DSN builds a PostgresStreamStore, any
    other builds the SQLite-backed StreamStore."""
    from urllib.parse import parse_qs, urlparse

    if dsn.startswith(("postgres://", "postgresql://")):
        from .store.stream_postgres import PostgresStreamStore
        return PostgresStreamStore.from_dsn(dsn, default_table)
    from .store.stream import StreamStore

    u = urlparse(dsn)
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


class Engine:
    """
    A single fasten runtime instance.

    Holds service identity, redactor, audit store, stdout transport, and
    drainer state for one deployment context.  Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq: int = 0
        self._prev_hash: str = "genesis"  # P1-23: hash chain
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

        self._drainer_handle: Any = None          # FastenStore* (ctypes void ptr)
        self._drainer_callback: Any = None        # keep ctypes callback alive (GC guard)
        self._drainer_lock = threading.Lock()
        self._atexit_registered = False
        self._last_init_at: Optional[datetime] = None

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

        # FR3 free-text search is opt-in (§4.1): off unless explicitly enabled,
        # via arg or FASTEN_SEARCH_ENABLED. Enabling it without a syslog store
        # still yields "search requires sys persistence" at read time.
        env_search = os.environ.get("FASTEN_SEARCH_ENABLED")
        search_on = search_enabled or (env_search or "").lower() in ("1", "true", "yes")

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
        )

    def start(self, cfg: FastenConfig) -> None:
        """Wire runtime from a resolved FastenConfig. Idempotent — safe to call
        on re-configuration; flushes and stops the previous drainer first."""
        self._service_id = cfg.service_id
        self._node_id    = cfg.node_id
        self._tenant_id  = cfg.tenant_id
        self._audit_store = cfg.audit_store
        self._api_store   = cfg.api_store
        self._syslog_store = cfg.syslog_store

        if self._audit_store is not None and hasattr(self._audit_store, "max_monotonic_seq"):
            # Seed seq from THIS engine's own (service_id, source_node_id)
            # sub-chain only — never the global MAX. monotonic_seq is a
            # per-node counter; seeding from a foreign origin's rows (which
            # this node may have ingested via ingest_replicated) would break
            # this node's own tamper chain.
            with self._lock:
                self._seq = self._audit_store.max_monotonic_seq(
                    service_id=cfg.service_id,
                    source_node_id=cfg.node_id,
                )
            # Seed prev_hash for the hash chain from the latest stored row of
            # THIS node's own sub-chain.
            try:
                latest = self._audit_store.query(
                    source_node_id=cfg.node_id, limit=1,
                )
                seed = latest[0].hash if latest and latest[0].hash else "genesis"
            except Exception:
                seed = "genesis"
            with self._lock:
                self._prev_hash = seed

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
        self._last_init_at = datetime.now(timezone.utc)

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

        # Build the row with a placeholder seq; hash chain fields are assigned
        # atomically under _lock below so concurrent emit() calls can't
        # interleave their prev_hash references.
        row = AuditRow(
            id=f"evt-{uuid.uuid4().hex[:20]}",
            origin_id="",
            monotonic_seq=0,  # placeholder — replaced under lock
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

        # Atomically: assign monotonic_seq + seal the hash chain (the ONE
        # canonical seal path — fasten.chain.seal stamps canonical_form_id,
        # prev_hash and computes hash).
        with self._lock:
            self._seq += 1
            row = dataclasses.replace(row, monotonic_seq=self._seq)
            row = seal(self._prev_hash, row)
            self._prev_hash = row.hash

        # Stdout write before store routing: row reaches the log stream even
        # if the store path blocks or raises.
        if self._stdout is not None:
            self._stdout.write_audit(row.to_dict())

        if self._audit_store is not None:
            if self._failure_strategy == "queue":
                handle = self._drainer_handle
                if handle is not None:
                    row_json = json.dumps(row.to_dict(), default=str)
                    _ffi.drainer_enqueue(handle, row_json)
                else:
                    try:
                        self._audit_store.insert(row)
                    except Exception as e:  # noqa: BLE001
                        # Swallowed on the hot path → durable history now has a
                        # hole; degrade the audit completeness flag.
                        note = getattr(self._audit_store, "note_write_failure", None)
                        if callable(note):
                            note()
                        self._drainer_sys_log("error", "audit_sync_fallback_failed", {
                            "error": f"{type(e).__name__}: {e}",
                            "row_id": row.id,
                        })
            else:
                try:
                    self._audit_store.insert(row)
                except Exception as e:  # noqa: BLE001
                    raise AuditStoreError(f"{type(e).__name__}: {e}") from e
        return row

    # ── Queue / drainer ───────────────────────────────────────────────────

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until pending audit rows drain (or timeout). Returns True iff drained."""
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
        with self._lock:
            self._seq = 0
            self._prev_hash = "genesis"
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

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _drainer_sys_log(self, level: str, event: str, fields: dict[str, Any]) -> None:
        """Route drainer events to stderr (not stdout) to avoid backpressure deadlock."""
        if self._stdout is None:
            return
        payload: dict[str, Any] = {
            "level": level,
            "event": event,
            "request_id": current_request_id(),
            "service_id": self._service_id or None,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
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
        # Build an insert callback that delegates to the Python store.
        # The row crosses Python → JSON → Rust queue → Python here, so
        # `timestamp` / `shipped_at` arrive as ISO strings and have to
        # be parsed back to `datetime` before the store's `_utc_iso`
        # tries to read `.tzinfo` (issue #36).
        cb_logger = logging.getLogger("fasten")

        def _insert_cb(row_json: bytes, _userdata: int) -> int:
            row_dict: dict[str, Any] = {}
            try:
                row_dict = json.loads(row_json.decode("utf-8"))
                for fld in ("timestamp", "shipped_at"):
                    v = row_dict.get(fld)
                    if isinstance(v, str):
                        row_dict[fld] = datetime.fromisoformat(v.replace("Z", "+00:00"))
                row = AuditRow(**{k: row_dict[k] for k in AuditRow.__dataclass_fields__ if k in row_dict})
                store.insert(row)
                return 0
            except Exception:  # noqa: BLE001 — store / drainer reports the dead-letter outcome
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
            self._drainer_callback = cb   # keep callback alive
        if old_handle is not None:
            _ffi.drainer_flush(old_handle, 5_000)
            _ffi.drainer_close(old_handle)
            _ffi.store_close(old_handle)
        _ = old_callback  # referenced to prevent premature GC
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
            # Keep old_callback alive until after drainer_close() returns.
            # The drainer's background thread may still call the Python
            # callback (CInsertFn) while we wait for it to stop; releasing
            # the ctypes closure before the thread exits would be a
            # use-after-free and causes a SIGSEGV.
            try:
                _ffi.drainer_close(old_handle)
                _ffi.store_close(old_handle)
            finally:
                del old_callback  # safe to release once thread has stopped

    def _atexit_flush(self) -> None:
        handle = self._drainer_handle
        if handle is not None:
            _ffi.drainer_flush(handle, 5_000)
        self._uninstall_drainer()


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
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
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
