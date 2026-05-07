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

from .audit_queue import _AuditQueueDrainer, AuditStoreError
from .attrs import AuditRow
from .codes import Severity, registry
from .context import current_request_id, mint_id
from .redact import Redactor
from .transport.stdout import StdoutTransport


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


class Engine:
    """
    A single fasten runtime instance.

    Holds service identity, redactor, audit store, stdout transport, and
    drainer state for one deployment context.  Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq: int = 0

        self._service_id: str = ""
        self._node_id: str = ""
        self._tenant_id: Optional[str] = None
        self._audit_store: Any = None
        self._api_store: Any = None
        self._stdout: Optional[StdoutTransport] = None
        self._redactor: Redactor = Redactor()
        self._failure_strategy: str = "queue"
        self._stdlib_logger = logging.getLogger("fasten")

        self._drainer: Optional[_AuditQueueDrainer] = None
        self._drainer_lock = threading.Lock()
        self._atexit_registered = False
        self._last_init_at: Optional[datetime] = None

        self.log: _Logger = _Logger(self)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def init(
        self,
        service_id: Optional[str] = None,
        node_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        audit_store: Any = None,
        api_store: Any = None,
        extra_redact_keys: Optional[list[str]] = None,
        redact_replacement: Optional[str] = None,
        audit_store_failure_strategy: str = "queue",
        queue_capacity: int = 100,
        queue_retry_initial_ms: int = 100,
        queue_retry_max_ms: int = 60_000,
        queue_retry_jitter: bool = True,
        queue_drain_max_attempts: int = 50,
    ) -> None:
        """
        Initialise this Engine. See ``fasten.init`` module docs for full
        parameter reference. Any argument omitted falls back to the
        corresponding environment variable.
        """
        self._service_id = _pick(service_id, "FASTEN_SERVICE_ID")
        self._node_id    = _pick(node_id,    "FASTEN_NODE_ID")
        env_tid          = os.environ.get("FASTEN_TENANT_ID")
        self._tenant_id  = tenant_id if tenant_id is not None else (env_tid or None)

        if not self._service_id or not self._node_id:
            raise RuntimeError(
                "fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required"
            )

        if audit_store is not None:
            self._audit_store = audit_store
        else:
            dsn = os.environ.get("FASTEN_AUDIT_DSN")
            if not dsn:
                raise RuntimeError(
                    "fasten.init: FASTEN_AUDIT_DSN is required. "
                    "Audit rows must go to durable storage — fasten does not "
                    "provide in-memory fallback. "
                    "Set FASTEN_AUDIT_DSN to a sqlite:// or postgres:// URL "
                    "(e.g., 'sqlite:///./fasten-audit.db'). "
                    "For tests, construct a store directly and pass via "
                    "init(audit_store=...)."
                )
            self._audit_store = _store_from_dsn(dsn)

        # Seed monotonic_seq from the store so post-restart rows never
        # duplicate (timestamp, seq) with pre-restart rows on the same node.
        if self._audit_store is not None and hasattr(self._audit_store, "max_monotonic_seq"):
            with self._lock:
                self._seq = self._audit_store.max_monotonic_seq()

        if api_store is not None:
            self._api_store = api_store
        else:
            dsn = os.environ.get("FASTEN_API_DSN")
            if dsn:
                self._api_store = _store_from_dsn(dsn)

        raw_keys = extra_redact_keys or (
            os.environ.get("FASTEN_REDACT_KEYS", "").split(",")
            if os.environ.get("FASTEN_REDACT_KEYS") else None
        )
        replacement = _pick(redact_replacement, "FASTEN_REDACT_REPLACEMENT", "***")
        self._redactor = Redactor(
            extra_keys=[k.strip() for k in raw_keys if k.strip()] if raw_keys else None,
            replacement=replacement,
        )

        self._stdout = StdoutTransport()

        env_strategy = os.environ.get("FASTEN_AUDIT_STORE_FAILURE_STRATEGY")
        strategy = (env_strategy or audit_store_failure_strategy or "queue").lower()
        if strategy not in ("queue", "raise"):
            raise RuntimeError(
                f"fasten.init: audit_store_failure_strategy must be 'queue' or 'raise' "
                f"(got {strategy!r})"
            )
        self._failure_strategy = strategy
        if strategy == "queue":
            self._install_drainer(
                store=self._audit_store,
                capacity=queue_capacity,
                retry_initial_ms=queue_retry_initial_ms,
                retry_max_ms=queue_retry_max_ms,
                retry_jitter=queue_retry_jitter,
                max_attempts=queue_drain_max_attempts,
            )
        else:
            self._uninstall_drainer()
        self._last_init_at = datetime.now(timezone.utc)

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

        meta = registry().get(code)
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
            monotonic_seq=self._next_seq(),
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
            pii_in_detail=meta.pii_in_detail,
            detail=detail,
        )
        row = dataclasses.replace(row, origin_id=row.id)

        # Stdout write before store routing: row reaches the log stream even
        # if the store path blocks or raises.
        if self._stdout is not None:
            self._stdout.write_audit(row.to_dict())

        if self._audit_store is not None:
            if self._failure_strategy == "queue":
                drainer = self._drainer
                if drainer is not None:
                    drainer.put(row)
                else:
                    try:
                        self._audit_store.insert(row)
                    except Exception as e:  # noqa: BLE001
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
        if self._drainer is None:
            return True
        return self._drainer.flush(timeout=timeout)

    def queue_stats(self) -> Optional[dict[str, Any]]:
        """Drainer health snapshot. Returns None in raise mode."""
        if self._drainer is None:
            return None
        return self._drainer.stats()

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

    def last_init_at(self) -> Optional[datetime]:
        """Timestamp of the most recent init() call, or None."""
        return self._last_init_at

    def reset_for_tests(self) -> None:
        """Reset all runtime state to pre-init defaults.

        Intended for test fixtures that need a clean Engine without
        constructing a new one.  Do not call in production code.
        """
        self._uninstall_drainer()
        with self._lock:
            self._seq = 0
        self._service_id = ""
        self._node_id = ""
        self._tenant_id = None
        self._audit_store = None
        self._api_store = None
        self._stdout = None
        self._redactor = Redactor()
        self._failure_strategy = "queue"
        self._last_init_at = None

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
        new_drainer = _AuditQueueDrainer(
            store=store,
            sys_log=self._drainer_sys_log,
            capacity=capacity,
            retry_initial_ms=retry_initial_ms,
            retry_max_ms=retry_max_ms,
            retry_jitter=retry_jitter,
            max_attempts=max_attempts,
        )
        with self._drainer_lock:
            old = self._drainer
            self._drainer = new_drainer
        if old is not None:
            old.flush(timeout=5.0)
            old.stop(timeout=2.0)
        if not self._atexit_registered:
            atexit.register(self._atexit_flush)
            self._atexit_registered = True

    def _uninstall_drainer(self) -> None:
        with self._drainer_lock:
            old = self._drainer
            self._drainer = None
        if old is not None:
            old.stop(timeout=2.0)

    def _atexit_flush(self) -> None:
        if self._drainer is not None:
            self._drainer.flush(timeout=5.0)
            self._drainer.stop(timeout=2.0)


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
