"""
The Emit contract — refuses to produce an audit row without the 6 anchors.

Public surface:
  - init(...)          — called once at process start; reads env vars
  - emit(code, ...)    — produces an audit row (WHO/WHAT/WHEN/WHERE/WHOM/HOW/CORRELATION)
  - log.info/warn/...  — structured syslog line; inherits request_id from ctx
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .transport.stdout import StdoutTransport
from .attrs import AuditRow
from .codes import Severity, registry
from .context import mint_id, current_request_id
from .redact import Redactor

_lock = threading.Lock()
_seq: int = 0

# Runtime config — populated by init()
_service_id: str = ""
_node_id: str = ""
_tenant_id: Optional[str] = None
_audit_store: Any = None
_api_store: Any = None
_stdout: Optional[StdoutTransport] = None
_redactor: Redactor = Redactor()
_logger = logging.getLogger("fasten")


def init(
    service_id: Optional[str] = None,
    node_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    audit_store: Any = None,
    api_store: Any = None,
    extra_redact_keys: Optional[list[str]] = None,
    redact_replacement: str = "***",
) -> None:
    """
    Initialise fasten. Any argument omitted falls back to the corresponding env var.

    Required (env or arg):
      - FASTEN_SERVICE_ID — service identity for the WHERE anchor
      - FASTEN_NODE_ID — host/node identity for the WHERE anchor
      - FASTEN_AUDIT_DSN — durable audit store DSN (sqlite:// or postgres://).
        Audit rows must go to durable storage; fasten does not provide an
        in-memory fallback. Required when ``audit_store=`` is not passed.

    Optional:
      - FASTEN_TENANT_ID — tenant / org / site
      - FASTEN_API_DSN — opt-in persistent api-log store (default: ring buffer only)
      - FASTEN_REDACT_KEYS — comma-separated extra redaction patterns
      - FASTEN_REDACT_REPLACEMENT — replacement string (default: "***")

    Calling init() with no arguments = "everything from env" — preferred.
    Errors are explicit: missing FASTEN_SERVICE_ID / FASTEN_NODE_ID /
    FASTEN_AUDIT_DSN raise RuntimeError with a fix-it message.

    After init(), public accessors are stable:
      - ``fasten.transport()`` → active StdoutTransport (audit/sys/api streams)
      - ``fasten.redactor()`` → active Redactor (so adopter logging layers
        can apply the same key-pattern scrubbing fasten applies on emit)
    """
    global _service_id, _node_id, _tenant_id, _audit_store, _api_store, _stdout, _redactor

    _service_id = service_id or os.environ.get("FASTEN_SERVICE_ID") or ""
    _node_id    = node_id    or os.environ.get("FASTEN_NODE_ID")    or ""
    _tenant_id  = tenant_id  or os.environ.get("FASTEN_TENANT_ID") or None

    if not _service_id or not _node_id:
        raise RuntimeError(
            "fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required"
        )

    if audit_store is not None:
        _audit_store = audit_store
    else:
        dsn = os.environ.get("FASTEN_AUDIT_DSN")
        if not dsn:
            raise RuntimeError(
                "fasten.init: FASTEN_AUDIT_DSN is required. "
                "Audit rows must go to durable storage — fasten does not provide in-memory fallback. "
                "Set FASTEN_AUDIT_DSN to a sqlite:// or postgres:// URL "
                "(e.g., 'sqlite:///./fasten-audit.db'). "
                "For tests, construct a store directly and pass via init(audit_store=...)."
            )
        from .store.sqlite import SQLiteStore
        _audit_store = SQLiteStore.from_dsn(dsn)

    if api_store is not None:
        _api_store = api_store
    else:
        dsn = os.environ.get("FASTEN_API_DSN")
        if dsn:
            from .store.sqlite import SQLiteStore
            _api_store = SQLiteStore.from_dsn(dsn)

    raw_keys = extra_redact_keys or (
        os.environ.get("FASTEN_REDACT_KEYS", "").split(",")
        if os.environ.get("FASTEN_REDACT_KEYS") else None
    )
    replacement = redact_replacement or os.environ.get("FASTEN_REDACT_REPLACEMENT", "***")
    _redactor = Redactor(
        extra_keys=[k.strip() for k in raw_keys if k.strip()] if raw_keys else None,
        replacement=replacement,
    )

    _stdout = StdoutTransport()


def _next_seq() -> int:
    global _seq
    with _lock:
        _seq += 1
        return _seq


def emit(
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

    `method` should reflect the transport that triggered this event
    (http, mqtt, cli, scheduler, ui, agent_tool). Defaults to "sdk" when
    called outside any shim context.

    Raises RuntimeError if init() has not been called.
    Raises ValueError for an unregistered code.
    """
    if not _service_id:
        raise RuntimeError("fasten.init() must be called before emit()")

    meta = registry().get(code)
    if meta is None:
        raise ValueError(f"unknown audit code: {code!r}")

    request_id = current_request_id() or mint_id()
    detail = _redactor.redact(detail or {})

    row = AuditRow(
        id=f"evt-{uuid.uuid4().hex[:20]}",
        origin_id="",
        monotonic_seq=_next_seq(),
        timestamp=datetime.now(timezone.utc),
        code=code,
        action=meta.action,
        severity=str(severity) if severity is not None else str(meta.severity),
        service_id=_service_id,
        source_node_id=_node_id,
        tenant_id=_tenant_id,
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

    if _audit_store is not None:
        _audit_store.insert(row)
    if _stdout is not None:
        _stdout.write_audit(row.to_dict())
    return row


class _Logger:
    """Structured syslog writer — stamps request_id automatically."""

    def _emit(self, level: int, event: str, **fields: Any) -> None:
        payload = {
            "event": event,
            "request_id": current_request_id(),
            "service_id": _service_id or None,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            **fields,
        }
        if _stdout is not None:
            _stdout.write_syslog({"level": logging.getLevelName(level).lower(), **payload})
        else:
            # fasten.init() not yet called — fall back to stdlib logger so
            # log.* works in tests and library code before init().
            _logger.log(level, json.dumps(payload, default=str))

    def debug(self,   event: str, **fields: Any) -> None: self._emit(logging.DEBUG,   event, **fields)
    def info(self,    event: str, **fields: Any) -> None: self._emit(logging.INFO,     event, **fields)
    def warn(self,    event: str, **fields: Any) -> None: self._emit(logging.WARNING,  event, **fields)
    def warning(self, event: str, **fields: Any) -> None: self._emit(logging.WARNING,  event, **fields)
    def error(self,   event: str, **fields: Any) -> None: self._emit(logging.ERROR,    event, **fields)


log = _Logger()


# ── Public accessors ──────────────────────────────────────────────────────
# Adopters writing custom middleware / logging layers reach the same
# transport / redactor / store that emit() uses through these.

def transport() -> Optional[StdoutTransport]:
    """Return the active StdoutTransport, or None if init() has not been called.

    The transport carries the audit / sys / api ring buffers and writes
    NDJSON lines to stdout. Use it for hand-rolled middleware that needs
    to push api / sys rows the SDK itself wouldn't otherwise emit.
    """
    return _stdout


def redactor() -> Redactor:
    """Return the active Redactor.

    Use it from adopter-side logging layers that want to apply the same
    secret-key scrubbing fasten applies on emit() — e.g. structlog
    processors, custom syslog wrappers. Always returns a usable Redactor;
    pre-init() it returns the default with no extra keys.
    """
    return _redactor


def audit_store() -> Any:
    """Return the active AuditRepository, or None if init() has not been called.

    The reader uses this to query rows; adopters writing their own
    reader / replication / outbox layer can use the same store fasten
    inserts into.
    """
    return _audit_store
