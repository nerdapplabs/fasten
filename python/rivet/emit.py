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
from .codes import registry
from .context import MintID, current_request_id
from .redact import Redactor

_lock = threading.Lock()
_seq: int = 0

# Runtime config (populated by init())
_service_id: str = ""
_node_id: str = ""
_tenant_id: Optional[str] = None
_audit_store: Any = None
_api_store: Any = None
_stdout: Optional[StdoutTransport] = None
_redactor: Redactor = Redactor()
_logger = logging.getLogger("rivet")


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
    Initialise rivet. Any argument omitted falls back to env var.

    Required (env or arg): RIVET_SERVICE_ID, RIVET_NODE_ID.
    Optional: RIVET_TENANT_ID, RIVET_AUDIT_DSN, RIVET_API_DSN.

    Calling init() with no arguments = "everything from env" — preferred.
    """
    global _service_id, _node_id, _tenant_id, _audit_store, _api_store, _stdout, _redactor

    _service_id = service_id or os.environ.get("RIVET_SERVICE_ID") or ""
    _node_id = node_id or os.environ.get("RIVET_NODE_ID") or ""
    _tenant_id = tenant_id or os.environ.get("RIVET_TENANT_ID") or None

    if not _service_id or not _node_id:
        raise RuntimeError(
            "rivet.init: RIVET_SERVICE_ID and RIVET_NODE_ID are required"
        )

    if audit_store is not None:
        _audit_store = audit_store
    else:
        dsn = os.environ.get("RIVET_AUDIT_DSN")
        if not dsn:
            raise RuntimeError(
                "rivet.init: RIVET_AUDIT_DSN is required. "
                "Audit rows must go to durable storage — rivet does not provide in-memory fallback. "
                "Set RIVET_AUDIT_DSN to a sqlite:// or postgres:// URL "
                "(e.g., 'sqlite:///./rivet-audit.db'). "
                "For tests, construct a store directly and pass via init(audit_store=...)."
            )
        from .store.sqlite import SQLiteStore
        _audit_store = SQLiteStore.from_dsn(dsn)

    if api_store is not None:
        _api_store = api_store
    else:
        dsn = os.environ.get("RIVET_API_DSN")
        if dsn:
            from .store.sqlite import SQLiteStore
            _api_store = SQLiteStore.from_dsn(dsn)

    keys = extra_redact_keys or (
        os.environ.get("RIVET_REDACT_KEYS", "").split(",") if os.environ.get("RIVET_REDACT_KEYS") else None
    )
    replacement = redact_replacement or os.environ.get("RIVET_REDACT_REPLACEMENT", "***")
    _redactor = Redactor(
        extra_keys=[k.strip() for k in keys if k.strip()] if keys else None,
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
    severity: Optional[str] = None,
    method: Optional[str] = None,
) -> AuditRow:
    """
    Emit an audit row. Anchors auto-filled where possible.

    Raises RuntimeError if init() hasn't been called.
    """
    if not _service_id:
        raise RuntimeError("rivet.init() must be called before emit()")

    meta = registry().get(code)
    if meta is None:
        raise ValueError(f"unknown audit code: {code}")

    request_id = current_request_id() or MintID()
    detail = _redactor.redact(detail or {})

    row = AuditRow(
        id=f"evt-{uuid.uuid4().hex[:20]}",
        origin_id="",                                   # set below
        monotonic_seq=_next_seq(),
        timestamp=datetime.now(timezone.utc),
        code=code,
        action=meta.action,
        severity=severity or meta.severity.value,
        service_id=_service_id,
        source_node_id=_node_id,
        tenant_id=_tenant_id,
        actor=actor,
        actor_kind=actor_kind,
        target=target,
        category=meta.category,
        domain=meta.domain,
        method=method or "http",
        request_id=request_id,
        detail=detail,
    )
    row = row.__class__(
        **{f.name: getattr(row, f.name) for f in dataclasses.fields(row) if f.name != "origin_id"},
        origin_id=row.id,
    )

    if _audit_store is not None:
        _audit_store.insert(row)
    if _stdout is not None:
        _stdout.write_audit(dataclasses.asdict(row))
    return row


class _Logger:
    """Convenience wrapper over stdlib logging, stamping request_id automatically."""

    def _emit(self, level: int, event: str, **fields: Any) -> None:
        payload = {"event": event, "request_id": current_request_id(), **fields}
        if _stdout is not None:
            _stdout.write_syslog({"level": logging.getLevelName(level).lower(), **payload})
        else:
            _logger.log(level, json.dumps(payload, default=str))

    def debug(self, event: str, **fields: Any) -> None: self._emit(logging.DEBUG, event, **fields)
    def info(self, event: str, **fields: Any) -> None: self._emit(logging.INFO, event, **fields)
    def warning(self, event: str, **fields: Any) -> None: self._emit(logging.WARNING, event, **fields)
    def error(self, event: str, **fields: Any) -> None: self._emit(logging.ERROR, event, **fields)


log = _Logger()


def _get_audit_store() -> Any:
    """Return the current audit store (set by init()). None before init()."""
    return _audit_store


def _get_stdout() -> "Optional[StdoutTransport]":
    """Return the current StdoutTransport (set by init()). None before init()."""
    return _stdout


def _get_redactor() -> "Redactor":
    """Return the active Redactor — always non-None (defaults to Redactor()). """
    return _redactor
