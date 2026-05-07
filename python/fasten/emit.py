"""
Module-level free functions — thin wrappers around the default Engine.

For multi-tenant or fully-isolated usage, construct Engine instances directly:

    from fasten import Engine
    eng = Engine()
    eng.init(tenant_id="t-42", audit_store=my_store)
    eng.emit(code="ORDER_PLACED", ...)

The free functions (``fasten.init``, ``fasten.emit``, …) delegate to a
single default Engine so existing single-tenant adopter code is unchanged.
"""
from __future__ import annotations

from typing import Any, Optional

from .attrs import AuditRow
from .audit_queue import AuditStoreError  # noqa: F401 — re-exported for back-compat
from .engine import Engine
from .redact import Redactor
from .transport.stdout import StdoutTransport

# Module-level default instance — all free functions delegate here.
_default: Engine = Engine()

# ``fasten.log`` is the default engine's logger.
log = _default.log


def init(*args: Any, **kwargs: Any) -> None:
    """
    Initialise fasten. Any argument omitted falls back to the corresponding
    env var. See Engine.init() for the full parameter reference.

    Required (env or arg):
      - FASTEN_SERVICE_ID
      - FASTEN_NODE_ID
      - FASTEN_AUDIT_DSN  (or ``audit_store=`` kwarg)
    """
    _default.init(*args, **kwargs)


def emit(
    code: str,
    target: str,
    actor: str = "system",
    actor_kind: str = "service",
    detail: Optional[dict[str, Any]] = None,
    severity: Optional[str] = None,
    method: Optional[str] = None,
) -> AuditRow:
    """Emit an audit row via the default Engine."""
    return _default.emit(
        code=code,
        target=target,
        actor=actor,
        actor_kind=actor_kind,
        detail=detail,
        severity=severity,
        method=method,
    )


def flush(timeout: float = 5.0) -> bool:
    """Block until pending rows drain. Delegates to the default Engine."""
    return _default.flush(timeout=timeout)


def queue_stats() -> Optional[dict[str, Any]]:
    """Drainer health snapshot. Delegates to the default Engine."""
    return _default.queue_stats()


def transport() -> Optional[StdoutTransport]:
    """Active StdoutTransport of the default Engine."""
    return _default.transport()


def redactor() -> Redactor:
    """Active Redactor of the default Engine."""
    return _default.redactor()


def audit_store() -> Any:
    """Active AuditRepository of the default Engine."""
    return _default.audit_store()
