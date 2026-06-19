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
from .chain import verify_chain as _verify_chain
from .engine import AuditStoreError  # noqa: F401 — re-exported
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


def init_config(*args: Any, **kwargs: Any) -> Any:
    """Resolve init parameters to a FastenConfig without starting runtime."""
    return _default.init_config(*args, **kwargs)


def start(cfg: Any) -> None:
    """Wire runtime from a FastenConfig. Delegates to the default Engine."""
    _default.start(cfg)


def last_init_at() -> "Any":
    """Timestamp of the most recent init() call on the default Engine, or None."""
    return _default.last_init_at()


def verify_chain(rows: "list[Any]") -> "Any":
    """Verify the hash chain of a list of AuditRow objects.

    Returns a ChainVerifyResult with ok, total_rows, first_break_at, reason.
    """
    return _verify_chain(rows)


def list_unshipped(limit: int = 100) -> "list[AuditRow]":
    """Rows not yet shipped upstream (oldest first), via the default Engine's store.

    Raises RuntimeError if the default Engine has no audit store configured.
    """
    return _default.list_unshipped(limit=limit)


def mark_shipped(ids: "list[str]") -> None:
    """Mark rows shipped upstream by id, via the default Engine's store."""
    _default.mark_shipped(ids)


def ingest_replicated(rows: "list[AuditRow]") -> Any:
    """Verify + insert the verified prefix of a replicated batch, via the
    default Engine's store.

    Verifies the per-row hash chain first, then inserts the longest verified
    prefix in a single transaction. Does NOT raise on a chain break — the
    returned IngestResult carries ``rejected_from_seq`` (the monotonic_seq of the
    first broken row) so the sender resyncs from there.
    """
    return _default.ingest_replicated(rows)
