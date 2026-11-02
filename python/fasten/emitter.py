"""Module-level functions that call a default Engine. Construct an Engine
directly when a process needs more than one configuration."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

from .attrs import AuditRow
from .chain import verify_chain as _verify_chain
from .context import current_request_id, mint_sentinel, with_request_id
from .engine import AuditStoreError  # noqa: F401  re-exported
from .engine import Engine
from .redact import Redactor
from .transport.stdout import StdoutTransport

_default: Engine = Engine()

# ``fasten.log`` is the default engine's logger.
log = _default.log


def init(*args: Any, **kwargs: Any) -> None:
    """Initialise the default Engine. Omitted arguments fall back to env vars;
    see Engine.init_config().

    service_id and node_id (FASTEN_SERVICE_ID, FASTEN_NODE_ID) are required.
    Without audit_store or FASTEN_AUDIT_DSN, audit rows only go to stdout.
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
    """Wait for queued audit rows to be stored. Returns False on timeout."""
    return _default.flush(timeout=timeout)


def queue_stats() -> Optional[dict[str, Any]]:
    """Drainer stats, or None in raise mode."""
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


def persisted_streams() -> frozenset[str]:
    """Streams of the default Engine that have a store attached."""
    return _default.persisted_streams()


def search_enabled() -> bool:
    """Whether free-text search is enabled on the default Engine."""
    return _default.search_enabled()


@contextmanager
def background(kind: str = "bg") -> Iterator[str]:
    """Context for work outside a request, such as a worker or scheduled tick.

    Keeps the active request_id if there is one, otherwise sets a sentinel of
    the given ``kind`` (``bg``, ``sched`` or ``lib``). Yields the request_id.
    """
    active = current_request_id()
    if active:
        yield active
    else:
        with with_request_id(mint_sentinel(kind, _default._service_id)) as rid:
            yield rid


def go(fn: Callable[..., Any], *args: Any, _kind: str = "bg", **kwargs: Any) -> threading.Thread:
    """Run ``fn`` in a daemon thread with the caller's request_id, or a new
    sentinel if there is none. contextvars do not cross threads on their own.
    Returns the started thread."""
    parent = current_request_id()

    def _run() -> None:
        rid = parent or mint_sentinel(_kind, _default._service_id)
        with with_request_id(rid):
            fn(*args, **kwargs)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def init_config(*args: Any, **kwargs: Any) -> Any:
    """Resolve init parameters to a FastenConfig without starting runtime."""
    return _default.init_config(*args, **kwargs)


def start(cfg: Any) -> None:
    """Apply a FastenConfig to the default Engine."""
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
    """Verify a replicated batch and insert its verified prefix in one
    transaction, via the default Engine's store.

    Does not raise on a chain break. The returned IngestResult carries
    ``rejected_from_seq``, the monotonic_seq to resend from.
    """
    return _default.ingest_replicated(rows)
