"""
Correlation context carrier — one `request_id` ambient across every emission.

Python uses contextvars so async handlers inherit it automatically.
Go equivalent: ctx.WithValue. JS equivalent: AsyncLocalStorage.

Primary API:
  - `with_request_id(rid)` — context manager, preferred
  - `current_request_id()` — read the ambient id
  - `mint_id()` — generate a new id without setting it
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional


_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "fasten_request_id", default=None
)


def mint_id() -> str:
    """Mint a new 12-char request id."""
    return uuid.uuid4().hex[:12]


# Sentinel namespaces for rows written outside a real request context. Stamping
# one of these (instead of leaving request_id empty) keeps every stream row
# correlatable — `/logs/correlate?request_id=boot-…` returns the whole startup
# window — and self-describing: the prefix tells an operator what kind of
# context produced the row instead of "anonymous noise".
SENTINEL_KINDS = ("boot", "sched", "bg", "lib", "orphan")


def mint_sentinel(kind: str, service_id: str = "") -> str:
    """Mint a namespaced sentinel request_id (e.g. ``orphan-svc-ab12cd34ef56``).

    boot is minted once per process and shared (one startup window); the
    others are per-task/per-write and unique."""
    if kind not in SENTINEL_KINDS:
        raise ValueError(f"unknown sentinel kind {kind!r}; expected one of {SENTINEL_KINDS}")
    return f"{kind}-{service_id or 'svc'}-{mint_id()}"


def request_id_kind(request_id: str) -> str:
    """Classify a request_id by its namespace: a sentinel kind, or ``request``
    for a real correlation id. Lets a UI pivot/filter by where a row came from."""
    if request_id:
        for k in SENTINEL_KINDS:
            if request_id.startswith(k + "-"):
                return k
    return "request"


def is_sentinel(request_id: str) -> bool:
    """True if request_id is a minted sentinel (not a real correlation id)."""
    return request_id_kind(request_id) != "request"


def current_request_id() -> Optional[str]:
    """Return the ambient request_id, or None if not set."""
    return _request_id.get()


def _set_request_id(request_id: str) -> contextvars.Token:
    """Low-level: set request_id and return a reset token. Prefer with_request_id()."""
    return _request_id.set(request_id)


@contextmanager
def with_request_id(request_id: Optional[str] = None) -> Iterator[str]:
    """
    Context manager — sets request_id for the duration of the block.
    If None, mints a new one.
    """
    rid = request_id or mint_id()
    token = _request_id.set(rid)
    try:
        yield rid
    finally:
        _request_id.reset(token)
