"""
Correlation context carrier — one `request_id` ambient across every emission.

Python uses contextvars so async handlers inherit it automatically.
Go equivalent: ctx.WithValue. JS equivalent: AsyncLocalStorage.
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional


_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "rivet_request_id", default=None
)


def MintID() -> str:
    """Mint a new 12-char request id."""
    return uuid.uuid4().hex[:12]


def current_request_id() -> Optional[str]:
    """Return the ambient request_id, or None if not set."""
    return _request_id.get()


def WithRequestID(request_id: str) -> contextvars.Token:
    """Set request_id in the current context. Returns token for reset."""
    return _request_id.set(request_id)


@contextmanager
def with_request_id(request_id: Optional[str] = None) -> Iterator[str]:
    """
    Context manager — sets request_id for the duration of the block.
    If None, mints a new one.
    """
    rid = request_id or MintID()
    token = _request_id.set(rid)
    try:
        yield rid
    finally:
        _request_id.reset(token)
