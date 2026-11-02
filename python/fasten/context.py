"""The ambient ``request_id``, held in a contextvar so async tasks inherit it."""
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


# Request id prefixes for rows written outside a request, so they can still be
# correlated (e.g. /logs/correlate?request_id=boot-...) and the prefix says
# where the row came from. The transport stamps boot and orphan itself; the
# others are for callers using mint_sentinel().
SENTINEL_KINDS = ("boot", "sched", "bg", "lib", "orphan")


def mint_sentinel(kind: str, service_id: str = "") -> str:
    """Mint a sentinel request_id such as ``orphan-svc-ab12cd34ef56``.

    Raises ValueError if ``kind`` is not in SENTINEL_KINDS.
    """
    if kind not in SENTINEL_KINDS:
        raise ValueError(f"unknown sentinel kind {kind!r}; expected one of {SENTINEL_KINDS}")
    return f"{kind}-{service_id or 'svc'}-{mint_id()}"


def request_id_kind(request_id: str) -> str:
    """Return the sentinel kind of ``request_id``, or ``"request"`` for a real id.

    This only looks at the prefix, so an upstream id that starts with e.g.
    ``boot-`` is reported as a sentinel. ids from mint_id() never do.
    """
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
    """Set request_id for the duration of the block, minting one if None."""
    rid = request_id or mint_id()
    token = _request_id.set(rid)
    try:
        yield rid
    finally:
        _request_id.reset(token)
