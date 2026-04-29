"""
Scheduler shim — mints `scheduler-<run_id>` at autonomous job start.

No external caller exists for scheduled jobs; without this, audit rows
emitted by jobs would carry synthetic / null request_ids. Instead, every
job run mints a deterministic-shape id so downstream audit stitches.
"""
from __future__ import annotations

import inspect
import uuid
from contextlib import contextmanager
from typing import Callable, Iterator, TypeVar

from ..context import with_request_id

T = TypeVar("T")


def mint_run_id() -> str:
    """e.g. 'scheduler-a1b2c3d4'."""
    return f"scheduler-{uuid.uuid4().hex[:8]}"


@contextmanager
def job_run(run_id: str | None = None) -> Iterator[str]:
    """Wrap a scheduled job body — all logs inside inherit the minted id."""
    rid = run_id or mint_run_id()
    with with_request_id(rid) as ctx_id:
        yield ctx_id


def instrument(fn: Callable[..., T]) -> Callable[..., T]:
    """Decorator — wraps a scheduled callable so each invocation mints a run id.

    Works for both sync and async callables.
    """
    if inspect.iscoroutinefunction(fn):
        async def async_wrapper(*args: object, **kwargs: object) -> T:
            with job_run():
                return await fn(*args, **kwargs)  # type: ignore[return-value]
        return async_wrapper  # type: ignore[return-value]

    def wrapper(*args: object, **kwargs: object) -> T:
        with job_run():
            return fn(*args, **kwargs)
    return wrapper
