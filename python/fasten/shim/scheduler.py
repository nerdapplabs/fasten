"""Give each scheduled job run its own ``scheduler-<run_id>`` request_id."""
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
    """Run the block with ``run_id`` (or a new one) as the request_id."""
    rid = run_id or mint_run_id()
    with with_request_id(rid) as ctx_id:
        yield ctx_id


def instrument(fn: Callable[..., T]) -> Callable[..., T]:
    """Decorator giving each call of a sync or async job a new run id."""
    if inspect.iscoroutinefunction(fn):
        async def async_wrapper(*args: object, **kwargs: object) -> T:
            with job_run():
                return await fn(*args, **kwargs)
        return async_wrapper  # type: ignore[return-value]

    def wrapper(*args: object, **kwargs: object) -> T:
        with job_run():
            return fn(*args, **kwargs)
    return wrapper
