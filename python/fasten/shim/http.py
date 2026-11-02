"""ASGI middleware: X-Request-ID handling and api log rows.

    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(APILogger, skip={"/health", "/metrics"})
"""
from __future__ import annotations

import time
from typing import Any, Awaitable, Callable, Iterable, Optional

from ..canonical_ts import canonical_now
from ..context import _request_id, current_request_id, mint_id, _set_request_id

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class RequestIDMiddleware:
    """Use the incoming X-Request-ID (or mint one) as the request_id for the
    request, and echo it in the response headers."""

    HEADER = b"x-request-id"

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        rid = headers.get(self.HEADER, b"").decode() or mint_id()
        token = _set_request_id(rid)

        async def send_wrapper(msg: dict[str, Any]) -> None:
            if msg["type"] == "http.response.start":
                headers_out = list(msg.get("headers", []))
                headers_out.append((b"x-request-id", rid.encode()))
                msg = {**msg, "headers": headers_out}
            await send(msg)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _request_id.reset(token)


class APILogger:
    """Record an api log row per HTTP request, except for paths in ``skip``.

    Rows have the same keys as Go's ``fasten.APILogger``: ``method``,
    ``path``, ``status``, ``duration_ms``, ``request_id``, ``timestamp``.

    Add it after :class:`RequestIDMiddleware` so rows get its request_id.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        skip: Optional[Iterable[str]] = None,
    ) -> None:
        self.app = app
        self.skip = frozenset(skip or ())

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self.skip:
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        # Capture status + rid at response.start time. Reading current_request_id()
        # after the inner await chain returns is too late: any downstream
        # RequestIDMiddleware will have reset its contextvar token by then.
        snapshot: dict[str, Any] = {"status": 200, "request_id": ""}

        async def send_wrapper(msg: dict[str, Any]) -> None:
            if msg["type"] == "http.response.start":
                snapshot["status"] = int(msg.get("status", 200))
                snapshot["request_id"] = current_request_id() or ""
            await send(msg)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            from ..emitter import transport as _transport
            t = _transport()
            if t is None:
                return
            row = {
                "method": scope.get("method", ""),
                "path": path,
                "status": snapshot["status"],
                "duration_ms": duration_ms,
                "request_id": snapshot["request_id"],
                "timestamp": canonical_now(),
            }
            t.write_api(row)
