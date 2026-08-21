"""
HTTP shim — honours or mints `X-Request-ID` per request, and (optionally)
pushes an api-log row to the fasten transport on each request.

FastAPI / Starlette:
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(APILogger, skip={"/health", "/metrics"})
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional

from ..canonical_ts import canonical_now
from ..context import _request_id, current_request_id, mint_id, _set_request_id

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class RequestIDMiddleware:
    """
    ASGI middleware — mints/honours X-Request-ID on every request and sets
    it in the ambient context for the duration of the call.
    """

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
    """
    ASGI middleware — pushes each inbound HTTP request into fasten's
    api-log ring buffer (and the persistent api store if configured).

    Skips paths in ``skip`` (set or iterable of strings, e.g.
    ``{"/health", "/metrics"}``).

    Mirrors Go's ``fasten.APILogger(skipPaths...)`` — same row keys
    (``method``, ``path``, ``status``, ``duration_ms``, ``request_id``,
    ``timestamp``) so /logs/api responses are uniform across services
    in mixed-language fleets.

    Place this middleware **after** :class:`RequestIDMiddleware` so the
    api row carries the request_id minted/honoured upstream.
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
