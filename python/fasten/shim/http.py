"""
HTTP shim — honours or mints `X-Request-ID` per request.

FastAPI / Starlette: `app.add_middleware(RequestIDMiddleware)`.
Flask / other WSGI: drop in `RequestIDMiddleware` as middleware.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

from ..context import _request_id, mint_id, _set_request_id

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
