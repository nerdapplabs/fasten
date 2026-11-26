"""Carry the request_id over MQTT in a ``_req`` field of JSON payloads."""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from ..context import current_request_id, mint_id, usable_request_id, with_request_id


async def publish(client: Any, topic: str, payload: dict[str, Any]) -> None:
    """Publish ``payload`` with ``_req`` set to the current request_id
    (minting one if unset)."""
    rid = current_request_id() or mint_id()
    enriched = {**payload, "_req": rid}
    await client.publish(topic, json.dumps(enriched))


_Handler = Callable[..., Awaitable[None]]


def handler(topic: str) -> Callable[[_Handler], _Handler]:
    """Decorator that runs the handler with the request_id from ``_req``,
    or a new one when ``_req`` is missing or not a usable request id
    (``context.usable_request_id``).

        @mqtt_shim.handler("cmd/+/config/updated")
        async def on_cmd(msg, ctx):  # ctx.request_id is set
            ...
    """
    def decorate(fn: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
        async def wrapper(msg: Any) -> None:
            payload = json.loads(msg.payload) if msg.payload else {}
            rid = usable_request_id(payload.get("_req"))
            with with_request_id(rid) as ctx_id:
                ctx = type("Ctx", (), {"request_id": ctx_id, "topic": topic})()
                await fn(msg, ctx)
        return wrapper
    return decorate
