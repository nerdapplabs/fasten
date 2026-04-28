"""
MQTT shim — correlation over pub/sub via reserved `_req` field in payload.

Publish helper injects `_req = current_request_id()`; subscriber helper
reads `_req` into the ambient ctx before invoking the handler.

Wire convention: JSON payloads carry a reserved `_req` key. Binary payloads
carry the id as an MQTT v5 user property `req-id` when possible.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Awaitable

from ..context import MintID, with_request_id, current_request_id


async def publish(client: Any, topic: str, payload: dict[str, Any]) -> None:
    """Publish with `_req` injected from ctx (mint if absent)."""
    rid = current_request_id() or MintID()
    enriched = {**payload, "_req": rid}
    await client.publish(topic, json.dumps(enriched))


def handler(topic: str) -> Callable[[Callable[..., Awaitable[None]]], Callable[..., Awaitable[None]]]:
    """
    Decorator — reads `_req` from incoming payload, sets ctx for the handler.

    Usage:
        @mqtt_shim.handler("cmd/+/config/updated")
        async def on_cmd(msg, ctx):  # ctx.request_id is set
            ...
    """
    def decorate(fn: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
        async def wrapper(msg: Any) -> None:
            payload = json.loads(msg.payload) if msg.payload else {}
            rid = payload.get("_req")
            with with_request_id(rid) as ctx_id:
                ctx = type("Ctx", (), {"request_id": ctx_id, "topic": topic})()
                await fn(msg, ctx)
        return wrapper
    return decorate
