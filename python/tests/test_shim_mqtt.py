"""The MQTT shim runs a handler under the request_id from ``_req`` when it
is usable, and under a new one otherwise."""
import asyncio
import json

from fasten.shim import mqtt


class _Msg:
    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode()


def _request_id_for(payload: dict) -> str:
    seen = {}

    @mqtt.handler("cmd/+/x")
    async def on_cmd(msg, ctx):
        seen["rid"] = ctx.request_id

    asyncio.run(on_cmd(_Msg(payload)))
    return seen["rid"]


def test_handler_keeps_a_usable_request_id():
    for rid in ("req-A1.b2_c3", "x" * 128):
        assert _request_id_for({"_req": rid}) == rid


def test_handler_replaces_an_unusable_request_id():
    for rid in ("x" * 129, "x" * 6000, "has space", "café", 42, None, ["a"]):
        got = _request_id_for({"_req": rid})
        assert got != rid and len(got) == 12 and got.isalnum(), (rid, got)
