"""fasten.shim.http: RequestIDMiddleware and APILogger."""
import asyncio


import fasten
from fasten.shim.http import APILogger, RequestIDMiddleware


# ASGI harness

class _Echo:
    """Minimal ASGI app that returns 200 with no body."""

    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def __call__(self, scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": self.status,
            "headers": [],
        })
        await send({"type": "http.response.body", "body": b""})


def _scope(method: str = "GET", path: str = "/users") -> dict:
    return {"type": "http", "method": method, "path": path, "headers": []}


async def _noop_receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


def _send_recorder():
    sent: list[dict] = []

    async def send(msg: dict) -> None:
        sent.append(msg)

    return sent, send


# RequestIDMiddleware

def test_request_id_middleware_mints_when_absent(initialized):
    app = RequestIDMiddleware(_Echo())
    sent, send = _send_recorder()
    asyncio.run(app(_scope(), _noop_receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    rid_headers = [h for h in start["headers"] if h[0] == b"x-request-id"]
    assert len(rid_headers) == 1
    assert len(rid_headers[0][1].decode()) == 12


def _response_request_id(headers: list) -> str:
    app = RequestIDMiddleware(_Echo())
    sent, send = _send_recorder()
    scope = {**_scope(), "headers": headers}
    asyncio.run(app(scope, _noop_receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return next(h[1] for h in start["headers"] if h[0] == b"x-request-id").decode()


def test_request_id_middleware_keeps_a_valid_client_id(initialized):
    for rid in (b"req-A1.b2_c3", b"550e8400-e29b-41d4-a716-446655440000", b"x" * 128):
        assert _response_request_id([(b"x-request-id", rid)]) == rid.decode()


def test_request_id_middleware_replaces_an_unusable_client_id(initialized):
    for rid in (b"x" * 129, b"x" * 6000, b"has space", b"semi;colon", b"nul\x00byte",
                b"\xff\xfe", "caf\u00e9".encode()):
        got = _response_request_id([(b"x-request-id", rid)])
        assert len(got) == 12 and got.isalnum(), (rid, got)


# APILogger

def test_api_logger_writes_row_to_transport(initialized):
    app = APILogger(_Echo(status=201))
    _, send = _send_recorder()
    asyncio.run(app(_scope(method="POST", path="/users"), _noop_receive, send))

    transport = fasten.transport()
    rows = transport.query_api(limit=10)
    assert len(rows) >= 1
    last = rows[0]
    assert last["method"] == "POST"
    assert last["path"] == "/users"
    assert last["status"] == 201
    assert "duration_ms" in last
    assert "timestamp" in last
    assert "request_id" in last  # a sentinel without RequestIDMiddleware


def test_api_logger_skips_configured_paths(initialized):
    app = APILogger(_Echo(), skip={"/health", "/metrics"})
    _, send = _send_recorder()
    transport = fasten.transport()
    before = len(transport.query_api(limit=100))

    asyncio.run(app(_scope(path="/health"), _noop_receive, send))
    asyncio.run(app(_scope(path="/metrics"), _noop_receive, send))

    after = len(transport.query_api(limit=100))
    assert after == before, "skipped paths must not push api rows"


def test_api_logger_inherits_request_id(initialized):
    """When chained behind RequestIDMiddleware, api row carries the rid."""
    app = APILogger(RequestIDMiddleware(_Echo()))
    _, send = _send_recorder()

    headers = [(b"x-request-id", b"deadbeefcafe")]
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": headers}
    asyncio.run(app(scope, _noop_receive, send))

    rows = fasten.transport().query_api(limit=1)
    assert rows[0]["request_id"] == "deadbeefcafe"


def test_api_logger_passthrough_for_non_http_scope(initialized):
    """Lifespan / websocket scopes must not be intercepted."""
    app = APILogger(_Echo())
    _, send = _send_recorder()
    transport = fasten.transport()
    before = len(transport.query_api(limit=100))

    asyncio.run(app({"type": "lifespan"}, _noop_receive, send))

    after = len(transport.query_api(limit=100))
    assert after == before
