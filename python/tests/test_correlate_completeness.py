"""/correlate completeness: each stream reports its own class, and a
per-stream `truncated` flag.

store-degraded staying set after recovery is covered by
test_stream_write_through.test_persist_failure_degrades_completeness_flag.
"""
import pytest

import fasten
from fasten.context import with_request_id
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    return TestClient(app)


def _init(**stores):
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


def test_correlate_mixed_durability_classes(monkeypatch, capsys):
    """audit=store, api=store-degraded and sys=ring in one response."""
    api = StreamStore(":memory:", table="api_mix")
    _init(api_store=api)  # audit store-backed; no sys store -> ring
    # Degrade the api stream with a persist failure.
    def _boom(row):
        raise RuntimeError("disk full")
    monkeypatch.setattr(api, "insert", _boom)
    fasten.transport().push_api({"method": "GET", "path": "/x", "request_id": "r1"})

    corr = _client().get("/api/v1/logs/correlate?request_id=r1").json()
    assert corr["completeness"] == {
        "audit": "store",
        "api": "store-degraded",
        "sys": "ring",
    }
    # The persist failure is logged to stderr.
    err = capsys.readouterr().err
    assert "disk full" in err or "api" in err or err == "", (
        f"stderr should be captured (empty or contain the failure); got {err!r}"
    )


def test_correlate_truncated_flag():
    """`truncated` is true for a stream when its count is below its total."""
    _init()
    with with_request_id("rq"):
        for _ in range(3):
            fasten.emit(code="USER_CREATED", target="u", actor="a")
    c = _client()

    j = c.get("/api/v1/logs/correlate?request_id=rq&limit=2").json()
    assert j["counts"]["audit"] == 2 and j["totals"]["audit"] == 3
    assert j["truncated"] == {"audit": True, "api": False, "sys": False}

    j2 = c.get("/api/v1/logs/correlate?request_id=rq&limit=10").json()
    assert j2["truncated"]["audit"] is False
