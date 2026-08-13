"""FR4 completeness gaps from the gh_issues_58 review:

- mixed-class /correlate composition (each stream reports its own class)
- /correlate per-stream `truncated` boolean (counts < totals)

(The sticky-through-recovery gap for store-degraded is covered by
test_phase1_review.test_persist_failure_degrades_completeness_flag.)
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
    app.include_router(build_router(), prefix="/api/v1/logs")
    return TestClient(app)


def _init(**stores):
    import os
    os.environ["FASTEN_SERVICE_ID"] = "test-svc"
    os.environ["FASTEN_NODE_ID"] = "test-node"
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


def test_correlate_mixed_durability_classes():
    """FR4-3: /correlate reports each stream's own class when they differ —
    audit=store, api=store-degraded, sys=ring in one response."""
    api = StreamStore(":memory:", table="api_mix")
    _init(api_store=api)  # audit store-backed; no sys store -> ring
    # degrade the api stream via a swallowed persist failure
    api.insert = lambda row: (_ for _ in ()).throw(RuntimeError("disk full"))
    fasten.transport().push_api({"method": "GET", "path": "/x", "request_id": "r1"})

    corr = _client().get("/api/v1/logs/correlate?request_id=r1").json()
    assert corr["completeness"] == {
        "audit": "store",
        "api": "store-degraded",
        "sys": "ring",
    }


def test_correlate_truncated_flag():
    """FR4-4: /correlate exposes a per-stream `truncated` boolean (counts <
    totals) so callers don't re-derive the inequality."""
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
