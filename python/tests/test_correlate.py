"""FR2 — unified correlation read: every stream for one request_id.

GET /logs/correlate?request_id=X fans out to the audit store + sys/api
rings-or-stores and assembles {request_id, audit, api, sys, counts,
completeness}, so a consumer gets the whole operation in one call.
"""
import pytest

import fasten
from fasten.context import with_request_id
from fasten.store.sqlite import SQLiteStore


def _client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    return TestClient(app)


def _init():
    # service_id / node_id passed explicitly; the earlier os.environ writes were dead code that leaked env across tests.
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
    )


def test_correlate_assembles_all_three_streams():
    _init()
    rid = "req-corr-1"
    with with_request_id(rid):
        fasten.emit(code="USER_CREATED", target="u-1", actor="alice")
    t = fasten.transport()
    t.push_api({"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": rid})
    t.push_syslog({"level": "error", "event": "db.timeout", "request_id": rid})
    # noise under a different request_id must not leak in
    t.push_api({"method": "GET", "path": "/health", "status": 200, "request_id": "other"})

    body = _client().get(f"/api/v1/logs/correlate?request_id={rid}").json()

    assert body["request_id"] == rid
    assert body["counts"] == {"audit": 1, "api": 1, "sys": 1}
    assert all(r["request_id"] == rid for r in body["audit"])
    assert body["api"][0]["path"] == "/v1/checkout"
    assert body["sys"][0]["event"] == "db.timeout"
    assert body["completeness"] == {"audit": "store", "api": "ring", "sys": "ring"}


def test_correlate_empty_for_unknown_request_id():
    _init()
    body = _client().get("/api/v1/logs/correlate?request_id=nope").json()
    assert body["counts"] == {"audit": 0, "api": 0, "sys": 0}
    assert body["audit"] == [] and body["api"] == [] and body["sys"] == []


def test_correlate_requires_request_id():
    _init()
    resp = _client().get("/api/v1/logs/correlate")
    assert resp.status_code == 422  # FastAPI: missing required query param


def test_correlate_reports_store_when_streams_persisted():
    """When api/sys persist, completeness flips and history is recoverable
    past the ring window — the historical-investigation use case."""
    from fasten.store.stream import StreamStore
    # service_id / node_id passed explicitly; the earlier os.environ writes were dead code that leaked env across tests.
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        api_store=StreamStore(":memory:", table="api_log"),
        syslog_store=StreamStore(":memory:", table="syslog"),
        audit_store_failure_strategy="raise",
    )
    rid = "req-old"
    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/x", "request_id": rid})
    # bury it under > ring capacity of later traffic
    for i in range(2500):
        t.push_api({"method": "GET", "path": "/n", "request_id": f"n-{i}"})

    body = _client().get(f"/api/v1/logs/correlate?request_id={rid}").json()
    assert body["completeness"] == {"audit": "store", "api": "store", "sys": "store"}
    assert body["counts"]["api"] == 1  # recovered despite ring churn


def test_correlate_totals_expose_truncation_ring_only():
    """counts reflects the capped response; totals reflects what the backing
    source holds — counts < totals is the truncation signal a heavily
    correlated request_id needs (100-of-100 vs 100-of-5000 was previously
    indistinguishable)."""
    _init()
    rid = "req-hot"
    t = fasten.transport()
    for i in range(7):
        t.push_syslog({"level": "info", "event": f"step.{i}", "request_id": rid})

    body = _client().get(f"/api/v1/logs/correlate?request_id={rid}&limit=3").json()
    assert body["counts"]["sys"] == 3
    assert body["totals"]["sys"] == 7  # truncated: 3 returned of 7 available

    # untruncated read: counts == totals
    body = _client().get(f"/api/v1/logs/correlate?request_id={rid}&limit=100").json()
    assert body["counts"]["sys"] == body["totals"]["sys"] == 7


def test_correlate_totals_count_store_history_and_audit():
    """With persistence on, totals counts durable history (beyond any window)
    for the streams AND the audit store — every stream reports total vs
    returned."""
    from fasten.context import with_request_id
    from fasten.store.stream import StreamStore
    # service_id / node_id passed explicitly; the earlier os.environ writes were dead code that leaked env across tests.
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        api_store=StreamStore(":memory:", table="api_log"),
        audit_store_failure_strategy="raise",
    )
    rid = "req-deep"
    t = fasten.transport()
    for _ in range(5):
        t.push_api({"method": "GET", "path": "/x", "request_id": rid})
    with with_request_id(rid):
        fasten.emit(code="USER_CREATED", target="u-1", actor="alice")
        fasten.emit(code="USER_CREATED", target="u-2", actor="alice")

    body = _client().get(f"/api/v1/logs/correlate?request_id={rid}&limit=2").json()
    assert body["counts"] == {"audit": 2, "api": 2, "sys": 0}
    assert body["totals"]["api"] == 5
    assert body["totals"]["audit"] == 2
    assert body["totals"]["sys"] == 0
