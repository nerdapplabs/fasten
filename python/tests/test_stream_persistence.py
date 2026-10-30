"""Optional persistence for the api and sys streams.

With a StreamStore attached, writes go to the ring and through to the store,
reads come from the store, and completeness is "store". Without one, the
stream is ring-only.
"""
import pytest

import fasten
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


def _init_with_streams(**stores):
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


# StreamStore

def test_streamstore_roundtrip_and_filter():
    s = StreamStore(":memory:", table="api_log")
    s.insert({"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-A"})
    s.insert({"method": "GET", "path": "/v1/health", "status": 200, "request_id": "r-B"})

    # newest first
    allrows = s.query()
    assert [r["request_id"] for r in allrows] == ["r-B", "r-A"]
    assert [r["path"] for r in s.query(request_id="r-A")] == ["/v1/checkout"]
    # method and path are exact match, same as the ring
    assert len(s.query(method="POST")) == 1
    assert len(s.query(method="post")) == 0          # not case-folded
    assert len(s.query(path="/v1/checkout")) == 1
    assert len(s.query(path="checkout")) == 0        # not substring


def test_streamstore_survives_beyond_ring_capacity():
    """The ring drops old rows; the store keeps them."""
    s = StreamStore(":memory:", table="syslog")
    for i in range(5000):
        s.insert({"level": "info", "event": f"e{i}", "request_id": f"r-{i}"})
    assert s.count() == 5000
    # r-0 would have left a 2000-row ring long ago
    assert len(s.query(request_id="r-0")) == 1


# Through init and the reader

def test_api_persisted_reports_store_and_serves_from_store():
    _init_with_streams(api_store=StreamStore(":memory:", table="api_log"))
    assert fasten.persisted_streams() == frozenset({"audit", "api"})

    t = fasten.transport()
    t.push_api({"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-1"})

    body = _client().get("/api/v1/logs/api?request_id=r-1").json()
    assert body["completeness"] == {"api": "store"}
    assert [r["path"] for r in body["rows"]] == ["/v1/checkout"]


def test_sys_persisted_depth_beyond_ring():
    """sys persisted: a request_id older than the ring window is still found."""
    _init_with_streams(syslog_store=StreamStore(":memory:", table="syslog"))
    t = fasten.transport()
    for i in range(3000):  # > default ring maxlen (2000)
        t.push_syslog({"level": "error", "event": "db.timeout", "request_id": f"r-{i}"})

    body = _client().get("/api/v1/logs/sys?request_id=r-0").json()
    assert body["completeness"] == {"sys": "store"}
    assert len(body["rows"]) == 1                              # survived ring churn


def test_unpersisted_streams_stay_ring():
    """With no stream store, reads come from the ring and completeness is 'ring'."""
    _init_with_streams()  # audit only
    assert fasten.persisted_streams() == frozenset({"audit"})

    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/x", "request_id": "r-9"})
    body = _client().get("/api/v1/logs/api").json()
    assert body["completeness"] == {"api": "ring"}
    assert len(body["rows"]) == 1                              # served from ring


def test_write_through_keeps_ring_and_store_in_sync():
    """A push lands in both the ring and the store."""
    store = StreamStore(":memory:", table="api_log")
    _init_with_streams(api_store=store)
    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/y", "request_id": "r-7"})

    assert store.count() == 1
    assert len(t._api) == 1


def test_drainer_self_reports_persist_like_any_syslog_push(capsys):
    """Drainer events are persisted like any syslog push. With a syslog store
    attached, reads come only from the store, so they would otherwise be
    missing from the reader API."""
    _init_with_streams(syslog_store=StreamStore(":memory:", table="syslog"))
    t = fasten.transport()

    t.write_drainer_syslog({"level": "error", "event": "audit_enqueue_failed"})
    capsys.readouterr()  # the drainer path also writes the row to stderr

    rows = t.query_syslog(event="audit_enqueue_failed")  # served from the store
    assert len(rows) == 1
    assert rows[0]["request_id"]  # gets a sentinel id
