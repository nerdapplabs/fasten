"""FR1 — opt-in persistence for the api / sys streams.

When a StreamStore is configured, the ring stays the hot write path and the
store is a write-through sink; reads for that stream come from the store so
they reach durable history instead of a bounded window, and the completeness
flag flips ring -> store. With no store, behaviour is unchanged (ring-only).
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
    app.include_router(build_router(), prefix="/api/v1/logs")
    return TestClient(app)


def _init_with_streams(**stores):
# service_id / node_id are passed explicitly to fasten.init below; the
    # earlier os.environ writes were dead code that leaked env across tests.
        fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


# ── StreamStore unit behaviour ────────────────────────────────────────────

def test_streamstore_roundtrip_and_filter():
    s = StreamStore(":memory:", table="api_log")
    s.insert({"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-A"})
    s.insert({"method": "GET", "path": "/v1/health", "status": 200, "request_id": "r-B"})

    # newest-first, byte-identical rows
    allrows = s.query()
    assert [r["request_id"] for r in allrows] == ["r-B", "r-A"]
    # request_id filter
    assert [r["path"] for r in s.query(request_id="r-A")] == ["/v1/checkout"]
    # method/path are exact-match (parity with the ring and the Go SDK)
    assert len(s.query(method="POST")) == 1
    assert len(s.query(method="post")) == 0          # not case-folded
    assert len(s.query(path="/v1/checkout")) == 1
    assert len(s.query(path="checkout")) == 0        # not substring


def test_streamstore_survives_beyond_ring_capacity():
    """The ring drops old rows; the store keeps them — the core FR1 win."""
    s = StreamStore(":memory:", table="syslog")
    for i in range(5000):
        s.insert({"level": "info", "event": f"e{i}", "request_id": f"r-{i}"})
    assert s.count() == 5000
    # a request_id from long before a 2000-row ring would still hold
    assert len(s.query(request_id="r-0")) == 1


# ── End-to-end through init + reader ──────────────────────────────────────

def test_api_persisted_reports_store_and_serves_from_store():
    _init_with_streams(api_store=StreamStore(":memory:", table="api_log"))
    assert fasten.persisted_streams() == frozenset({"audit", "api"})

    t = fasten.transport()
    t.push_api({"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-1"})

    body = _client().get("/api/v1/logs/api?request_id=r-1").json()
    assert body["completeness"] == {"api": "store"}          # flipped ring -> store
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
    """No stream store → ring-only, completeness 'ring' (backward compatible)."""
    _init_with_streams()  # audit only
    assert fasten.persisted_streams() == frozenset({"audit"})

    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/x", "request_id": "r-9"})
    body = _client().get("/api/v1/logs/api").json()
    assert body["completeness"] == {"api": "ring"}
    assert len(body["rows"]) == 1                              # served from ring


def test_write_through_keeps_ring_and_store_in_sync():
    """A persisted push lands in BOTH the ring (hot path) and the store."""
    store = StreamStore(":memory:", table="api_log")
    _init_with_streams(api_store=store)
    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/y", "request_id": "r-7"})

    assert store.count() == 1               # write-through sink got it
    assert len(t._api) == 1                 # ring (hot path) also got it


def test_drainer_self_reports_persist_like_any_syslog_push(capsys):
    """write_drainer_syslog is a syslog push path like any other: with a
    syslog store attached, reads come only from the store, so an unpersisted
    drainer event would vanish from the reader API (Go persists them via
    PushSyslog — parity)."""
    _init_with_streams(syslog_store=StreamStore(":memory:", table="syslog"))
    t = fasten.transport()

    t.write_drainer_syslog({"level": "error", "event": "audit_enqueue_failed"})
    capsys.readouterr()  # drainer path intentionally writes the row to stderr

    rows = t.query_syslog(event="audit_enqueue_failed")  # served from the store
    assert len(rows) == 1
    assert rows[0]["request_id"]  # sentinel invariant holds on this path too
