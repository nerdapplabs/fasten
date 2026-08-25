"""Regression tests from the Phase 1 review:

- write-through persist failure must not break the hot logging path
- null-timestamp rows agree between ring and store under since/until windows
- combined filters compose (AND), limit truncates to the newest N
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


def _init(**stores):
# service_id / node_id are passed explicitly to fasten.init below; the
    # earlier os.environ writes were dead code that leaked env across tests.
        fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


# ── write-through resilience ──────────────────────────────────────────────

class _BrokenStore(StreamStore):
    def __init__(self):
        super().__init__(":memory:", table="broken_sink")

    def insert(self, row):
        raise RuntimeError("disk full")


def test_persist_failure_does_not_break_hot_path(capsys):
    """A store insert that raises must be swallowed (logged to stderr), the
    ring copy kept, and the push call must return normally."""
    _init()
    t = fasten.transport()
    t._api_store = _BrokenStore()  # simulate a failing sink
    t.push_api({"method": "GET", "path": "/x", "request_id": "r1"})  # must not raise
    assert len(t._api) == 1                       # ring (hot path) kept the row
    assert "api persist failed" in capsys.readouterr().err


def test_persist_failure_degrades_completeness_flag(capsys):
    """A swallowed persist failure must not leave completeness lying: reads
    for a store-backed stream come only from the store, so a row that failed
    to persist is silently missing — the flag degrades to "store-degraded"
    instead of asserting durability. Sticky: a later successful write does
    not clear it (the hole in history remains)."""
    store = StreamStore(":memory:", table="api_log")
    _init(api_store=store)
    t = fasten.transport()

    assert _client().get("/api/v1/logs/api").json()["completeness"] == {"api": "store"}

    real_insert = StreamStore.insert
    store.insert = lambda row: (_ for _ in ()).throw(RuntimeError("disk full"))
    t.push_api({"method": "GET", "path": "/lost", "request_id": "r1"})  # swallowed
    assert "api persist failed" in capsys.readouterr().err

    body = _client().get("/api/v1/logs/api").json()
    assert body["completeness"] == {"api": "store-degraded"}
    assert store.degraded and store.write_failures == 1

    # sink recovers — the flag stays degraded, because the lost row does not come back
    store.insert = lambda row: real_insert(store, row)
    t.push_api({"method": "GET", "path": "/kept", "request_id": "r2"})
    body = _client().get("/api/v1/logs/api").json()
    assert body["completeness"] == {"api": "store-degraded"}
    assert [r["path"] for r in body["rows"]] == ["/kept"]  # /lost is gone — the hole

    # /correlate carries the same degraded class
    corr = _client().get("/api/v1/logs/correlate?request_id=r2").json()
    assert corr["completeness"]["api"] == "store-degraded"


# ── null-timestamp ring/store agreement ───────────────────────────────────

def test_null_timestamp_window_agrees_ring_vs_store():
    # ring-only
    _init()
    fasten.transport().push_syslog({"level": "info", "event": "no.ts", "request_id": "r1"})  # no timestamp
    ring_until = _client().get("/api/v1/logs/sys?until=2026-06-25T00:00:00Z").json()["rows"]
    ring_since = _client().get("/api/v1/logs/sys?since=2026-06-25T00:00:00Z").json()["rows"]

    # persisted
    _init(syslog_store=StreamStore(":memory:", table="syslog"))
    fasten.transport().push_syslog({"level": "info", "event": "no.ts", "request_id": "r1"})
    store_until = _client().get("/api/v1/logs/sys?until=2026-06-25T00:00:00Z").json()["rows"]
    store_since = _client().get("/api/v1/logs/sys?since=2026-06-25T00:00:00Z").json()["rows"]

    # a missing timestamp is treated as "" by both: included by until, excluded by since
    assert len(ring_until) == 1 and len(store_until) == 1
    assert len(ring_since) == 0 and len(store_since) == 0


# ── combined filters + limit ──────────────────────────────────────────────

def test_combined_status_and_since_compose():
    _init(api_store=StreamStore(":memory:", table="api_log"))
    t = fasten.transport()
    t.push_api({"method": "POST", "path": "/a", "status": 502, "request_id": "r1", "timestamp": "2026-06-25T09:00:00Z"})
    t.push_api({"method": "POST", "path": "/b", "status": 502, "request_id": "r2", "timestamp": "2026-06-25T13:00:00Z"})
    t.push_api({"method": "GET", "path": "/c", "status": 200, "request_id": "r3", "timestamp": "2026-06-25T13:00:00Z"})

    rows = _client().get("/api/v1/logs/api?status=502&since=2026-06-25T12:00:00Z").json()["rows"]
    assert [r["path"] for r in rows] == ["/b"]   # only the row matching BOTH


def test_limit_truncates_to_newest():
    _init(api_store=StreamStore(":memory:", table="api_log"))
    t = fasten.transport()
    for i in range(10):
        t.push_api({"method": "GET", "path": f"/{i}", "request_id": f"r{i}",
                    "timestamp": f"2026-06-25T10:00:{i:02d}Z"})
    rows = _client().get("/api/v1/logs/api?limit=3").json()["rows"]
    assert len(rows) == 3
    assert [r["path"] for r in rows] == ["/9", "/8", "/7"]   # newest-first
