"""§3.4 — indexed structured-field filters on the sys/api reader endpoints.

event (sys), status (api), and since/until time windows are honoured
identically whether the stream is ring-only or persisted, so discovery by a
field an operator already knows works the same in both modes.
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


def _init(**stores):
# service_id / node_id are passed explicitly to fasten.init below; the
    # earlier os.environ writes were dead code that leaked env across tests.
        fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        **stores,
    )


def _seed():
    t = fasten.transport()
    t.push_syslog({"level": "error", "event": "db.timeout", "request_id": "r1", "timestamp": "2026-06-25T10:00:00Z"})
    t.push_syslog({"level": "info", "event": "cache.miss", "request_id": "r2", "timestamp": "2026-06-25T12:00:00Z"})
    t.push_api({"method": "POST", "path": "/checkout", "status": 502, "request_id": "r1", "timestamp": "2026-06-25T10:00:00Z"})
    t.push_api({"method": "GET", "path": "/health", "status": 200, "request_id": "r3", "timestamp": "2026-06-25T12:00:00Z"})


# ── ring-only (no persistence) ────────────────────────────────────────────

def test_event_filter_on_sys_ring():
    _init()
    _seed()
    rows = _client().get("/api/v1/logs/sys?event=db.timeout").json()["rows"]
    assert [r["event"] for r in rows] == ["db.timeout"]


def test_status_filter_on_api_ring():
    _init()
    _seed()
    rows = _client().get("/api/v1/logs/api?status=502").json()["rows"]
    assert len(rows) == 1 and rows[0]["status"] == 502


def test_since_until_window_on_api_ring():
    _init()
    _seed()
    rows = _client().get("/api/v1/logs/api?since=2026-06-25T11:00:00Z").json()["rows"]
    assert [r["path"] for r in rows] == ["/health"]   # only the 12:00 row
    rows = _client().get("/api/v1/logs/sys?until=2026-06-25T11:00:00Z").json()["rows"]
    assert [r["event"] for r in rows] == ["db.timeout"]  # only the 10:00 row


# ── persisted: store path must filter identically ─────────────────────────

def test_filters_agree_between_store_and_ring():
    _init(
        api_store=StreamStore(":memory:", table="api_log"),
        syslog_store=StreamStore(":memory:", table="syslog"),
    )
    _seed()
    c = _client()
    # event on persisted sys
    sys = c.get("/api/v1/logs/sys?event=cache.miss").json()
    assert sys["completeness"] == {"sys": "store"}
    assert [r["event"] for r in sys["rows"]] == ["cache.miss"]
    # status on persisted api
    api = c.get("/api/v1/logs/api?status=502").json()
    assert api["completeness"] == {"api": "store"}
    assert [r["status"] for r in api["rows"]] == [502]
    # since on persisted api
    win = c.get("/api/v1/logs/api?since=2026-06-25T11:00:00Z").json()["rows"]
    assert [r["path"] for r in win] == ["/health"]
