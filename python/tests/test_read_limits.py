"""Read endpoints bound ``limit`` at ge=1.

A negative limit is not just invalid input: it reaches SQLite as ``LIMIT -1``,
which SQLite reads as *no limit* and dumps the whole table/ring on an admin
endpoint (and Postgres rejects it with a 500). The router must refuse it up
front rather than pass it down the query path.
"""
import pytest

import fasten
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
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
    )


_ENDPOINTS = [
    "/api/v1/logs/sys",
    "/api/v1/logs/api",
    "/api/v1/logs/audit",
    "/api/v1/logs/correlate?request_id=x&",
]


@pytest.mark.parametrize("base", _ENDPOINTS)
@pytest.mark.parametrize("bad", [-1, 0, -1000])
def test_non_positive_limit_rejected(base, bad):
    _init()
    sep = "" if base.endswith("&") else ("&" if "?" in base else "?")
    resp = _client().get(f"{base}{sep}limit={bad}")
    assert resp.status_code == 422, (base, bad, resp.text)


@pytest.mark.parametrize("base", _ENDPOINTS)
def test_over_cap_limit_rejected(base):
    _init()
    sep = "" if base.endswith("&") else ("&" if "?" in base else "?")
    resp = _client().get(f"{base}{sep}limit=1001")
    assert resp.status_code == 422, (base, resp.text)


def test_valid_limit_returns_bounded_rows():
    """A negative limit used to return the whole ring; a bounded limit returns
    at most that many rows."""
    _init()
    rid = "req-bound"
    t = fasten.transport()
    for i in range(10):
        t.push_syslog({"level": "info", "event": f"e{i}", "request_id": rid})

    resp = _client().get("/api/v1/logs/sys?limit=3")
    assert resp.status_code == 200
    assert len(resp.json()["rows"]) == 3
