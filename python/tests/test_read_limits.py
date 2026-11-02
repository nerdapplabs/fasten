"""Read endpoints reject a non-positive or over-cap limit.

SQLite reads ``LIMIT -1`` as no limit and Postgres rejects it with a 500, so
the router refuses non-positive values with a 422.
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
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
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
    _init()
    rid = "req-bound"
    t = fasten.transport()
    for i in range(10):
        t.push_syslog({"level": "info", "event": f"e{i}", "request_id": rid})

    resp = _client().get("/api/v1/logs/sys?limit=3")
    assert resp.status_code == 200
    assert len(resp.json()["rows"]) == 3
