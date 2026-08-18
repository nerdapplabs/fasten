"""FR3 — constrained free-text search over persisted sys history.

sys-only, opt-in (search.enabled), since= mandatory, hard-capped, no ranking.
A match returns its request_id so a consumer can hand it to /correlate.
"""
import pytest

import fasten
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore

SINCE = "2026-01-01T00:00:00Z"


def _client(**router_kwargs):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(build_router(**router_kwargs), prefix="/api/v1/logs")
    return TestClient(app)


def _init(search=False, with_store=True):
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="syslog") if with_store else None,
        audit_store_failure_strategy="raise",
        search_enabled=search,
    )


def _seed():
    t = fasten.transport()
    t.push_syslog({"level": "error", "event": "db.timeout",
                   "message": "connection reset by peer",
                   "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"})
    t.push_syslog({"level": "info", "event": "ok",
                   "timestamp": "2026-08-01T00:00:01Z", "request_id": "r-2"})


def test_search_disabled_by_default():
    _init(search=False)
    _seed()
    body = _client().get("/api/v1/logs/search", params={"q": "reset", "since": SINCE}).json()
    assert body["matches"] == []
    assert "disabled" in body["error"]


def test_search_finds_request_id():
    _init(search=True)
    _seed()
    body = _client().get(
        "/api/v1/logs/search", params={"q": "reset by peer", "since": SINCE}
    ).json()
    assert body["counts"]["sys"] == 1
    m = body["matches"][0]
    assert m["stream"] == "sys"
    assert m["request_id"] == "r-1"      # the id a follow-up /correlate needs
    assert m["summary"] == "db.timeout"


def test_search_case_insensitive():
    _init(search=True)
    _seed()
    body = _client().get("/api/v1/logs/search", params={"q": "RESET", "since": SINCE}).json()
    assert body["counts"]["sys"] == 1


def test_search_since_mandatory():
    _init(search=True)
    _seed()
    resp = _client().get("/api/v1/logs/search", params={"q": "reset"})
    assert resp.status_code == 422  # since is a required query param


def test_search_requires_persistence():
    _init(search=True, with_store=False)  # ring-only sys — no durable history
    _seed()
    body = _client().get("/api/v1/logs/search", params={"q": "reset", "since": SINCE}).json()
    assert "persistence" in body["error"]


def test_search_result_cap():
    _init(search=True)
    t = fasten.transport()
    for i in range(10):
        t.push_syslog({"event": "boom", "timestamp": f"2026-08-01T00:00:{i:02d}Z",
                       "request_id": f"r-{i}"})
    body = _client().get(
        "/api/v1/logs/search", params={"q": "boom", "since": SINCE, "limit": 3}
    ).json()
    assert body["counts"]["sys"] == 3  # hard-capped


def test_search_wildcard_escaped():
    _init(search=True)
    t = fasten.transport()
    t.push_syslog({"event": "100%done", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-w"})
    t.push_syslog({"event": "100XYZdone", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-x"})
    body = _client().get("/api/v1/logs/search", params={"q": "100%done", "since": SINCE}).json()
    assert body["counts"]["sys"] == 1  # literal %, not a LIKE wildcard → only r-w
    assert body["matches"][0]["request_id"] == "r-w"


def test_search_wildcard_escaped_underscore():
    # `_` is the single-char LIKE wildcard; it must be escaped to match literally.
    # Regression guard for the escape order in stream.py / stream_store.go.
    _init(search=True)
    t = fasten.transport()
    t.push_syslog({"event": "ab_cd", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-u"})
    t.push_syslog({"event": "abXcd", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-x"})
    body = _client().get("/api/v1/logs/search", params={"q": "ab_cd", "since": SINCE}).json()
    assert body["counts"]["sys"] == 1  # literal _, not a wildcard → only r-u (not abXcd)
    assert body["matches"][0]["request_id"] == "r-u"


def test_search_backslash_escaped():
    # `\` is the ESCAPE char itself; it must be escaped so it is matched as data,
    # not treated as a metacharacter that consumes the next char. The event value
    # c\d (one backslash) is stored in the JSON payload as c\\d.
    _init(search=True)
    t = fasten.transport()
    t.push_syslog({"event": "c\\d", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-bs"})
    t.push_syslog({"event": "cXd", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-dec"})
    body = _client().get("/api/v1/logs/search", params={"q": "c\\\\d", "since": SINCE}).json()
    assert body["counts"]["sys"] == 1  # backslashes matched literally → only r-bs
    assert body["matches"][0]["request_id"] == "r-bs"


def test_sys_q_param_gated_and_bounded():
    _init(search=True)
    _seed()
    body = _client().get(
        "/api/v1/logs/sys", params={"q": "timeout", "since": SINCE}
    ).json()
    assert len(body["rows"]) == 1
    assert body["rows"][0]["request_id"] == "r-1"

    no_since = _client().get("/api/v1/logs/sys", params={"q": "timeout"}).json()
    assert "since" in no_since["error"]
