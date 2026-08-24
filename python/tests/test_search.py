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
    # Per-stream error since #16: ring-only sys reports errors.sys, not a
    # top-level error (a global error is only for policy failures like
    # search-disabled or since-missing).
    assert "persistence" in body["errors"]["sys"]


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


def test_search_non_ascii_utf8(tmp_path):
    """PR #59 finding 7: json.dumps default ensure_ascii=True stored 'café'
    as '\\u00e9'; a search for the raw UTF-8 substring returned zero.
    ensure_ascii=False keeps the row bytes queryable and matches Go's
    json.Marshal, which never escapes."""
    _init(search=True)
    t = fasten.transport()
    t.push_syslog({"event": "de.prüfung.failed", "message": "Prüfung fehlgeschlagen",
                   "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-de"})
    t.push_syslog({"event": "fr.café.opened",
                   "timestamp": "2026-08-01T00:00:01Z", "request_id": "r-fr"})
    # Substring q= over the UTF-8 payload must match; with ensure_ascii=True
    # the store held '\\u00fc' / '\\u00e9', so these q= values missed.
    for q, expected_rid in (("prüfung", "r-de"), ("café", "r-fr")):
        body = _client().get(
            "/api/v1/logs/search", params={"q": q, "since": SINCE}
        ).json()
        assert body["counts"]["sys"] == 1, f"non-ASCII q={q!r}: {body}"
        assert body["matches"][0]["request_id"] == expected_rid


def test_search_streams_param_rejects_unknown():
    """?streams=foo must fail loudly — a typo silently searching sys is
    the exact "silent narrowing" the finding #6 fix prevented on /sys?q=."""
    _init(search=True)
    _seed()
    resp = _client().get(
        "/api/v1/logs/search",
        params={"q": "x", "since": SINCE, "streams": "sys,foo"},
    )
    assert resp.status_code == 400
    assert "unknown stream" in resp.json()["detail"]


def test_search_api_stream():
    """PR #59 finding 16 (phase0 restoration): /search?streams=api must
    scan persisted api history the same way sys does."""
    from fasten.store.stream import StreamStore
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        api_store=StreamStore(":memory:", table="api_search"),
        syslog_store=StreamStore(":memory:", table="sys_search"),
        audit_store_failure_strategy="raise",
        search_enabled=True,
    )
    t = fasten.transport()
    t.push_api({"method": "POST", "path": "/checkout", "status": 502,
                "message": "gateway timeout on payment provider",
                "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-api"})
    body = _client().get(
        "/api/v1/logs/search",
        params={"q": "gateway", "since": SINCE, "streams": "api"},
    ).json()
    assert body["counts"]["api"] == 1
    assert body["matches"][0]["stream"] == "api"
    assert body["matches"][0]["request_id"] == "r-api"
    assert "POST /checkout" in body["matches"][0]["summary"]


def test_search_audit_stream():
    """PR #59 finding 16 restoration: /search?streams=audit scans the
    detail column so operators can find rows by an error string they only
    have from a support ticket."""
    _init(search=True)
    fasten.emit(code="USER_CREATED", target="u-99", actor="a",
                detail={"message": "onboarding hit gateway timeout on retry"})
    body = _client().get(
        "/api/v1/logs/search",
        params={"q": "gateway", "since": SINCE, "streams": "audit"},
    ).json()
    assert body["counts"]["audit"] == 1
    assert body["matches"][0]["stream"] == "audit"
    assert body["matches"][0]["summary"] == "USER_CREATED"


def test_search_all_three_streams_fan_out():
    """?streams=audit,api,sys returns matches from every named stream that
    has a store. Stream order in the response is stable (sys → api → audit)
    for UI-friendly tab rendering."""
    from fasten.store.stream import StreamStore
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        api_store=StreamStore(":memory:", table="api_all"),
        syslog_store=StreamStore(":memory:", table="sys_all"),
        audit_store_failure_strategy="raise",
        search_enabled=True,
    )
    t = fasten.transport()
    t.push_syslog({"event": "cache.miss", "message": "cache miss on key foo",
                   "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-sys"})
    t.push_api({"method": "GET", "path": "/foo", "status": 200,
                "message": "hit for foo",
                "timestamp": "2026-08-01T00:00:01Z", "request_id": "r-api"})
    fasten.emit(code="USER_CREATED", target="u", detail={"note": "foo did it"})

    body = _client().get(
        "/api/v1/logs/search",
        params={"q": "foo", "since": SINCE, "streams": "audit,api,sys"},
    ).json()
    assert body["counts"] == {"sys": 1, "api": 1, "audit": 1}
    streams_in_order = [m["stream"] for m in body["matches"]]
    assert streams_in_order == ["sys", "api", "audit"], streams_in_order


def test_search_stream_without_store_reports_per_stream_error():
    """?streams=api on a ring-only api engine must NOT return an empty
    counts.api=0 with no explanation — that would read as "no matches"
    when the caller actually has no store. Per-stream errors dict."""
    _init(search=True)  # syslog_store attached, api_store not
    body = _client().get(
        "/api/v1/logs/search",
        params={"q": "x", "since": SINCE, "streams": "sys,api"},
    ).json()
    assert body["counts"]["api"] == 0
    assert "api" in body["errors"]
    assert "persistence" in body["errors"]["api"]


def test_sys_q_param_rejects_structured_filter_combination():
    """PR #59 finding 6: /sys?q=... combined with a structured filter
    (level/request_id/service_id/event) must 400, not silently discard the
    filter. Parity with the existing /api?q= reject policy."""
    _init(search=True)
    _seed()
    c = _client()
    for chip in ("level", "request_id", "service_id", "event"):
        resp = c.get(
            "/api/v1/logs/sys",
            params={"q": "timeout", "since": SINCE, chip: "anything"},
        )
        assert resp.status_code == 400, (
            f"chip={chip} should 400 (structured + q=); got {resp.status_code} {resp.text}"
        )
        # The error names the dropped chip so the caller knows which filter
        # was refused, not just "bad request".
        assert chip in resp.json()["detail"]
