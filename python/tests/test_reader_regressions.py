"""Regression tests for the gh #58 conformance fixes that were verified
ad-hoc during development but lacked a committed test:

- C1   empty ?request_id= on /correlate -> 422 (not just a missing param)
- FR3-1 empty ?q= on /logs/sys -> 422
- FR3-3 q= on /logs/api -> 400 (sys-only)
- M3    absolute sqlite DSN path preserved (sqlite:////abs)
- M4    non-string request_id -> sentinel string
- FR5-9 /audit dual pagination: total/limit/offset + next_after cursor
"""
import pytest

import fasten
from fasten.context import is_sentinel, with_request_id
from fasten.store.sqlite import SQLiteStore


def _client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    return TestClient(app)


def _init(search=False, **stores):
    # Pass config explicitly (no global env mutation, so tests stay isolated —
    # setting FASTEN_SEARCH_ENABLED here would leak into other tests).
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
        search_enabled=search,
        **stores,
    )


# ── C1 ────────────────────────────────────────────────────────────────────
def test_correlate_empty_request_id_rejected():
    _init()
    c = _client()
    assert c.get("/api/v1/logs/correlate?request_id=").status_code == 422  # empty string
    assert c.get("/api/v1/logs/correlate").status_code == 422              # missing
    assert c.get("/api/v1/logs/correlate?request_id=r1").status_code == 200


# ── FR3-1 ─────────────────────────────────────────────────────────────────
def test_sys_empty_q_rejected():
    _init(search=True)
    c = _client()
    assert c.get("/api/v1/logs/sys?q=&since=2020-01-01T00:00:00Z").status_code == 422
    assert c.get("/api/v1/logs/sys").status_code == 200  # absent q is fine


# ── FR3-3 ─────────────────────────────────────────────────────────────────
def test_api_q_rejected_sys_only():
    _init()
    c = _client()
    assert c.get("/api/v1/logs/api?q=foo").status_code == 400
    assert c.get("/api/v1/logs/api?q=").status_code == 400   # presence, even empty
    assert c.get("/api/v1/logs/api").status_code == 200


# ── M3 ────────────────────────────────────────────────────────────────────
def test_stream_store_from_dsn_preserves_absolute_path(tmp_path):
    from fasten.engine import _stream_store_from_dsn
    abs_db = tmp_path / "streams.db"
    s = _stream_store_from_dsn(f"sqlite:///{abs_db}", "api_log")  # 3 slashes + abs = 4
    got = getattr(s, "path", getattr(s, "_path", None))
    assert got == str(abs_db), f"absolute path not preserved: {got!r}"
    # relative form stays relative
    s2 = _stream_store_from_dsn("sqlite:///rel.db", "api_log")
    assert getattr(s2, "path", getattr(s2, "_path", None)) == "rel.db"


# PR #59 finding 11: reject unknown DSN schemes rather than silently opening
# a local SQLite file named after the DSN's path component. Any of these
# used to create a container-local file that reads then reports
# completeness=store — durability asserted over an ephemeral file.
def test_stream_store_dsn_rejects_unknown_schemes():
    import pytest as _pytest
    from fasten.engine import _stream_store_from_dsn
    for dsn in (
        "postgresql+psycopg://host/db",   # SQLAlchemy dialect form
        "mysql://host/logs",              # wrong database entirely
        "redis://host/0",                 # completely unrelated
    ):
        with _pytest.raises(ValueError, match="scheme"):
            _stream_store_from_dsn(dsn, "api_log")


# ── M4 ────────────────────────────────────────────────────────────────────
def test_stamp_request_id_non_string_becomes_sentinel():
    from fasten.transport.stdout import StdoutTransport
    tr = StdoutTransport(service_id="svc")
    row = {"request_id": 123, "event": "x"}
    tr._stamp_request_id(row)
    assert isinstance(row["request_id"], str) and is_sentinel(row["request_id"])
    real = {"request_id": "real-abc"}
    tr._stamp_request_id(real)
    assert real["request_id"] == "real-abc"  # a real string id is untouched


# ── FR5-9 ─────────────────────────────────────────────────────────────────
def test_audit_dual_pagination_cursor_and_offset():
    _init()
    with with_request_id("rq"):
        for _ in range(5):
            fasten.emit(code="USER_CREATED", target="u", actor="a")
    c = _client()
    j = c.get("/api/v1/logs/audit?limit=2").json()
    assert set(j) >= {"rows", "total", "limit", "offset", "next_after", "completeness"}
    assert j["total"] == 5 and j["limit"] == 2 and j["offset"] == 0
    # cursor walk (older rows), newest-first so seqs descend
    seqs, cur = [], None
    for _ in range(6):
        url = "/api/v1/logs/audit?limit=2" + (f"&after={cur}" if cur else "")
        page = c.get(url).json()
        if not page["rows"]:
            break
        seqs.append([r["monotonic_seq"] for r in page["rows"]])
        cur = page["next_after"]
        if cur is None:
            break
    assert seqs == [[5, 4], [3, 2], [1]]
    # offset path still works
    assert [r["monotonic_seq"] for r in c.get("/api/v1/logs/audit?limit=2&offset=2").json()["rows"]] == [3, 2]
