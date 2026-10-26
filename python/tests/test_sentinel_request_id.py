"""Every stream row carries a request_id.

Rows written outside a request get a sentinel: a shared boot id during
startup, then a unique orphan id per row.
"""
import pytest

import fasten
from fasten.context import is_sentinel, mint_sentinel, request_id_kind, with_request_id
from fasten.store.sqlite import SQLiteStore


def _init():
    fasten.init(
        service_id="test-svc", node_id="test-node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
    )


# Helpers

def test_mint_and_classify_sentinels():
    rid = mint_sentinel("orphan", "svc")
    assert rid.startswith("orphan-svc-")
    assert is_sentinel(rid)
    assert request_id_kind(rid) == "orphan"
    assert request_id_kind("3a7b1c9d") == "request"   # a real id
    with pytest.raises(ValueError):
        mint_sentinel("bogus")


# Stamping in the transport

def test_contextless_push_gets_boot_sentinel_during_startup():
    _init()
    t = fasten.transport()
    t.push_syslog({"level": "info", "event": "started"})   # no request_id
    row = t.query_syslog()[0]
    assert request_id_kind(row["request_id"]) == "boot"
    assert row["request_id"].startswith("boot-test-svc-")


def test_real_request_ends_boot_window_then_orphan():
    _init()
    t = fasten.transport()
    t.push_api({"method": "GET", "path": "/a"})             # boot (startup)
    with with_request_id("real-123"):
        from fasten import current_request_id
        t.push_api({"method": "GET", "path": "/b", "request_id": current_request_id()})
    t.push_api({"method": "GET", "path": "/c"})             # orphan

    by_path = {r["path"]: r["request_id"] for r in t.query_api()}
    assert request_id_kind(by_path["/a"]) == "boot"
    assert by_path["/b"] == "real-123"
    assert request_id_kind(by_path["/c"]) == "orphan"


def test_explicit_request_id_is_untouched():
    _init()
    t = fasten.transport()
    t.push_syslog({"level": "warn", "event": "x", "request_id": "my-own-id"})
    assert t.query_syslog()[0]["request_id"] == "my-own-id"


# No row has an empty request_id

def test_no_stream_row_ever_lacks_request_id():
    """Boot, in-request and context-less rows all have a request_id."""
    _init()
    t = fasten.transport()
    t.push_syslog({"level": "info", "event": "boot.init"})           # boot
    t.push_api({"method": "GET", "path": "/health"})                 # boot
    with with_request_id("op-1"):
        from fasten import current_request_id
        rid = current_request_id()
        t.push_api({"method": "POST", "path": "/x", "request_id": rid})
        t.push_syslog({"level": "error", "event": "boom", "request_id": rid})
    t.push_syslog({"level": "info", "event": "bg.tick"})             # orphan

    rows = t.query_syslog(limit=1000) + t.query_api(limit=1000)
    assert rows, "expected rows"
    assert all(r.get("request_id") for r in rows), \
        "every stream row must carry a non-empty request_id"


def test_boot_rows_are_correlatable():
    """/correlate with a boot id returns the startup rows."""
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    _init()
    t = fasten.transport()
    t.push_syslog({"level": "error", "event": "db.connect.failed"})  # boot
    boot_id = t.query_syslog()[0]["request_id"]
    assert request_id_kind(boot_id) == "boot"

    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    body = TestClient(app).get(f"/api/v1/logs/correlate?request_id={boot_id}").json()
    assert body["counts"]["sys"] == 1
    assert body["sys"][0]["event"] == "db.connect.failed"
