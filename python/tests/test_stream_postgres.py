"""PostgresStreamStore — FR1 Postgres backend for api/sys, parity with SQLite.

The suite is parametrized over both backends. Postgres cases are skipped unless
FASTEN_TEST_POSTGRES_DSN is set:

    FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test pytest
"""
import os
import uuid

import pytest

from fasten.store.stream import StreamStore


def _sqlite():
    return StreamStore(":memory:", table="s_" + uuid.uuid4().hex[:10])


def _postgres():
    dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FASTEN_TEST_POSTGRES_DSN not set — skipping Postgres stream tests")
    from fasten.store.stream_postgres import PostgresStreamStore
    return PostgresStreamStore(dsn=dsn, table="sst_" + uuid.uuid4().hex[:10])


@pytest.fixture(params=["sqlite", "postgres"])
def store(request):
    return _sqlite() if request.param == "sqlite" else _postgres()


def _seed(store):
    store.insert({"level": "error", "event": "db.timeout", "service_id": "svc",
                  "message": "connection reset by peer",
                  "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"})
    store.insert({"level": "info", "event": "ok", "service_id": "svc",
                  "timestamp": "2026-08-01T00:00:01Z", "request_id": "r-2"})


def test_insert_query_newest_first(store):
    _seed(store)
    assert [r["request_id"] for r in store.query()] == ["r-2", "r-1"]  # seq DESC


def test_structured_filter_exact_match(store):
    _seed(store)
    assert {r["request_id"] for r in store.query(level="error")} == {"r-1"}
    assert {r["request_id"] for r in store.query(event="ok")} == {"r-2"}
    assert {r["request_id"] for r in store.query(request_id="r-1")} == {"r-1"}
    assert store.query(level="ERROR") == []  # exact-match, not case-folded


def test_time_window(store):
    _seed(store)
    assert {r["request_id"] for r in store.query(since="2026-08-01T00:00:01Z")} == {"r-2"}


def test_count_matching_and_count(store):
    _seed(store)
    assert store.count() == 2
    assert store.count_matching(level="error") == 1


def test_purge(store):
    _seed(store)
    store.insert({"event": "old", "timestamp": "2026-01-01T00:00:00Z", "request_id": "r-old"})
    assert store.purge(before="2026-06-01T00:00:00Z") == 1
    assert "r-old" not in {r["request_id"] for r in store.query()}


def test_search_case_insensitive_and_escape(store):
    _seed(store)
    store.insert({"event": "100%done", "timestamp": "2026-08-01T00:00:05Z", "request_id": "r-w"})
    store.insert({"event": "100XYZdone", "timestamp": "2026-08-01T00:00:06Z", "request_id": "r-x"})
    hits = store.search(q="RESET BY PEER", since="2026-01-01T00:00:00Z")
    assert {r["request_id"] for r in hits} == {"r-1"}  # case-insensitive
    esc = store.search(q="100%done", since="2026-01-01T00:00:00Z")
    assert {r["request_id"] for r in esc} == {"r-w"}  # literal %, not a wildcard


def test_degraded_flag(store):
    assert store.degraded is False
    store.note_write_failure()
    assert store.degraded is True
