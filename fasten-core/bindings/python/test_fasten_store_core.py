"""
Tests for the Python binding  (fasten-core/bindings/python/fasten_core.py).

Requires libfasten_core to be built:
    cd fasten/fasten-core && cargo build --release --features all

Skip gracefully when the library is absent so CI passes on the Rust-only job.

Run:
    PYTHONPATH=. pytest test_fasten_core.py -v
"""

from __future__ import annotations

import json
import os
import pytest

# ── Library availability guard ────────────────────────────────────────────────

try:
    from fasten_core import FastenStore, FastenStoreError
    _LIB_AVAILABLE = True
except (ImportError, OSError):
    _LIB_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _LIB_AVAILABLE,
    reason="libfasten_core not built — run `cargo build --release --features all`",
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_row(row_id: str, code: str = "TEST") -> dict:
    return {
        "wire_version": "1",
        "id": row_id,
        "origin_id": row_id,
        "monotonic_seq": 1,
        "timestamp": "2026-05-07T00:00:00.000Z",
        "code": code,
        "action": "test",
        "severity": "info",
        "service_id": "test-svc",
        "source_node_id": "node-1",
        "actor": "tester",
        "actor_kind": "user",
        "target": "res-1",
        "category": "test",
        "domain": "test",
        "method": "sdk",
        "request_id": "req-001",
        "detail": {"key": "value"},
    }


@pytest.fixture
def sqlite_store():
    store = FastenStore.open("sqlite", ":memory:", "audit_log")
    yield store
    store.close()


# ── SQLite tests ──────────────────────────────────────────────────────────────

def test_version_is_string():
    assert isinstance(FastenStore.version(), str)
    assert len(FastenStore.version()) > 0


def test_sqlite_open_and_ping(sqlite_store):
    sqlite_store.ping()  # must not raise


def test_sqlite_insert(sqlite_store):
    sqlite_store.insert(make_row("evt-py-sqlite-001"))


def test_sqlite_insert_idempotent(sqlite_store):
    row = make_row("evt-py-idem-001")
    sqlite_store.insert(row)
    sqlite_store.insert(row)  # INSERT OR IGNORE — must not raise


def test_sqlite_insert_json_string(sqlite_store):
    row = make_row("evt-py-json-001")
    sqlite_store.insert_json(json.dumps(row))


def test_sqlite_nullable_columns(sqlite_store):
    row = make_row("evt-py-null-001")
    row["tenant_id"] = "tenant-abc"
    row["shipped_at"] = "2026-05-07T01:00:00.000Z"
    sqlite_store.insert(row)


def test_sqlite_pii_in_detail(sqlite_store):
    row = make_row("evt-py-pii-001")
    row["pii_in_detail"] = True
    sqlite_store.insert(row)


def test_context_manager():
    with FastenStore.open("sqlite", ":memory:", "audit_log") as store:
        store.insert(make_row("evt-py-ctx-001"))
    # store.close() called on __exit__; double-close must not crash
    store.close()


def test_invalid_table_name_raises():
    with pytest.raises(FastenStoreError):
        FastenStore.open("sqlite", ":memory:", "bad-name!")


def test_invalid_backend_raises():
    with pytest.raises(FastenStoreError):
        FastenStore.open("unknown_backend", ":memory:", "audit_log")


# ── PostgreSQL tests (skipped without DSN) ────────────────────────────────────

_PG_DSN = os.environ.get("FASTEN_TEST_POSTGRES_DSN")


@pytest.mark.skipif(not _PG_DSN, reason="FASTEN_TEST_POSTGRES_DSN not set")
def test_postgres_open_and_ping():
    with FastenStore.open("postgres", _PG_DSN, "fasten_py_sc_test") as store:
        store.ping()


@pytest.mark.skipif(not _PG_DSN, reason="FASTEN_TEST_POSTGRES_DSN not set")
def test_postgres_insert_idempotent():
    with FastenStore.open("postgres", _PG_DSN, "fasten_py_sc_test") as store:
        row = make_row("evt-py-pg-001")
        store.insert(row)
        store.insert(row)  # ON CONFLICT (id) DO NOTHING


@pytest.mark.skipif(not _PG_DSN, reason="FASTEN_TEST_POSTGRES_DSN not set")
def test_postgres_schema_qualified():
    with FastenStore.open("postgres", _PG_DSN, "fasten_py_sc_schema.audit_rows") as store:
        store.insert(make_row("evt-py-schema-001"))
