"""Regression: a PostgresStore read must not leave its connection
idle-in-transaction.

Root cause of the audit-store-init deadlock (continuum issue 014): the engine's
startup seed reads — ``max_monotonic_seq()`` then ``query(..., limit=1)`` —
executed a ``SELECT`` but never ``commit()``/``rollback()``, so the thread-local
connection stayed *idle in transaction* holding an ``ACCESS SHARE`` lock on the
audit table. A concurrent store-init ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS``
(which needs ``ACCESS EXCLUSIVE``, even as a no-op) then queued behind that lock
forever, hanging the worker. These tests pin the fix: reads release their
transaction, so they neither sit idle-in-transaction nor block DDL.

Postgres-only; skipped unless FASTEN_TEST_POSTGRES_DSN is set:

    FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test \
        pytest python/tests/test_store_idle_in_tx.py -v
"""
from __future__ import annotations

import os
import uuid

import pytest

DSN = os.getenv("FASTEN_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="FASTEN_TEST_POSTGRES_DSN not set — skipping Postgres tests"
)


def _base_dsn() -> str:
    # DSN without the fasten-specific ?table= param, for a raw probe connection.
    assert DSN is not None  # guarded by pytestmark skipif
    return DSN.split("?", 1)[0]


def _store_on(table: str):
    from fasten.store.postgres import PostgresStore

    assert DSN is not None  # guarded by pytestmark skipif
    sep = "&" if "?" in DSN else "?"
    return PostgresStore.from_dsn(f"{DSN}{sep}table={table}")


def test_seed_reads_do_not_leave_connection_idle_in_transaction():
    import psycopg

    table = f"audit_idletx_{uuid.uuid4().hex}"
    store = _store_on(table)
    try:
        # The two reads engine.start() performs to seed the hash chain.
        store.max_monotonic_seq()
        assert (
            store._tls.conn.info.transaction_status
            == psycopg.pq.TransactionStatus.IDLE
        ), "max_monotonic_seq left the connection idle-in-transaction"

        store.query(limit=1)
        assert (
            store._tls.conn.info.transaction_status
            == psycopg.pq.TransactionStatus.IDLE
        ), "query left the connection idle-in-transaction"
    finally:
        store.close()


def test_read_does_not_block_concurrent_ddl():
    """The real deadlock repro: after a store read, a separate connection's
    ``ALTER TABLE ... ADD COLUMN`` must not block on an ACCESS SHARE lock."""
    import psycopg

    table = f"audit_idletx_{uuid.uuid4().hex}"
    store = _store_on(table)
    try:
        store.max_monotonic_seq()  # seed read — must not hold ACCESS SHARE

        with psycopg.connect(_base_dsn()) as probe:
            with probe.cursor() as cur:
                cur.execute("SET lock_timeout = '3s'")
                # Mirrors Fasten store-init's no-op migration. If the reader still
                # holds ACCESS SHARE, this queues for ACCESS EXCLUSIVE and raises
                # LockNotAvailable after 3s. With the fix it succeeds immediately.
                cur.execute(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS probe_col text"
                )
            probe.commit()
    finally:
        store.close()
