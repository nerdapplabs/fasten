"""Regression: a PostgresStore read must not leave its connection in an open
transaction (holding ``ACCESS SHARE``) — neither on success nor on error.

Root cause of the audit-store-init deadlock (continuum issue 014): the engine's
startup seed reads — ``max_monotonic_seq()`` then ``query(..., limit=1)`` —
executed a ``SELECT`` but never ``commit()``/``rollback()``, so the thread-local
connection stayed *idle in transaction* holding an ``ACCESS SHARE`` lock on the
audit table. A concurrent store-init ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS``
(which needs ``ACCESS EXCLUSIVE``, even as a no-op) then queued behind that lock
forever, hanging the worker. A read that *errors* leaves the connection INERROR
with the same lock held (and poisoned for reuse). These tests pin the fix:
reads release their transaction on both paths, so they neither sit
idle-in-transaction nor block DDL.

The Postgres cases are skipped unless FASTEN_TEST_POSTGRES_DSN is set:

    FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test \
        pytest python/tests/test_store_idle_in_tx.py -v

The retry/reconnect unit test needs no database.
"""
from __future__ import annotations

import os
import uuid

import pytest

DSN = os.getenv("FASTEN_TEST_POSTGRES_DSN")
requires_pg = pytest.mark.skipif(
    not DSN, reason="FASTEN_TEST_POSTGRES_DSN not set — skipping Postgres tests"
)


def _base_dsn() -> str:
    # DSN without the fasten-specific ?table= param, for a raw probe connection.
    assert DSN is not None  # guarded by @requires_pg
    return DSN.split("?", 1)[0]


def _store_on(table: str):
    from fasten.store.postgres import PostgresStore

    assert DSN is not None  # guarded by @requires_pg
    sep = "&" if "?" in DSN else "?"
    return PostgresStore.from_dsn(f"{DSN}{sep}table={table}")


def _drop(table: str) -> None:
    import psycopg

    with psycopg.connect(_base_dsn()) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")


@requires_pg
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
        _drop(table)


@requires_pg
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
        _drop(table)


@requires_pg
def test_failed_read_leaves_connection_idle_not_inerror():
    """A read that *errors* (e.g. a bad column during the concurrent-ALTER
    window) must leave the connection IDLE — not INERROR, which keeps the
    transaction open (holding any lock) and poisons the connection for reuse."""
    import psycopg

    table = f"audit_idletx_{uuid.uuid4().hex}"
    store = _store_on(table)
    try:
        def bad(conn):
            with conn.cursor() as cur:
                cur.execute(f"SELECT nonexistent_col FROM {table}")  # UndefinedColumn

        with pytest.raises(psycopg.errors.UndefinedColumn):
            store._execute_with_retry(bad)

        assert (
            store._tls.conn.info.transaction_status
            == psycopg.pq.TransactionStatus.IDLE
        ), "failed read left the connection INERROR (txn open, holding locks)"
        # ...and the connection is reusable, not poisoned.
        assert store.max_monotonic_seq() == 0
    finally:
        store.close()
        _drop(table)


def test_execute_with_retry_reconnects_and_releases_on_stale_connection():
    """No database: a stale-connection error reconnects and retries once, the
    cleanup rollback runs on both the dead and the fresh connection, and a
    failing cleanup rollback on the dead connection does not mask the in-flight
    error the retry depends on."""
    import psycopg

    from fasten.store.postgres import PostgresStore

    ts = psycopg.pq.TransactionStatus

    class FakeConn:
        def __init__(self, status, rollback_raises=False):
            self.status = status
            self.rolled_back = False
            self._rollback_raises = rollback_raises

        @property
        def info(self):
            outer = self

            class _Info:
                @property
                def transaction_status(self):
                    return outer.status

            return _Info()

        def rollback(self):
            self.rolled_back = True
            if self._rollback_raises:
                raise psycopg.OperationalError("rollback on dead connection")

    dead = FakeConn(ts.UNKNOWN, rollback_raises=True)  # poisoned + cleanup itself fails
    fresh = FakeConn(ts.INTRANS)                       # a read leaves a txn open

    store = PostgresStore.__new__(PostgresStore)  # bypass __init__ (no DB connect)
    store._connect = lambda: dead          # type: ignore[method-assign]
    store._connect_fresh = lambda: fresh   # type: ignore[method-assign]

    seen = []

    def fn(conn):
        seen.append(conn)
        if conn is dead:
            raise psycopg.OperationalError("connection closed by server")
        return "ok"

    assert store._execute_with_retry(fn) == "ok"
    assert seen == [dead, fresh]   # retried once on the fresh connection
    assert dead.rolled_back        # cleanup attempted on the dead conn (its failure swallowed)
    assert fresh.rolled_back       # the successful read's open txn was released
