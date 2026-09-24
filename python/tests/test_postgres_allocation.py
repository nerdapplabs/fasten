"""P0-9 / #12 — Postgres allocation against a REAL server.

This path was written, reviewed and shipped twice without ever executing.
It is the one place a bug of the same shape as the SQLite unsealed-row defect
would not have been caught. Requires FASTEN_TEST_PG_DSN.
"""
import os
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import verify_chain

DSN = os.environ.get("FASTEN_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="set FASTEN_TEST_PG_DSN")


def _row(i: int, *, service_id: str = "svc-a", node: str = "node-1") -> AuditRow:
    return AuditRow(
        id=f"evt-{service_id}-{i}", origin_id=f"evt-{service_id}-{i}",
        monotonic_seq=0,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id=service_id, source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target=f"u/{i}",
        category="account", domain="user", method="sdk",
        request_id=f"req-{i}", detail={"n": i},
    )


@pytest.fixture()
def store():
    from fasten.store.postgres import PostgresStore
    s = PostgresStore.from_dsn(DSN)
    s.purge(before=datetime(2099, 1, 1, tzinfo=timezone.utc), respect_unshipped=False)
    return s


def test_allocates_and_seals(store):
    sealed = store.allocate_and_insert_originated(_row(1))
    assert sealed.monotonic_seq >= 1
    assert sealed.hash and sealed.prev_hash


def test_two_services_share_one_node_sequence(store):
    a = store.allocate_and_insert_originated(_row(1, service_id="svc-a"))
    b = store.allocate_and_insert_originated(_row(1, service_id="svc-b"))
    assert b.monotonic_seq == a.monotonic_seq + 1
    assert b.prev_hash == a.hash


def test_advisory_lock_serialises_concurrent_writers(store):
    """pg_advisory_xact_lock, NOT SELECT ... FOR UPDATE: on an empty table
    there is no tip row to lock, so FOR UPDATE would let every writer through
    to allocate seq 1."""
    import threading
    n, errors = 12, []
    barrier = threading.Barrier(n)
    from fasten.store.postgres import PostgresStore

    def worker(i: int) -> None:
        try:
            s = PostgresStore.from_dsn(DSN)
            barrier.wait(timeout=60)
            s.allocate_and_insert_originated(_row(i, service_id=f"svc-{i % 3}"))
        except BaseException as exc:
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    rows = store.query(limit=100)
    seqs = sorted(r.monotonic_seq for r in rows)
    assert seqs == list(range(1, n + 1)), f"duplicate/gapped: {seqs}"
    assert verify_chain(rows).ok


def test_unsealed_rows_still_occupy_their_sequence(store):
    """Same defect the SQLite backend had: filtering MAX(seq) on hash != ''
    restarts the counter against pre-upgrade rows."""
    import dataclasses
    store._insert_row(dataclasses.replace(_row(99), monotonic_seq=42))
    nxt = store.allocate_and_insert_originated(_row(1))
    assert nxt.monotonic_seq == 43


def test_retry_is_idempotent(store):
    """#12: re-running a committed allocation must return the PERSISTED row,
    not a freshly-sealed one with a burned sequence number."""
    first = store.allocate_and_insert_originated(_row(7))
    again = store.allocate_and_insert_originated(_row(7))
    assert again.monotonic_seq == first.monotonic_seq
    assert again.hash == first.hash
    assert len([r for r in store.query(limit=100) if r.id == first.id]) == 1
