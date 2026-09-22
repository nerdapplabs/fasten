"""P0-9 — store-allocated sequencing (spec §2.1).

monotonic_seq and prev_hash are allocated inside the insert transaction, so N
concurrent writers on one node still produce ONE verifiable chain. These tests
are the regression guard: if allocation ever moves back into engine memory,
`test_concurrent_threads_produce_one_verifiable_chain` fails.
"""
import os
import tempfile
import threading
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import verify_chain
from fasten.store.sqlite import SQLiteStore


def _unsealed(i: int, *, service_id: str = "svc-a", node: str = "node-1") -> AuditRow:
    """A row as emit() now produces it: no seq, no prev_hash, no hash."""
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
    return SQLiteStore(path=os.path.join(tempfile.mkdtemp(), "audit.db"),
                       table="fasten_audit")


def test_allocates_from_one_and_seals(store):
    sealed = store.allocate_and_insert_originated(_unsealed(1))
    assert sealed.monotonic_seq == 1
    assert sealed.prev_hash == "genesis"
    assert sealed.hash


def test_sequence_increments_and_links(store):
    a = store.allocate_and_insert_originated(_unsealed(1))
    b = store.allocate_and_insert_originated(_unsealed(2))
    assert (a.monotonic_seq, b.monotonic_seq) == (1, 2)
    assert b.prev_hash == a.hash
    assert verify_chain(store.query(limit=10)).ok


def test_two_services_share_one_node_sequence(store):
    """THE P0-9 GUARD. Different services on one node must NOT both get seq 1."""
    a = store.allocate_and_insert_originated(_unsealed(1, service_id="svc-a"))
    b = store.allocate_and_insert_originated(_unsealed(1, service_id="svc-b"))
    assert a.monotonic_seq == 1
    assert b.monotonic_seq == 2, "second service restarted the counter"
    assert b.prev_hash == a.hash
    result = verify_chain(store.query(limit=10))
    assert result.ok, result.reason


def test_distinct_nodes_keep_independent_sequences(store):
    a = store.allocate_and_insert_originated(_unsealed(1, node="node-1"))
    b = store.allocate_and_insert_originated(_unsealed(1, node="node-2"))
    assert a.monotonic_seq == b.monotonic_seq == 1
    assert verify_chain(store.query(limit=10)).ok


def test_concurrent_threads_produce_one_verifiable_chain(store):
    """BEGIN IMMEDIATE must serialise allocation.

    Without it this is a read-modify-write race: two writers read the same
    MAX(seq) and both insert at that seq + 1.
    """
    n = 24
    errors: list[BaseException] = []
    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        try:
            barrier.wait()
            store.allocate_and_insert_originated(
                _unsealed(i, service_id=f"svc-{i % 4}"))
        except BaseException as exc:      # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    rows = store.query(limit=200)
    assert len(rows) == n
    seqs = sorted(r.monotonic_seq for r in rows)
    assert seqs == list(range(1, n + 1)), "duplicate or gapped allocation"
    result = verify_chain(rows)
    assert result.ok, result.reason


def test_rejects_foreign_origin(store):
    import dataclasses
    row = dataclasses.replace(_unsealed(1), origin_id="evt-somewhere-else")
    with pytest.raises(ValueError, match="origin_id == id"):
        store.allocate_and_insert_originated(row)


def test_rollback_leaves_no_gap(store):
    """A failed insert must not consume a sequence number."""
    import dataclasses
    store.allocate_and_insert_originated(_unsealed(1))
    bad = dataclasses.replace(_unsealed(2), origin_id="nope")
    with pytest.raises(ValueError):
        store.allocate_and_insert_originated(bad)
    nxt = store.allocate_and_insert_originated(_unsealed(3))
    assert nxt.monotonic_seq == 2
    assert verify_chain(store.query(limit=10)).ok
