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


def test_unsealed_rows_still_occupy_their_sequence(store):
    """REGRESSION: allocation must count UNSEALED rows too.

    A pre-upgrade row, or one written in stdout-only mode (spec §8.1), has
    hash="". It still occupies its monotonic_seq. An allocator that filters on
    `hash != ''` when computing MAX(seq) restarts the counter at 1 and mints
    duplicates against those rows — silently, until verify_chain reports a
    duplicate allocation.

    seq spans ALL rows on the node; prev_hash chains only from sealed ones.
    """
    import dataclasses
    unsealed = dataclasses.replace(_unsealed(99), monotonic_seq=42)
    assert unsealed.hash == ""
    store._insert_row(unsealed)                       # bypass sealing entirely

    nxt = store.allocate_and_insert_originated(_unsealed(1))
    assert nxt.monotonic_seq == 43, (
        f"allocated seq {nxt.monotonic_seq} against an existing unsealed row at "
        "42 — the counter restarted"
    )
    # No sealed predecessor exists, so this row legitimately starts the chain.
    assert nxt.prev_hash == "genesis"
    assert verify_chain([r for r in store.query(limit=10) if r.hash]).ok


def test_prev_hash_skips_unsealed_tip(store):
    """prev_hash must chain from the last SEALED row, not the last row."""
    import dataclasses
    first = store.allocate_and_insert_originated(_unsealed(1))
    store._insert_row(dataclasses.replace(_unsealed(98), monotonic_seq=500))
    third = store.allocate_and_insert_originated(_unsealed(2))
    assert third.monotonic_seq == 501, "seq ignored the unsealed row"
    assert third.prev_hash == first.hash, "chained from an unsealed row"
