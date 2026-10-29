"""Ingest checks a batch against what the store already holds (spec §4): a
row that disagrees with a stored row is rejected and reported, not ignored."""
import dataclasses
import os
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import seal
from fasten.replication import ingest
from fasten.store.sqlite import SQLiteStore


def _row(seq: int, *, target: str = "u/1", rid: str | None = None,
         node: str = "node-1") -> AuditRow:
    rid = rid or f"evt-{seq}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, seq, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target=target,
        category="account", domain="user", method="sdk",
        request_id=f"req-{seq}", detail={"k": "v"},
    )


def _chain(seqs, *, prev: str = "genesis", **kw) -> list[AuditRow]:
    out = []
    for seq in seqs:
        row = seal(prev, _row(seq, **kw))
        prev = row.hash
        out.append(row)
    return out


def _stored(store):
    return sorted((r.monotonic_seq, r.id, r.target) for r in store.query(limit=100))


def test_redelivering_a_stored_batch_is_a_no_op():
    store, rows = SQLiteStore(":memory:"), _chain([1, 2, 3])
    assert ingest(store, rows).rejected_from_seq is None
    again = ingest(store, rows)
    assert again.rejected_from_seq is None and len(_stored(store)) == 3


def test_a_continuing_batch_is_stored():
    store, rows = SQLiteStore(":memory:"), _chain([1, 2, 3, 4, 5])
    ingest(store, rows[:3])
    assert ingest(store, rows[3:]).rejected_from_seq is None
    assert [s for s, _, _ in _stored(store)] == [1, 2, 3, 4, 5]


def test_a_row_that_differs_from_the_stored_row_with_its_id_is_rejected():
    store = SQLiteStore(":memory:")
    first = _chain([1, 2, 3], target="u/other")      # same ids, other content
    ingest(store, first)
    result = ingest(store, _chain([1, 2, 3]))
    assert result.rejected_from_seq == 1 and result.inserted == 0
    assert "stored row" in result.reason
    assert all(t == "u/other" for _, _, t in _stored(store))


def test_a_new_row_at_a_stored_seq_is_rejected():
    store = SQLiteStore(":memory:")
    ingest(store, _chain([1, 2]))
    other = [seal("genesis", _row(1, rid="evt-x1"))]
    result = ingest(store, other)
    assert result.rejected_from_seq == 1 and len(_stored(store)) == 2


def test_a_new_row_must_link_to_the_stored_row_before_it():
    store = SQLiteStore(":memory:")
    ingest(store, _chain([1, 2]))
    detached = _chain([3, 4], prev="0" * 64)
    result = ingest(store, detached)
    assert result.rejected_from_seq == 3 and len(_stored(store)) == 2


def test_the_stored_row_after_a_new_one_must_link_to_it():
    store, rows = SQLiteStore(":memory:"), _chain([1, 2, 3])
    ingest(store, [rows[0]])
    ingest(store, [rows[2]])                           # seq 2 still missing
    filler = [seal(rows[0].hash, _row(2, target="u/other"))]
    result = ingest(store, filler)
    assert result.rejected_from_seq == 2
    assert ingest(store, [rows[1]]).rejected_from_seq is None   # the real row fits


def test_a_kept_row_is_checked_against_the_stored_row_after_it():
    # Stored 1-4 and 6; the batch's 6 conflicts, so only its 5 can be kept,
    # and that 5 must still link to the stored 6.
    store, rows = SQLiteStore(":memory:"), _chain([1, 2, 3, 4, 5, 6])
    ingest(store, rows[:4])
    ingest(store, [rows[5]])
    other = _chain([5, 6], prev=rows[3].hash, target="u/other")
    other[1] = seal(other[0].hash, _row(6, rid="evt-x6", target="u/other"))
    result = ingest(store, other)
    assert result.rejected_from_seq == 5 and result.inserted == 0
    assert ingest(store, [rows[4]]).rejected_from_seq is None   # the real 5 fits


def test_one_id_on_two_nodes_in_a_batch_is_rejected():
    # id is unique across nodes, so the store could keep only one of them.
    store = SQLiteStore(":memory:")
    rows = _chain([1]) + _chain([1], node="node-2")
    result = ingest(store, rows)
    assert result.rejected_from_seq == 1 and result.inserted == 0
    assert "also in this batch" in result.reason
    assert _stored(store) == []


def test_a_row_after_a_stored_unsealed_row_links_to_genesis():
    store = SQLiteStore(":memory:")
    store.insert_originated(dataclasses.replace(_row(1), hash="", prev_hash=""))
    assert ingest(store, _chain([2], prev="deadbeef")).rejected_from_seq == 2
    result = ingest(store, _chain([2]))
    assert result.rejected_from_seq is None and result.inserted == 1


def _blind_first_check(monkeypatch):
    """Make the first stored-row check miss everything, as when another
    writer stores a row between the check and the insert."""
    from fasten.store import repo
    real, calls = repo.stored_conflict, []

    def blind(prefix, by_id, at_seq):
        calls.append(1)
        return None if len(calls) == 1 else real(prefix, by_id, at_seq)
    monkeypatch.setattr(repo, "stored_conflict", blind)
    return calls


def _stored_elsewhere(store):
    """evt-1 already stored on node-2; the batch carries evt-1 on node-1."""
    ingest(store, _chain([1], node="node-2"))
    return _chain([1, 2])


def test_a_skipped_insert_is_not_reported_as_stored_sqlite(monkeypatch):
    store = SQLiteStore(":memory:")
    rows = _stored_elsewhere(store)
    _blind_first_check(monkeypatch)
    with pytest.raises(Exception, match="evt-1"):
        ingest(store, rows)
    assert [n for n, _, _ in _stored(store)] == [1]


@pytest.mark.skipif(not os.getenv("FASTEN_TEST_POSTGRES_DSN"),
                    reason="FASTEN_TEST_POSTGRES_DSN not set")
def test_a_row_stored_meanwhile_is_checked_again_postgres(monkeypatch):
    import uuid
    from fasten.store.postgres import PostgresStore
    table = f"ingest_{uuid.uuid4().hex[:8]}"
    store = PostgresStore.from_dsn(f"{os.environ['FASTEN_TEST_POSTGRES_DSN']}?table={table}")
    try:
        rows = _stored_elsewhere(store)
        calls = _blind_first_check(monkeypatch)
        result = ingest(store, rows)
        assert len(calls) == 2
        assert result.rejected_from_seq == 1 and result.inserted == 0
        assert len(store.query(limit=10)) == 1
    finally:
        import psycopg
        with psycopg.connect(os.environ["FASTEN_TEST_POSTGRES_DSN"], autocommit=True) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {table}")

