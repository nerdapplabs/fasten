"""Ingest checks a batch against what the store already holds (spec §4): a
row that disagrees with a stored row is rejected and reported, not ignored."""
from datetime import datetime, timezone

from fasten.attrs import AuditRow
from fasten.chain import seal
from fasten.replication import ingest
from fasten.store.sqlite import SQLiteStore


def _row(seq: int, *, target: str = "u/1", rid: str | None = None) -> AuditRow:
    rid = rid or f"evt-{seq}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, seq, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id="node-1", tenant_id=None,
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
