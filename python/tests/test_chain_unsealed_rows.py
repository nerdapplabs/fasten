"""Unsealed rows in a chain (spec §2): allowed only before a node's first
sealed row, which then links to "genesis"."""
import dataclasses
from datetime import datetime, timezone

from fasten.attrs import AuditRow
from fasten.chain import seal, verify_chain


def _row(seq: int, *, node: str = "node-1") -> AuditRow:
    return AuditRow(
        id=f"evt-{node}-{seq}", origin_id=f"evt-{node}-{seq}", monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target="u/1",
        category="account", domain="user", method="sdk",
        request_id=f"req-{seq}", detail={"k": "v"},
    )


def _chain(seqs, *, node: str = "node-1", prev: str = "genesis") -> list[AuditRow]:
    out = []
    for seq in seqs:
        row = seal(prev, _row(seq, node=node))
        prev = row.hash
        out.append(row)
    return out


def _unsealed(row: AuditRow, **changes) -> AuditRow:
    return dataclasses.replace(row, hash="", **changes)


def test_unsealed_rows_before_the_chain_starts_are_skipped():
    legacy = [_unsealed(_row(1), prev_hash=""), _unsealed(_row(2), prev_hash="")]
    assert verify_chain(legacy + _chain([3, 4])).ok


def test_an_all_unsealed_stream_verifies():
    assert verify_chain([_unsealed(_row(1)), _unsealed(_row(2))]).ok


def test_an_edited_row_with_its_hash_cleared_breaks_the_chain():
    rows = _chain([1, 2, 3])
    rows[1] = _unsealed(rows[1], target="u/2")
    result = verify_chain(rows)
    assert not result.ok and result.first_break_at == 2


def test_clearing_the_last_rows_hash_breaks_the_chain():
    rows = _chain([1, 2, 3])
    rows[2] = _unsealed(rows[2], target="u/2")
    result = verify_chain(rows)
    assert not result.ok and result.first_break_at == 3


def test_clearing_the_hashes_of_leading_rows_breaks_the_chain():
    rows = _chain([1, 2, 3])
    rows[0] = _unsealed(rows[0], target="u/2")
    rows[1] = _unsealed(rows[1])
    result = verify_chain(rows)
    assert not result.ok and result.first_break_at == 3


def test_a_window_that_starts_mid_chain_still_verifies():
    assert verify_chain(_chain([1, 2, 3, 4])[2:]).ok


def test_unsealed_rows_on_another_node_do_not_affect_this_one():
    other = [_unsealed(_row(5, node="node-2"))]
    assert verify_chain(_chain([1, 2]) + other).ok


def test_a_purged_head_with_unsealed_rows_kept_verifies():
    # Retention removed sealed seqs 3-4; unsealed 1-2 survive below the chain.
    legacy = [_unsealed(_row(1), prev_hash=""), _unsealed(_row(2), prev_hash="")]
    assert verify_chain(legacy + _chain([3, 4, 5, 6])[2:]).ok


def test_an_unsealed_row_tied_with_the_first_sealed_seq_breaks_in_any_order():
    sealed = _chain([1, 2])
    tie = _unsealed(dataclasses.replace(_row(1), id="evt-tie"))
    for rows in ([tie] + sealed, sealed + [tie]):
        result = verify_chain(rows)
        assert not result.ok and result.first_break_at == 1


def test_first_break_is_the_lowest_seq_across_nodes():
    a = _chain([1, 2, 3, 4], node="node-a")
    b = _chain([1, 2, 3], node="node-b")
    a[2] = _unsealed(a[2])          # node-a breaks at 3
    b[1] = _unsealed(b[1])          # node-b breaks at 2
    result = verify_chain(a + b)
    assert not result.ok and result.first_break_at == 2


def test_ingest_keeps_the_rows_before_an_unsealed_one():
    from fasten.store.repo import verified_prefix
    rows = _chain([1, 2, 3])
    rows[1] = _unsealed(rows[1])
    prefix, rejected_from, _ = verified_prefix(rows)
    assert [r.monotonic_seq for r in prefix] == [1] and rejected_from == 2


def test_an_edit_below_a_duplicate_seq_is_the_first_break():
    rows = _chain([1, 2, 3, 4])
    rows[1] = dataclasses.replace(rows[1], target="u/2")            # hash mismatch at 2
    rows.append(seal(rows[3].hash, dataclasses.replace(_row(4), id="evt-dup")))
    result = verify_chain(rows)
    assert not result.ok and result.first_break_at == 2


def test_a_duplicate_seq_breaks_and_a_redelivered_row_does_not():
    rows = _chain([1, 2, 3])
    assert verify_chain(rows + [rows[1]]).ok                         # same row again
    dup = seal(rows[0].hash, dataclasses.replace(_row(2), id="evt-dup"))
    result = verify_chain(rows + [dup])
    assert not result.ok and result.first_break_at == 2 and "duplicate" in (result.reason or "")
