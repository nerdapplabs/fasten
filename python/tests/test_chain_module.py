"""Items 6, 7, 10: chain module + public seal(), canonical_form_id dispatch,
and Engine-decoupled replication.ingest."""
import dataclasses

import fasten
from fasten import seal, verify_chain
from fasten.attrs import AuditRow
from fasten.chain import CURRENT_CANONICAL_FORM_ID
from fasten.store.sqlite import SQLiteStore


def _bare_row(seq: int = 1) -> AuditRow:
    from datetime import datetime, timezone
    return AuditRow(
        id="evt-1", origin_id="evt-1", monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id="node", tenant_id=None,
        actor="a", actor_kind="user", target="u/1",
        category="account", domain="user", method="sdk", request_id="req-1",
        detail={"k": "v"},
    )


# ── item 7: public seal() round-trip ───────────────────────────────────────────

def test_seal_round_trip_verifies():
    """A seal()-sealed row verifies under verify_chain."""
    row = seal("genesis", _bare_row())
    assert row.hash  # sealed
    assert row.prev_hash == "genesis"
    assert row.canonical_form_id == CURRENT_CANONICAL_FORM_ID
    result = verify_chain([row])
    assert result.ok is True


def test_seal_two_row_chain_verifies():
    r1 = seal("genesis", _bare_row(seq=1))
    r2 = seal(r1.hash, dataclasses.replace(_bare_row(seq=2), id="evt-2", origin_id="evt-2"))
    assert verify_chain([r1, r2]).ok is True


def test_seal_is_public_surface():
    assert fasten.seal is seal


# ── item 6: canonical_form_id dispatch ─────────────────────────────────────────

def test_emit_stamps_canonical_form_id(initialized):
    row = fasten.emit(code="USER_CREATED", target="u/9")
    assert row.canonical_form_id == "1"
    assert verify_chain([row]).ok is True


def test_unknown_canonical_form_id_is_rejected():
    """A row carrying an unknown canonical_form_id must REJECT, naming the id."""
    row = seal("genesis", _bare_row())
    # Forge an unknown form id WITHOUT recomputing the hash — verify_chain must
    # reject on the unknown id, not merely on a hash mismatch.
    forged = dataclasses.replace(row, canonical_form_id="99")
    result = verify_chain([forged])
    assert result.ok is False
    assert result.first_break_at == forged.monotonic_seq
    assert '"99"' in (result.reason or "")
    assert "unknown canonical_form_id" in (result.reason or "")


def test_canonical_form_id_round_trips_through_store(initialized, mem_store):
    fasten.emit(code="USER_CREATED", target="u/1")
    rows = mem_store.query(limit=10)
    assert rows
    assert all(r.canonical_form_id == "1" for r in rows)


# ── item 10: replication.ingest decoupled from the Engine ──────────────────────

def test_replication_ingest_without_init():
    """fasten.replication.ingest works on a fresh store with NO fasten.init()."""
    # Hand-seal a standalone chain — no Engine, no init().
    rows = []
    prev = "genesis"
    for i in range(3):
        r = seal(prev, dataclasses.replace(
            _bare_row(seq=i + 1), id=f"evt-{i}", origin_id=f"evt-{i}"))
        rows.append(r)
        prev = r.hash

    dest = SQLiteStore(":memory:")
    result = fasten.replication.ingest(dest, rows)
    assert result.inserted == 3
    assert result.rejected_from_seq is None
    assert dest.count() == 3


def test_replication_ingest_rejects_on_break_without_init():
    rows = []
    prev = "genesis"
    for i in range(3):
        r = seal(prev, dataclasses.replace(
            _bare_row(seq=i + 1), id=f"evt-{i}", origin_id=f"evt-{i}"))
        rows.append(r)
        prev = r.hash
    tampered = dataclasses.replace(rows[1], actor="evil")  # breaks self-hash
    chain = [rows[0], tampered, rows[2]]

    dest = SQLiteStore(":memory:")
    result = fasten.replication.ingest(dest, chain)  # must NOT raise
    assert result.inserted == 1
    assert result.rejected_from_seq == rows[1].monotonic_seq
    assert dest.count() == 1


def test_replication_module_is_exposed():
    assert callable(fasten.replication.ingest)
