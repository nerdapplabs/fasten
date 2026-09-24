"""P0-9 — one node, one chain (spec §2).

`monotonic_seq` is unique within a `source_node_id`. Two engine instances that
allocate independently (spec §2.1 non-conformance) mint duplicate seq values;
`verify_chain` MUST report that rather than tolerate it, because a chain with
two rows at seq 1 is not a chain.

These are regression tests for the class of bug where the allocation grain and
the verification grain disagree. If the allocator is ever moved back in-memory,
`test_duplicate_seq_on_one_node_is_rejected` fails loudly.
"""
import dataclasses
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import seal, verify_chain


def _row(service_id: str, seq: int, *, node: str = "node-1") -> AuditRow:
    return AuditRow(
        id=f"evt-{service_id}-{seq}", origin_id=f"evt-{service_id}-{seq}",
        monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id=service_id, source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target="u/1",
        category="account", domain="user", method="sdk",
        request_id=f"req-{service_id}-{seq}", detail={"k": "v"},
    )


def _chain(*specs, node: str = "node-1") -> list[AuditRow]:
    """Seal (service_id, seq) pairs into ONE node chain, in the order given."""
    out: list[AuditRow] = []
    prev = "genesis"
    for service_id, seq in specs:
        row = seal(prev, _row(service_id, seq, node=node))
        prev = row.hash
        out.append(row)
    return out


# ── the conformant case ───────────────────────────────────────────────────────

def test_two_services_share_one_node_chain():
    """Different services interleave into ONE sequence with unique seq values.

    This is what store-allocated sequencing (spec §2.1) produces.
    """
    rows = _chain(("svc-a", 1), ("svc-b", 2), ("svc-a", 3), ("svc-b", 4))
    result = verify_chain(rows)
    assert result.ok, result.reason
    assert result.total_rows == 4


def test_verification_is_order_independent():
    """Row order out of the store must not matter."""
    rows = _chain(("svc-a", 1), ("svc-b", 2), ("svc-a", 3))
    assert verify_chain(list(reversed(rows))).ok


def test_two_nodes_are_independent_chains():
    """seq is unique per node, so the same seq on two nodes is fine."""
    rows = _chain(("svc-a", 1), ("svc-a", 2), node="node-1") + \
           _chain(("svc-a", 1), ("svc-a", 2), node="node-2")
    assert verify_chain(rows).ok


# ── the regression this file exists for ───────────────────────────────────────

def test_duplicate_seq_on_one_node_is_rejected():
    """THE P0-9 REGRESSION GUARD.

    Two engines allocating in memory both start at seq 1. Before the fix this
    surfaced as a prev_hash break — a false tamper signal. It must now be named
    for what it is: a duplicate allocation.
    """
    a = seal("genesis", _row("svc-a", 1))
    b = seal("genesis", _row("svc-b", 1))   # second engine, also seq 1
    result = verify_chain([a, b])
    assert not result.ok
    assert result.first_break_at == 1
    assert "duplicate monotonic_seq" in (result.reason or "")
    # and it must NOT be misreported as tampering
    assert "prev_hash does not match" not in (result.reason or "")


def test_duplicate_seq_reported_even_when_hashes_are_valid():
    """Both rows individually hash correctly; the duplication is the defect."""
    rows = _chain(("svc-a", 1), ("svc-a", 2)) + [seal("genesis", _row("svc-b", 1))]
    assert not verify_chain(rows).ok


def test_same_row_twice_is_not_a_duplicate():
    """Idempotent re-delivery (spec §4) must not be mistaken for two allocators."""
    row = seal("genesis", _row("svc-a", 1))
    assert verify_chain([row, row]).ok


# ── detection must not have been weakened ─────────────────────────────────────

def test_tampered_row_still_detected():
    rows = _chain(("svc-a", 1), ("svc-a", 2), ("svc-a", 3))
    tampered = [*rows[:2], dataclasses.replace(rows[2], target="u/999")]
    result = verify_chain(tampered)
    assert not result.ok
    assert "evt-svc-a-3" in (result.reason or "")


def test_prev_hash_break_still_detected():
    rows = _chain(("svc-a", 1), ("svc-a", 2))
    orphan = seal("genesis", _row("svc-a", 3))   # prev_hash != rows[1].hash
    result = verify_chain([*rows, orphan])
    assert not result.ok
    assert result.first_break_at == 3


def test_unsealed_rows_skipped_not_duplicated():
    """Empty-hash rows (stdout-only mode, spec §8.1) are skipped, so two of them
    at seq 0 must not trip the duplicate check."""
    a, b = _row("svc-a", 0), _row("svc-b", 0)
    assert a.hash == "" and b.hash == ""
    assert verify_chain([a, b]).ok


def test_empty_and_single():
    assert verify_chain([]).ok
    assert verify_chain(_chain(("svc-a", 1))).ok


def test_two_engines_one_store_produce_one_chain():
    """END-TO-END P0-9 GUARD.

    Two Engines, two services, one node, one store. Before store-allocated
    sequencing both minted seq 1 and verify_chain reported a prev_hash break —
    a false tamper signal. Now they share one sequence and the chain verifies.
    """
    import os, tempfile, time
    from fasten import codes
    from fasten.codes import Severity
    from fasten.engine import Engine
    from fasten.store.sqlite import SQLiteStore

    codes.register("repro", {"REPRO_EVENT": codes.Meta(
        domain="repro", category="demo", action="create",
        severity=list(Severity)[0], description="repro", emitter="repro")})

    db = os.path.join(tempfile.mkdtemp(), "audit.db")

    def _engine(service_id):
        e = Engine()
        e.init(service_id=service_id, node_id="node-1", audit_store=SQLiteStore(db))
        return e

    a, b = _engine("svc-a"), _engine("svc-b")
    a.emit("REPRO_EVENT", target="t1")
    b.emit("REPRO_EVENT", target="t2")
    a.emit("REPRO_EVENT", target="t3")
    for e in (a, b):
        e.flush()
    time.sleep(1)
    assert verify_chain(SQLiteStore(db).query(limit=100)).ok


# ── tenant isolation: empty scope must not widen the query ───────────────────

def test_empty_tenant_id_filters_to_nothing_not_everything():
    """SECURITY REGRESSION: `if tenant_id:` treated "" as no-filter.

    A tenant_scope hook returning "" passed the router's `is None` gate and then
    disabled filtering in the store — a full cross-tenant read with isolation
    nominally enabled.
    """
    import os
    import tempfile
    from fasten.store.sqlite import SQLiteStore

    store = SQLiteStore(path=os.path.join(tempfile.mkdtemp(), "audit.db"),
                        table="fasten_audit")
    for tid in ("tenant-a", "tenant-b"):
        r = _row("svc", 1)
        store.insert_replicated(seal("genesis", dataclasses.replace(
            r, id=f"evt-{tid}", origin_id=f"evt-{tid}", tenant_id=tid)))

    assert len(store.query(limit=10)) == 2
    assert store.query(tenant_id="tenant-a", limit=10)[0].tenant_id == "tenant-a"
    assert store.query(tenant_id="", limit=10) == [], (
        "empty tenant_id returned rows — the filter was dropped"
    )
