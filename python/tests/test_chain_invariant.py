"""Per-(service_id, source_node_id) tamper-chain invariant regression tests.

The tamper chain is per ``(service_id, source_node_id)`` and ``monotonic_seq``
is a per-node counter (see README + attrs.py). Replication must preserve each
origin's sub-chain. These tests pin the three invariants a reviewer found
broken:

  - Fix 1: ``max_monotonic_seq`` must be scoped to the engine's own identity
    so a restart after ingesting a foreign origin's rows does not seed the
    engine's seq from that foreign sub-chain.
  - Fix 2: ``list_unshipped`` must return only rows this engine ORIGINATED,
    not rows it ingested from another origin.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

from fasten import AuditRow, Engine, verify_chain
from fasten.engine import _row_hash
from fasten.store.sqlite import SQLiteStore


# Identity of "this" engine (the hub / aggregator).
HUB_SVC = "hub-svc"
HUB_NODE = "hub-node"

# Identity of a remote origin whose rows replicate up to the hub.
NODE_A_SVC = "node-a-svc"
NODE_A_NODE = "node-a-node"


def _make_remote_chain(n: int, *, service_id: str, source_node_id: str) -> list:
    """Build a valid n-row tamper chain as if emitted by a remote origin.

    Each row carries the remote origin's (service_id, source_node_id) and a
    per-node monotonic_seq 1..n, sealed into a linked hash chain.
    """
    rows: list = []
    prev = "genesis"
    for i in range(n):
        row = AuditRow(
            id=f"evt-A{i:018d}",
            origin_id=f"evt-A{i:018d}",
            monotonic_seq=i + 1,
            timestamp=datetime.now(timezone.utc),
            code="USER_CREATED", action="create", severity="info",
            service_id=service_id, source_node_id=source_node_id, tenant_id=None,
            actor="system", actor_kind="service", target=f"u-{i}",
            category="account", domain="user",
            method="sdk", request_id=f"req-A-{i}", detail={},
            prev_hash=prev,
        )
        h = _row_hash(row.to_dict())
        row = dataclasses.replace(row, hash=h)
        rows.append(row)
        prev = h
    return rows


# ── Fix 1: restart seeds seq from the engine's OWN sub-chain ──────────────────


def test_fix1_restart_seeds_seq_scoped_to_own_identity():
    """Regression for unscoped max_monotonic_seq.

    Hub emits its own row (seq=1), ingests 100 rows from node A (seq 1..100),
    restarts (re-seeding seq from max_monotonic_seq of the HUB identity), then
    emits again. The hub's new row must be seq=2 (continuing the hub's own
    sub-chain), NOT seq=101 (which would happen if seq were seeded from the
    global MAX, which node A's rows dominate). The hub's own sub-chain must
    verify intact across the restart.
    """
    store = SQLiteStore(":memory:")

    # Session 1: hub emits one originated row.
    hub = Engine()
    hub.init(
        service_id=HUB_SVC, node_id=HUB_NODE,
        audit_store=store, audit_store_failure_strategy="raise",
    )
    r1 = hub.emit(code="USER_CREATED", target="hub-1")
    assert r1.monotonic_seq == 1

    # Hub ingests 100 rows from node A — seq 1..100 on node A's sub-chain.
    node_a_rows = _make_remote_chain(100, service_id=NODE_A_SVC, source_node_id=NODE_A_NODE)
    result = store.ingest_replicated(node_a_rows)
    assert result.inserted == 100

    # Sanity: global MAX is now 100 (node A dominates), but the hub's own
    # sub-chain max is still 1.
    assert store.max_monotonic_seq() == 100
    assert store.max_monotonic_seq(service_id=HUB_SVC, source_node_id=HUB_NODE) == 1

    # Session 2: simulate restart — a fresh Engine re-seeds seq from the store.
    hub2 = Engine()
    hub2.init(
        service_id=HUB_SVC, node_id=HUB_NODE,
        audit_store=store, audit_store_failure_strategy="raise",
    )
    r2 = hub2.emit(code="USER_CREATED", target="hub-2")

    # The load-bearing assertion: hub's next row is seq=2, not seq=101.
    assert r2.monotonic_seq == 2, (
        f"hub's own per-node counter must continue at 2 after restart, "
        f"got {r2.monotonic_seq} (unscoped seed leak from node A's sub-chain)"
    )
    assert r2.prev_hash == r1.hash, "hub sub-chain prev_hash link must continue"

    # The hub's own (service_id, source_node_id) sub-chain verifies intact.
    hub_rows = [
        row for row in store.query(limit=1000)
        if row.service_id == HUB_SVC and row.source_node_id == HUB_NODE
    ]
    assert {row.monotonic_seq for row in hub_rows} == {1, 2}
    assert verify_chain(hub_rows).ok is True


# ── Fix 2: list_unshipped returns only originated rows ────────────────────────


def test_fix2_list_unshipped_returns_only_originated_rows():
    """Regression for cross-origin bleed in list_unshipped.

    The hub emits 2 of its own rows and ingests 3 from node A. list_unshipped()
    for the hub must return ONLY the hub's 2 originated rows — node A's rows are
    replicated, already shipped from A's perspective, and must not be re-shipped
    upstream by the hub.
    """
    store = SQLiteStore(":memory:")
    hub = Engine()
    hub.init(
        service_id=HUB_SVC, node_id=HUB_NODE,
        audit_store=store, audit_store_failure_strategy="raise",
    )

    own1 = hub.emit(code="USER_CREATED", target="hub-1")
    own2 = hub.emit(code="USER_CREATED", target="hub-2")

    node_a_rows = _make_remote_chain(3, service_id=NODE_A_SVC, source_node_id=NODE_A_NODE)
    store.ingest_replicated(node_a_rows)

    unshipped = hub.list_unshipped(limit=100)
    assert {row.id for row in unshipped} == {own1.id, own2.id}, (
        "list_unshipped must return only the hub's originated rows, not the "
        "rows it ingested from node A"
    )
    # Every returned row is originated (origin_id == id) and belongs to the hub.
    for row in unshipped:
        assert row.origin_id == row.id
        assert row.source_node_id == HUB_NODE
