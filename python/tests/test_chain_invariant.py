"""Chain invariants when a store holds both originated and replicated rows.

``monotonic_seq`` is a per-node counter (spec §2.1) and replication keeps each
origin's sub-chain as it was. These tests check that:

  - after a restart the engine continues its own sequence, not one seeded
    from rows it ingested from another origin;
  - ``list_unshipped`` returns only rows this engine originated.
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


# Restart continues the engine's own sub-chain


def test_restart_seeds_seq_scoped_to_own_identity():
    """Hub emits its own row (seq=1), ingests 100 rows from node A (seq 1..100),
    restarts, then emits again. The hub's new row must be seq=2, continuing its
    own sub-chain, not seq=101 from the global MAX. The hub's sub-chain must
    verify across the restart.
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

    # Hub ingests 100 rows from node A, seq 1..100 on node A's sub-chain.
    node_a_rows = _make_remote_chain(100, service_id=NODE_A_SVC, source_node_id=NODE_A_NODE)
    result = store.ingest_replicated(node_a_rows)
    assert result.inserted == 100

    # Sanity: global MAX is now 100 (node A dominates), but the hub's own
    # sub-chain max is still 1.
    assert store.max_monotonic_seq() == 100
    assert store.max_monotonic_seq(service_id=HUB_SVC, source_node_id=HUB_NODE) == 1

    # Session 2: restart with a fresh Engine on the same store.
    hub2 = Engine()
    hub2.init(
        service_id=HUB_SVC, node_id=HUB_NODE,
        audit_store=store, audit_store_failure_strategy="raise",
    )
    r2 = hub2.emit(code="USER_CREATED", target="hub-2")

    assert r2.monotonic_seq == 2, (
        f"hub's own per-node counter must continue at 2 after restart, "
        f"got {r2.monotonic_seq} (seeded from node A's sub-chain)"
    )
    assert r2.prev_hash == r1.hash, "hub sub-chain prev_hash link must continue"

    # The hub's own (service_id, source_node_id) sub-chain verifies intact.
    hub_rows = [
        row for row in store.query(limit=1000)
        if row.service_id == HUB_SVC and row.source_node_id == HUB_NODE
    ]
    assert {row.monotonic_seq for row in hub_rows} == {1, 2}
    assert verify_chain(hub_rows).ok is True


# list_unshipped returns only originated rows


def test_list_unshipped_returns_only_originated_rows():
    """The hub emits 2 of its own rows and ingests 3 from node A. list_unshipped()
    must return only the hub's 2 originated rows. Node A already shipped its
    own rows, so the hub must not ship them again.
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
