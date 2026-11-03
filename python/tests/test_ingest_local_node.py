"""Ingest refuses rows whose source_node_id is the receiving node: a node's
own rows come from its emit path, never from replication."""
import dataclasses
import os
import uuid
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import seal
from fasten.replication import ingest
from fasten.store import IngestResult
from fasten.store.sqlite import SQLiteStore


def _row(seq: int, node: str) -> AuditRow:
    rid = f"{node}-{seq}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, seq, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target="u/1",
        category="account", domain="user", method="sdk",
        request_id=f"req-{seq}", detail={"k": "v"},
    )


def _chain(seqs, node: str, prev: str = "genesis") -> list[AuditRow]:
    out = []
    for seq in seqs:
        row = seal(prev, _row(seq, node))
        prev = row.hash
        out.append(row)
    return out


def _ids(store) -> list[str]:
    return sorted(r.id for r in store.query(limit=100))


def test_rows_continuing_the_local_chain_are_refused():
    store = SQLiteStore(":memory:")
    own = _chain([1, 2, 3, 4], "agg")
    ingest(store, own[:2])                       # the aggregator's own rows
    result = ingest(store, own[2:], local_node_id="agg")
    assert result.rejected_from_seq == 3 and result.inserted == 0
    assert "is this node" in result.reason
    assert _ids(store) == ["agg-1", "agg-2"]


def test_a_mixed_batch_is_cut_at_the_first_local_row():
    store = SQLiteStore(":memory:")
    rows = _chain([1, 2, 3], "node-1") + _chain([2], "agg")
    result = ingest(store, rows, local_node_id="agg")
    assert result.rejected_from_seq == 2 and result.inserted == 1
    assert _ids(store) == ["node-1-1"]


def test_an_earlier_break_is_still_reported():
    store = SQLiteStore(":memory:")
    broken = _chain([1, 2], "node-1")
    broken[1] = dataclasses.replace(broken[1], target="u/edited")
    result = ingest(store, broken + _chain([3], "agg"), local_node_id="agg")
    assert result.rejected_from_seq == 2 and result.inserted == 1
    assert "is this node" not in result.reason


def test_other_nodes_are_unaffected():
    store = SQLiteStore(":memory:")
    result = ingest(store, _chain([1, 2], "node-1"), local_node_id="agg")
    assert result.rejected_from_seq is None and result.inserted == 2


def test_the_store_method_takes_the_local_node():
    store = SQLiteStore(":memory:")
    result = store.ingest_replicated(_chain([1], "agg"), local_node_id="agg")
    assert result.rejected_from_seq == 1 and _ids(store) == []


class _OldStore:
    """An adopter store whose ingest_replicated predates local_node_id."""

    def __init__(self):
        self.inner = SQLiteStore(":memory:")

    def ingest_replicated(self, rows):
        return self.inner.ingest_replicated(rows)


def test_a_store_without_the_argument_is_still_checked():
    store = _OldStore()
    result = ingest(store, _chain([1, 2], "node-1") + _chain([1], "agg"),
                    local_node_id="agg")
    assert result.rejected_from_seq == 1 and _ids(store.inner) == []


class _InsertOnlyStore:
    """A store with no ingest_replicated: ingest inserts row by row."""

    def __init__(self):
        self.rows: list[AuditRow] = []

    def insert(self, row):
        self.rows.append(row)


def test_the_row_by_row_fallback_is_checked():
    store = _InsertOnlyStore()
    result = ingest(store, _chain([1], "node-1") + _chain([2], "agg"),
                    local_node_id="agg")
    assert result.rejected_from_seq == 2
    assert [r.id for r in store.rows] == ["node-1-1"]


def test_the_engine_refuses_its_own_node(initialized):
    result = initialized.ingest_replicated(
        _chain([1], "node-1") + _chain([1], "test-node"))
    assert isinstance(result, IngestResult)
    assert result.rejected_from_seq == 1 and result.inserted == 0


def test_the_engine_ingests_other_nodes(initialized):
    result = initialized.ingest_replicated(_chain([1, 2], "node-1"))
    assert result.rejected_from_seq is None and result.inserted == 2


@pytest.mark.skipif(not os.getenv("FASTEN_TEST_POSTGRES_DSN"),
                    reason="FASTEN_TEST_POSTGRES_DSN not set")
def test_rows_continuing_the_local_chain_are_refused_postgres():
    from fasten.store.postgres import PostgresStore
    table = f"ingest_{uuid.uuid4().hex[:8]}"
    store = PostgresStore.from_dsn(f"{os.environ['FASTEN_TEST_POSTGRES_DSN']}?table={table}")
    try:
        own = _chain([1, 2, 3], "agg")
        ingest(store, own[:2])
        result = store.ingest_replicated(own[2:], local_node_id="agg")
        assert result.rejected_from_seq == 3 and result.inserted == 0
        assert _ids(store) == ["agg-1", "agg-2"]
    finally:
        import psycopg
        with psycopg.connect(os.environ["FASTEN_TEST_POSTGRES_DSN"], autocommit=True) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
