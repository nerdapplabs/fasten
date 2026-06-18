"""#52: ingest_replicated sink + module-level outbox exposure."""
import dataclasses

import pytest

import fasten
from fasten.engine import _row_hash
from fasten.store import AuditChainError, IngestResult
from fasten.store.sqlite import SQLiteStore


def _seal_chain(rows):
    """Re-seal a list of rows into a valid chain (prev_hash links + self hash)."""
    sealed = []
    prev = "genesis"
    for i, r in enumerate(rows):
        r = dataclasses.replace(r, monotonic_seq=i + 1, prev_hash=prev)
        h = _row_hash(r.to_dict())
        r = dataclasses.replace(r, hash=h)
        sealed.append(r)
        prev = h
    return sealed


def _emit_rows(n):
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(n)]
    return rows


# ── store-level ingest_replicated ──────────────────────────────────────────────

def test_ingest_replicated_inserts_valid_chain(initialized):
    rows = _emit_rows(3)
    dest = SQLiteStore(":memory:")
    result = dest.ingest_replicated(rows)
    assert isinstance(result, IngestResult)
    assert result.inserted == 3
    assert dest.count() == 3


def test_ingest_replicated_rejects_broken_chain(initialized):
    rows = _emit_rows(3)
    tampered = dataclasses.replace(rows[1], actor="evil")  # hash now invalid
    chain = [rows[0], tampered, rows[2]]
    dest = SQLiteStore(":memory:")
    with pytest.raises(AuditChainError) as exc:
        dest.ingest_replicated(chain)
    assert exc.value.first_break_at == rows[1].monotonic_seq
    assert dest.count() == 0  # all-or-nothing: nothing inserted


def test_ingest_replicated_is_idempotent(initialized):
    rows = _emit_rows(2)
    dest = SQLiteStore(":memory:")
    dest.ingest_replicated(rows)
    # Re-deliver the same batch — INSERT OR IGNORE makes it a no-op.
    result = dest.ingest_replicated(rows)
    assert result.inserted == 2  # offered both rows again
    assert dest.count() == 2     # but no duplicates stored


def test_ingest_replicated_preserves_origin_id(initialized):
    rows = _emit_rows(1)
    origin = rows[0].origin_id
    dest = SQLiteStore(":memory:")
    dest.ingest_replicated(rows)
    stored = dest.query(limit=10)
    assert stored[0].origin_id == origin
    assert stored[0].hash == rows[0].hash


# ── module-level exposure (default engine's store) ─────────────────────────────

def test_module_level_functions_exist():
    assert callable(fasten.list_unshipped)
    assert callable(fasten.mark_shipped)
    assert callable(fasten.ingest_replicated)


def test_module_list_unshipped_and_mark_shipped(initialized):
    rows = _emit_rows(3)
    unshipped = fasten.list_unshipped(limit=10)
    assert len(unshipped) == 3
    fasten.mark_shipped([rows[0].id, rows[1].id])
    remaining = fasten.list_unshipped(limit=10)
    assert {r.id for r in remaining} == {rows[2].id}


def test_module_ingest_replicated_uses_default_store(initialized):
    src = SQLiteStore(":memory:")
    rows = _seal_chain([
        fasten.emit(code="USER_CREATED", target="x"),
    ])
    # default engine store (mem_store via `initialized`) already has the row;
    # ingest a freshly-sealed standalone chain into it idempotently.
    result = fasten.ingest_replicated(rows)
    assert isinstance(result, IngestResult)
    assert result.inserted == 1


def test_module_outbox_requires_store(monkeypatch):
    """In stdout-only mode (no store) the outbox helpers raise a clear error."""
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc-no-store")
    monkeypatch.setenv("FASTEN_NODE_ID", "node-no-store")
    fasten.init(service_id="svc-no-store", node_id="node-no-store")
    with pytest.raises(RuntimeError, match="requires an audit store"):
        fasten.list_unshipped()
