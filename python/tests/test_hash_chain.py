"""P1-23: per-row hash chain — emit, verify, tamper-detect."""
import dataclasses
import hashlib
import json
import re

import fasten
from fasten import verify_chain
from fasten.engine import _row_hash


# ── Basic emission ────────────────────────────────────────────────────────────

def test_emitted_row_has_hash(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert re.match(r"^[0-9a-f]{64}$", row.hash), "hash must be 64 hex chars"


def test_first_row_genesis_prev_hash(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert row.prev_hash == "genesis"


def test_second_row_links_prev(initialized):
    r1 = fasten.emit(code="USER_CREATED", target="u-1")
    r2 = fasten.emit(code="USER_CREATED", target="u-2")
    assert r2.prev_hash == r1.hash


def test_hash_is_deterministic(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-1")
    recomputed = _row_hash(row.to_dict())
    assert recomputed == row.hash


def test_hash_excludes_hash_field(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-1")
    # The hash field must not appear in its own preimage.
    d = {k: v for k, v in row.to_dict().items() if k != "hash"}
    expected = hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(',', ':'), default=str).encode()
    ).hexdigest()
    assert expected == row.hash


# ── verify_chain ──────────────────────────────────────────────────────────────

def test_verify_chain_empty():
    result = verify_chain([])
    assert result.ok is True
    assert result.total_rows == 0


def test_verify_chain_single_row(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-1")
    result = verify_chain([row])
    assert result.ok is True
    assert result.total_rows == 1


def test_verify_chain_multiple_rows(initialized):
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(5)]
    result = verify_chain(rows)
    assert result.ok is True
    assert result.total_rows == 5


def test_verify_chain_detects_hash_tampering(initialized):
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
    tampered = dataclasses.replace(rows[1], actor="evil-override")
    chain = [rows[0], tampered, rows[2]]
    result = verify_chain(chain)
    assert result.ok is False
    assert result.first_break_at == rows[1].monotonic_seq


def test_verify_chain_detects_prev_hash_break(initialized):
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
    # Recompute a valid hash for rows[2] but with a wrong prev_hash (simulates deletion of rows[1])
    patched = dataclasses.replace(rows[2], prev_hash="deadbeef" * 8)
    recomputed = _row_hash(patched.to_dict())
    patched = dataclasses.replace(patched, hash=recomputed)
    result = verify_chain([rows[0], patched])
    assert result.ok is False


def test_verify_chain_rows_out_of_order(initialized):
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(4)]
    # Pass in reverse order — verify_chain sorts by monotonic_seq
    result = verify_chain(list(reversed(rows)))
    assert result.ok is True


def test_verify_chain_skips_empty_hash_rows(initialized, mem_store):
    """Rows without a hash field (pre-upgrade) are silently skipped."""
    row = fasten.emit(code="USER_CREATED", target="u-1")
    # Simulate a legacy row with no hash
    legacy = dataclasses.replace(row, hash="", prev_hash="genesis",
                                  monotonic_seq=row.monotonic_seq - 1,
                                  id="evt-" + "0" * 20,
                                  origin_id="evt-" + "0" * 20)
    result = verify_chain([legacy, row])
    assert result.ok is True  # legacy row skipped; row self-verifies


# ── Store round-trip ──────────────────────────────────────────────────────────

def test_hash_chain_survives_store_roundtrip(initialized, mem_store):
    original = fasten.emit(code="USER_CREATED", target="u-1")
    stored = mem_store.query(request_id=original.request_id)
    assert len(stored) == 1
    assert stored[0].hash == original.hash
    assert stored[0].prev_hash == original.prev_hash


def test_verify_chain_from_store(initialized, mem_store):
    for i in range(4):
        fasten.emit(code="USER_CREATED", target=f"u-{i}")
    rows = mem_store.query(limit=10)
    result = verify_chain(rows)
    assert result.ok is True


# ── Re-init seeds prev_hash correctly ─────────────────────────────────────────

def test_reinit_seeds_prev_hash_from_store(mem_store, monkeypatch):
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc-chain")
    monkeypatch.setenv("FASTEN_NODE_ID", "node-chain")

    # First session: emit 2 rows
    fasten.init(audit_store=mem_store, audit_store_failure_strategy="raise")
    r1 = fasten.emit(code="USER_CREATED", target="u-1")
    r2 = fasten.emit(code="USER_CREATED", target="u-2")

    # Second session: re-init should seed prev_hash from store
    fasten.init(audit_store=mem_store, audit_store_failure_strategy="raise")
    r3 = fasten.emit(code="USER_CREATED", target="u-3")

    assert r3.prev_hash == r2.hash
    result = verify_chain([r1, r2, r3])
    assert result.ok is True
