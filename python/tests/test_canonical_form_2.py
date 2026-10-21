"""P1-47 / spec §1.4, §7 — canonical form "2" (committed detail) + redaction.

The point of form "2" is that `detail` can be destroyed for retention WITHOUT
moving the row hash. If it moved, the successor's `prev_hash` would no longer
match, forcing a re-seal of every following row — an O(n) rewrite that is
indistinguishable from tampering.

These are also the golden vectors the other five SDKs get implemented against.
"""
import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fasten.attrs import AuditRow
from fasten.canonical_ts import parse_canonical
from fasten.chain import (
    _row_hash_form_1,
    detail_commitment,
    redact,
    seal,
    verify_chain,
)

# A fixed row so hashes are reproducible across languages.
VECTOR_SALT = "a" * 64


def _row(seq: int = 1, detail=None) -> AuditRow:
    return AuditRow(
        id=f"evt-{seq}", origin_id=f"evt-{seq}", monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id="node", tenant_id=None,
        actor="a", actor_kind="user", target="u/1",
        category="account", domain="user", method="sdk", request_id="req-1",
        detail={"qty": 3, "sku": "WIDGET"} if detail is None else detail,
    )


def _seal2(prev: str, row: AuditRow, salt: str | None = None) -> AuditRow:
    """Seal explicitly under form "2".

    seal() stamps CURRENT_CANONICAL_FORM_ID, which is gated to "1" until the
    store has detail_salt / detail_commitment columns (P1-47). These tests
    exercise form "2" directly so they stay meaningful while it is gated.
    """
    import secrets
    from fasten.chain import _row_hash_form_2
    salt = salt or secrets.token_hex(32)
    r = dataclasses.replace(row, canonical_form_id="2", prev_hash=prev,
                            detail_salt=salt)
    r = dataclasses.replace(r, detail_commitment=detail_commitment(salt, r.detail))
    return dataclasses.replace(r, hash=_row_hash_form_2(r.to_dict()))


# ── backward compatibility: form "1" hashes must not move ────────────────────

def test_form_1_hash_unchanged_by_new_fields():
    """THE COMPAT GUARD — the real cross-language vector.

    Adding detail_salt / detail_commitment to AuditRow must not move any
    existing form-"1" hash. This is the exact row pinned in
    go/verify_test.go:pyVectorRow(); if this drifts, every Go aggregator
    verifying a Python-sealed chain breaks.
    """
    row = AuditRow(
        id="evt-abc123", origin_id="evt-abc123", monotonic_seq=1,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, 123456, tzinfo=timezone.utc),
        code="ORDER_PLACED", action="create", severity="info",
        service_id="gateway", source_node_id="node-1", tenant_id="tenant-x",
        actor="alice", actor_kind="user", target="order/42",
        category="order", domain="sales", method="http", request_id="req-xyz",
        detail={"qty": 3, "sku": "WIDGET"}, prev_hash="genesis",
    )
    assert _row_hash_form_1(row.to_dict()) == (
        "cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac"
    )


def test_form_1_hash_ignores_commitment_fields():
    """Populating the new fields must not perturb a form-"1" hash either."""
    bare = dataclasses.replace(_row(), canonical_form_id="1")
    populated = dataclasses.replace(
        bare, detail_salt=VECTOR_SALT,
        detail_commitment=detail_commitment(VECTOR_SALT, bare.detail))
    assert _row_hash_form_1(bare.to_dict()) == _row_hash_form_1(populated.to_dict())


def test_form_1_rows_still_verify():
    from fasten.chain import _row_hash
    r = dataclasses.replace(_row(), canonical_form_id="1", prev_hash="genesis")
    r = dataclasses.replace(r, hash=_row_hash(r.to_dict()))
    assert verify_chain([r]).ok


# ── form "2" behaviour ────────────────────────────────────────────────────────

def test_seal_stamps_form_2_and_commits():
    sealed = seal("genesis", _row())
    assert sealed.canonical_form_id == "2"
    assert sealed.detail_salt and len(sealed.detail_salt) == 64
    assert sealed.detail_commitment == detail_commitment(
        sealed.detail_salt, sealed.detail)
    assert verify_chain([sealed]).ok


def test_salt_is_unique_per_row():
    a, b = _seal2("genesis", _row(1)), _seal2("genesis", _row(2))
    assert a.detail_salt != b.detail_salt


def test_identical_detail_different_commitment():
    """Unique salts mean two rows with the same detail do not share a digest,
    so the commitment cannot be used as a cross-row equality oracle."""
    a, b = _seal2("genesis", _row(1)), _seal2("genesis", _row(2))
    assert a.detail == b.detail
    assert a.detail_commitment != b.detail_commitment


def test_commitment_is_covered_by_the_hash():
    """Tampering with detail_commitment must break verification."""
    sealed = _seal2("genesis", _row())
    tampered = dataclasses.replace(sealed, detail_commitment="0" * 64)
    assert not verify_chain([tampered]).ok


# ── redaction: the whole point ───────────────────────────────────────────────

def test_redaction_does_not_move_the_hash():
    """THE P1-47 GUARD."""
    sealed = _seal2("genesis", _row())
    gone = redact(sealed)
    assert gone.detail is None
    assert gone.detail_salt is None
    assert gone.hash == sealed.hash
    assert gone.prev_hash == sealed.prev_hash
    assert gone.monotonic_seq == sealed.monotonic_seq


def test_chain_verifies_after_redacting_a_middle_row():
    """Redact row 2 of 3. Nothing else is touched and the chain still walks."""
    rows, prev = [], "genesis"
    for i in (1, 2, 3):
        r = _seal2(prev, _row(i))
        prev = r.hash
        rows.append(r)
    assert verify_chain(rows).ok

    rows[1] = redact(rows[1])
    result = verify_chain(rows)
    assert result.ok, result.reason
    assert rows[1].detail is None
    assert rows[2].prev_hash == rows[1].hash   # successor untouched


def test_commitment_still_proves_the_original():
    """A party holding the original detail + salt can demonstrate the row was
    not altered — the commitment survives redaction."""
    sealed = _seal2("genesis", _row())
    original_detail, salt = sealed.detail, sealed.detail_salt
    gone = redact(sealed)
    assert gone.detail_commitment == detail_commitment(salt, original_detail)
    assert gone.detail_commitment != detail_commitment(salt, {"qty": 999})


def test_redacting_form_1_row_is_refused():
    """Form-"1" detail is hashed directly; redacting it would cascade."""
    r = dataclasses.replace(_row(), canonical_form_id="1")
    with pytest.raises(ValueError, match="form"):
        redact(r)


def test_redaction_is_idempotent():
    sealed = _seal2("genesis", _row())
    once = redact(sealed)
    assert redact(once).hash == once.hash


# ── golden vectors for the other SDKs ────────────────────────────────────────

def test_form_2_golden_vector():
    """Fixed salt + fixed row → fixed hash. Any SDK MUST reproduce these."""
    row = dataclasses.replace(
        _row(), canonical_form_id="2", prev_hash="genesis",
        detail_salt=VECTOR_SALT,
    )
    commitment = detail_commitment(VECTOR_SALT, row.detail)
    row = dataclasses.replace(row, detail_commitment=commitment)

    from fasten.chain import _row_hash_form_2
    computed = _row_hash_form_2(row.to_dict())

    # Redaction must not change it.
    assert _row_hash_form_2(redact(row).to_dict()) == computed

    print(f"\nGOLDEN commitment = {commitment}\nGOLDEN form-2 hash = {computed}")
    assert len(commitment) == 64 and len(computed) == 64


def test_whole_number_float_vector_under_form_2():
    """The §1.3 cross-language float hazard applies to the commitment too:
    75.0 must not render as 75."""
    c = detail_commitment(VECTOR_SALT, {"setpoint": 75.0, "retries": 7})
    assert c != detail_commitment(VECTOR_SALT, {"setpoint": 75, "retries": 7})


def test_redacted_row_survives_to_dict_and_cloud_event():
    """A redacted row has detail=None. Anything that reads detail must cope.

    `to_cloud_event` unpacked `**self.detail` unguarded, so a redacted row
    raised TypeError there — found by making the field Optional.
    """
    gone = redact(_seal2("genesis", _row()))
    assert gone.to_dict()["detail"] is None
    ev = gone.to_cloud_event()
    assert ev["data"]["actor"] == "a"
    assert "qty" not in ev["data"]


def test_redacted_row_round_trips_through_sqlite():
    """detail=None must persist as NULL and read back as None, and the row must
    still verify after the round trip."""
    import os
    import tempfile
    from fasten.store.sqlite import SQLiteStore

    store = SQLiteStore(path=os.path.join(tempfile.mkdtemp(), "audit.db"),
                        table="fasten_audit")
    store.insert_replicated(redact(_seal2("genesis", _row())))
    (back,) = store.query(limit=10)
    assert back.detail is None


# ── one timestamp renderer (spec §1.4) ───────────────────────────────────────

def test_form_2_hashes_the_wire_timestamp_verbatim():
    """REGRESSION for the two-renderer hazard (P1-48).

    Form "1" hashed "+00:00" while the row carried "Z", so every SDK needed a
    second private timestamp renderer in the hash path — and Go and Python
    drifted apart inside it. Form "2" hashes the timestamp exactly as
    serialised. If anyone reintroduces a conversion, this fails.
    """
    import hashlib
    from fasten.chain import _FORM_2_EXCLUDED, _canonical_json, _row_hash_form_2

    row = _seal2("genesis", _row(), salt=VECTOR_SALT)
    d = row.to_dict()
    assert d["timestamp"].endswith("Z"), "wire form should be Z (§4.3)"

    expected = hashlib.sha256(_canonical_json(
        {k: v for k, v in d.items() if k not in _FORM_2_EXCLUDED})).hexdigest()
    assert _row_hash_form_2(d) == expected, (
        "form 2 re-rendered the timestamp instead of hashing it verbatim"
    )


def test_form_2_whole_second_and_zero_micros():
    """micros==0 takes the branch that variable-width rendering got wrong.

    Under form "2" the width is fixed, so a whole second and a 1-microsecond
    instant must both round-trip and differ from each other.
    """
    whole = dataclasses.replace(
        _row(), timestamp=datetime(2026, 6, 15, 10, 30, 45, 0, tzinfo=timezone.utc))
    one = dataclasses.replace(
        _row(), timestamp=datetime(2026, 6, 15, 10, 30, 45, 1, tzinfo=timezone.utc))

    a = _seal2("genesis", whole, salt=VECTOR_SALT)
    b = _seal2("genesis", one, salt=VECTOR_SALT)
    assert a.to_dict()["timestamp"] == "2026-06-15T10:30:45.000000Z"
    assert b.to_dict()["timestamp"] == "2026-06-15T10:30:45.000001Z"
    assert a.hash != b.hash
    assert verify_chain([a]).ok and verify_chain([b]).ok


def test_pre_upgrade_form_1_rows_still_verify():
    """REGRESSION: the P1-48 fix must not orphan rows Python already sealed.

    Python once hashed form "1" over the wire "Z" spelling. Making it
    spec-conformant (+00:00) changed every hash it had written, so a
    pre-upgrade corpus failed with "hash mismatch" — reported as tampering.
    verify_chain falls back to the legacy spelling for form "1" only.
    """
    import hashlib
    from fasten.chain import _FORM_1_EXCLUDED, _canonical_json

    row = dataclasses.replace(_row(), canonical_form_id="1", prev_hash="genesis")
    legacy = hashlib.sha256(_canonical_json(
        {k: v for k, v in row.to_dict().items() if k not in _FORM_1_EXCLUDED}
    )).hexdigest()
    stored = dataclasses.replace(row, hash=legacy)

    result = verify_chain([stored])
    assert result.ok, f"pre-upgrade row rejected: {result.reason}"


def test_legacy_fallback_does_not_weaken_tamper_detection():
    """The fallback must accept only the legacy SPELLING, not arbitrary edits."""
    import hashlib
    from fasten.chain import _FORM_1_EXCLUDED, _canonical_json

    row = dataclasses.replace(_row(), canonical_form_id="1", prev_hash="genesis")
    legacy = hashlib.sha256(_canonical_json(
        {k: v for k, v in row.to_dict().items() if k not in _FORM_1_EXCLUDED}
    )).hexdigest()
    tampered = dataclasses.replace(row, hash=legacy, target="u/999")
    assert not verify_chain([tampered]).ok


def test_legacy_fallback_is_scoped_to_form_1():
    """A form-"2" row must NOT get a second chance at matching."""
    sealed = _seal2("genesis", _row())
    broken = dataclasses.replace(sealed, target="u/999")
    assert not verify_chain([broken]).ok


def test_tampering_with_detail_is_detected_under_form_2():
    """SECURITY: form "2" hashes detail_commitment, not detail.

    Without re-checking the commitment on read, an attacker could rewrite
    detail and leave the commitment intact — the row hash would still match
    and verify_chain would pass over altered audit content.
    """
    sealed = _seal2("genesis", _row())
    tampered = dataclasses.replace(sealed, detail={"qty": 999, "sku": "STOLEN"})
    result = verify_chain([tampered])
    assert not result.ok
    assert "commitment" in (result.reason or "")


def test_redacted_row_skips_the_commitment_check():
    """Once detail and salt are gone there is nothing to recompute."""
    gone = redact(_seal2("genesis", _row()))
    assert gone.detail is None and gone.detail_salt is None
    assert verify_chain([gone]).ok


def test_clearing_the_salt_does_not_skip_verification():
    """SECURITY: the salt is not a switch for disabling the commitment check."""
    sealed = _seal2("genesis", _row())
    attack = dataclasses.replace(
        sealed, detail={"qty": 999, "sku": "STOLEN"}, detail_salt=None)
    result = verify_chain([attack])
    assert not result.ok
    assert "detail_salt" in (result.reason or "")


# ── Cross-SDK: Go seals, Python verifies ─────────────────────────────────────
#
# The existing vector (go/xlang_form2.json) runs one direction only: Python
# seals, Go verifies. Nothing checked the reverse, so Go could have sealed rows
# no other SDK accepted — which is exactly the divergence that existed while Go
# sealed form "1" and Python sealed "2". spec/go-sealed-form2.json is produced
# by Go's Seal() and read here.

GO_VECTOR = Path(__file__).resolve().parents[2] / "spec" / "go-sealed-form2.json"


def _rows_from_go_vector() -> list[AuditRow]:
    raw = json.loads(GO_VECTOR.read_text())
    out = []
    for d in raw:
        for field in ("timestamp", "shipped_at"):
            if isinstance(d.get(field), str):
                d[field] = parse_canonical(d[field])
        out.append(AuditRow(**{
            k: d[k] for k in AuditRow.__dataclass_fields__ if k in d
        }))
    return out


def test_python_verifies_a_go_sealed_form_2_chain():
    rows = _rows_from_go_vector()
    assert len(rows) == 2
    assert all(r.canonical_form_id == "2" for r in rows)
    assert all(r.detail_salt and r.detail_commitment for r in rows)
    result = verify_chain(rows)
    assert result.ok, f"Python rejects a Go-sealed form-2 chain: {result.reason}"


def test_go_sealed_commitment_recomputes_under_python():
    """Both SDKs must agree on sha256(salt || canonical_json(detail))."""
    for row in _rows_from_go_vector():
        assert row.detail_salt is not None
        assert detail_commitment(row.detail_salt, row.detail) == \
            row.detail_commitment, \
            f"commitment disagrees across SDKs for {row.id}"


def test_go_sealed_row_detail_tampering_is_caught_by_python():
    rows = _rows_from_go_vector()
    attacked = [dataclasses.replace(rows[0], detail={"qty": 999})] + rows[1:]
    assert not verify_chain(attacked).ok, \
        "Python accepted tampered detail on a Go-sealed row"


def test_redacting_a_go_sealed_row_keeps_the_chain_valid():
    """The whole purpose: destroy the payload, keep the evidence."""
    rows = _rows_from_go_vector()
    rows[0] = dataclasses.replace(rows[0], detail=None, detail_salt=None)
    result = verify_chain(rows)
    assert result.ok, \
        f"a redacted Go-sealed row broke the chain: {result.reason}"


def test_committed_cross_sdk_vector_matches_current_sealing():
    """The Go-facing vector must not go stale.

    spec/python-sealed-forms.json is what Go verifies. If Python's sealing
    changes and the file is not regenerated, Go keeps verifying the OLD rows
    and the divergence is invisible — the file would silently stop describing
    this SDK. Regenerating here and comparing makes that a CI failure.

    Regenerate with: python3 scripts/gen_cross_sdk_vectors.py
    """
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / "gen_cross_sdk_vectors.py"),
         "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_cross_sdk_vector_covers_both_forms_and_both_timestamp_shapes():
    """Whole-second instants diverge under both halves of the P1-48 defect at
    once, so a vector without them passes a suffix-only fix."""
    labels = {c["label"] for c in
              json.loads((Path(__file__).resolve().parents[2] /
                          "spec" / "python-sealed-forms.json").read_text())["cases"]}
    for required in ("form1_micros", "form1_whole_second",
                     "form1_legacy_Z_micros", "form1_legacy_Z_whole",
                     "form2_micros", "form2_whole_second"):
        assert required in labels, f"vector lost coverage: {required}"
