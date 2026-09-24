"""
Hash chain — the single canonical home for fasten's tamper-evidence chain.

This module owns the row-hash canonical form, the per-row ``seal()`` operation,
and ``verify_chain()``. ``engine.py`` (emit path) and ``store/repo.py``
(verified-prefix / ingest path) both import from here, so there is exactly ONE
implementation of the hash and ONE place the canonical form is documented.

Canonical forms
---------------
The hashed canonical form is itself versioned via ``AuditRow.canonical_form_id``
so the choice of bytes is tamper-evident and future forms are additive.

Form "1" (the only form today): SHA-256 of the canonical JSON of the row dict
with the ``hash`` field excluded, where canonical JSON is

    json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)

over ``AuditRow.to_dict()``. This means:
  - the exact Python AuditRow field set (NOTE: no ``pii_in_detail`` — the Go
    wire Row carries it but the Python AuditRow does not; both SDKs exclude it
    from the hash so a Go aggregator can verify a Python-sealed chain),
  - ``canonical_form_id`` IS included in the hashed bytes,
  - sorted keys (top level and nested), compact separators,
  - ``None`` -> ``null`` for tenant_id / shipped_at,
  - timestamps as ``datetime.isoformat()`` strings.

A new form is added by registering a new id in ``_HASH_FN_BY_FORM`` with its own
hash function; ``verify_chain`` dispatches per row on ``canonical_form_id`` and
REJECTS rows that carry an unknown id.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .attrs import AuditRow

# The canonical_form_id stamped on every row sealed by this SDK version.
#
# Form "2" (spec §1.4) is now stamped on new rows: the stores carry
# detail_salt / detail_commitment and migrate existing tables. detail is
# COMMITTED to rather than hashed, so it can be destroyed for retention without
# moving the row hash — which is what makes a PII purge possible without
# breaking the chain (P1-47).
#
# Form "1" stays registered forever so every pre-existing row verifies
# unchanged; verify_chain dispatches per row.
CURRENT_CANONICAL_FORM_ID = "2"


def _canonical_json(d: dict[str, Any]) -> bytes:
    """Canonical JSON for hash chain: sorted keys, no whitespace, None->null."""
    return json.dumps(d, sort_keys=True, separators=(',', ':'), default=str).encode()


# Fields that exist on AuditRow but are NOT part of form "1"'s hashed bytes.
# detail_salt / detail_commitment were added for form "2" (spec §1.4); excluding
# them here is what keeps every pre-existing form-"1" hash bit-identical.
_FORM_1_EXCLUDED = frozenset({"hash", "detail_salt", "detail_commitment"})

# Form "2" commits to detail instead of hashing it, so `detail` and its salt
# leave the hashed set and `detail_commitment` enters it.
_FORM_2_EXCLUDED = frozenset({"hash", "detail", "detail_salt"})


def detail_commitment(salt: str, detail: Any) -> str:
    """Salted commitment to ``detail`` (spec §1.4): sha256(salt || canonical).

    The salt is what makes the commitment hiding. An unsalted digest of a
    low-entropy value (an email address, an account id) is a dictionary attack
    away from the original, so destroying ``detail`` alone would not destroy the
    information. Redaction therefore drops the salt too.
    """
    return hashlib.sha256(salt.encode() + _canonical_json(detail)).hexdigest()


_TS_HASHED_FIELDS = ("timestamp", "shipped_at")


def _hashed_ts(value: Any) -> Any:
    """Render a timestamp in the HASHED form (spec §1.2): ``+00:00``, and
    six-digit microseconds only when nonzero.

    ``AuditRow.to_dict()`` stamps timestamps with ``canonical_ts`` (spec §4.3),
    which is always-``Z`` with fixed six-digit microseconds so stamps sort
    lexicographically. That is the right WIRE form and the wrong HASHED form:
    §1.2 pins ``datetime.isoformat()``, and Go's ``pyISOFormat`` implements it.
    Hashing the ``Z`` form made every Python-sealed row unverifiable by a Go
    aggregator. The two forms are deliberately different; this converts back.
    """
    if not isinstance(value, str) or not value.endswith("Z"):
        return value
    body = value[:-1]
    if body.endswith(".000000"):
        body = body[: -len(".000000")]
    return body + "+00:00"


def _to_hashed_form(d: dict[str, Any]) -> dict[str, Any]:
    out = dict(d)
    for k in _TS_HASHED_FIELDS:
        if k in out:
            out[k] = _hashed_ts(out[k])
    return out


def _row_hash_form_1(row_dict: dict[str, Any]) -> str:
    """Form "1": SHA256 of canonical JSON of the row, excluding the 'hash' field.

    ``canonical_form_id`` is part of ``row_dict`` (via AuditRow.to_dict) and is
    therefore covered by the hash.
    """
    d = {k: v for k, v in row_dict.items() if k not in _FORM_1_EXCLUDED}
    return hashlib.sha256(_canonical_json(_to_hashed_form(d))).hexdigest()


def _row_hash_form_1_legacy_z(row_dict: dict[str, Any]) -> str:
    """Form "1" as Python ACTUALLY sealed it before the §1.2 conformance fix.

    Python hashed the wire timestamp verbatim (always-``Z``) while the spec and
    Go used ``+00:00`` — the P1-48 divergence. Fixing it changed every hash
    Python had already written, so a pre-upgrade row fails against the
    conformant function and is reported as "hash mismatch" — which reads as
    tampering, the exact false signal this chain exists to avoid.

    ``verify_chain`` falls back to this for form-"1" rows ONLY. Delete it when
    form "1" is retired.
    """
    d = {k: v for k, v in row_dict.items() if k not in _FORM_1_EXCLUDED}
    return hashlib.sha256(_canonical_json(d)).hexdigest()


def _row_hash_form_2(row_dict: dict[str, Any]) -> str:
    """Form "2" (spec §1.4): ``detail`` replaced by ``detail_commitment``.

    Because ``detail`` is not hashed, it can be set to NULL for retention
    without changing this row's hash — and therefore without invalidating the
    successor's ``prev_hash``, which would otherwise cascade a re-seal down the
    whole chain and be indistinguishable from tampering.
    """
    # NO _to_hashed_form here: form "2" hashes the timestamp exactly as the row
    # carries it on the wire (§4.3 / §1.4). One renderer, one spelling. Form "1"
    # needs the conversion because it hashed a different spelling than it wrote.
    d = {k: v for k, v in row_dict.items() if k not in _FORM_2_EXCLUDED}
    return hashlib.sha256(_canonical_json(d)).hexdigest()


# Form-id -> hash function registry. Adding a v2 is purely additive: register a
# new id here and stamp it in seal(); verify_chain dispatches automatically and
# rejects any id not present in this map.
_HASH_FN_BY_FORM: dict[str, Callable[[dict[str, Any]], str]] = {
    "1": _row_hash_form_1,
    "2": _row_hash_form_2,
}


def _row_hash(row_dict: dict[str, Any]) -> str:
    """Compute the row hash using the row's declared canonical_form_id.

    Defaults to form "1" when the dict carries no canonical_form_id (rows built
    before the field existed serialise without it). Raises KeyError on an
    unknown id — callers that must tolerate unknown ids use verify_chain, which
    rejects them gracefully instead.
    """
    form_id = str(row_dict.get("canonical_form_id", CURRENT_CANONICAL_FORM_ID))
    return _HASH_FN_BY_FORM[form_id](row_dict)


def seal(prev_hash: str, row: "AuditRow") -> "AuditRow":
    """Return a copy of ``row`` sealed into the chain.

    Stamps the current ``canonical_form_id``, sets ``prev_hash``, computes the
    self ``hash`` over the canonical form, and returns the new row. This is the
    ONE canonical way to seal a row — both the engine emit path and any
    re-sealing helper go through it.
    """
    salt = row.detail_salt or secrets.token_hex(32)
    sealed = dataclasses.replace(
        row,
        canonical_form_id=CURRENT_CANONICAL_FORM_ID,
        prev_hash=prev_hash,
        detail_salt=salt,
        detail_commitment=detail_commitment(salt, row.detail),
    )
    return dataclasses.replace(sealed, hash=_row_hash(sealed.to_dict()))


def redact(row: "AuditRow") -> "AuditRow":
    """Destroy ``detail`` while leaving the chain intact (spec §7.1).

    Returns a copy with ``detail`` and ``detail_salt`` cleared. ``hash``,
    ``prev_hash``, ``monotonic_seq`` and ``canonical_form_id`` are untouched, so
    verification passes before and after and no other row is affected.

    Raises on a form-"1" row: its ``detail`` is hashed directly, so redacting it
    would change its hash and force a re-seal of every following row.
    """
    if str(row.canonical_form_id) != "2":
        raise ValueError(
            f"row {row.id!r} is canonical form {row.canonical_form_id!r}; only "
            'form "2" rows can be redacted without re-sealing the chain suffix '
            "(spec §7.1). This row predates committed detail."
        )
    return dataclasses.replace(row, detail=None, detail_salt=None)


@dataclasses.dataclass
class ChainVerifyResult:
    """Result of verify_chain()."""
    ok: bool
    total_rows: int
    first_break_at: Optional[int]   # monotonic_seq of first tampered row
    reason: Optional[str]


def verify_chain(rows: "list[AuditRow]") -> ChainVerifyResult:
    """Walk the per-row hash chain and return a verification result.

    The canonical hashed form, the cross-language rendering rules (including the
    whole-number-float hazard), the canonical_form_id registry, and the
    replication contract are normative in ``spec/chain-replication.md``.

    Detects field tampering, row insertion, deletion, and reorder. Does NOT
    detect tail truncation — that requires an external tip-anchor (see P1-23 for
    the documented limitation).

    Rows with an empty ``hash`` field (written before hash-chain support was
    enabled) are skipped silently — the chain is verified only for the portion
    that carries hashes.

    Each row's ``canonical_form_id`` is dispatched against the form registry: a
    known id is recomputed and compared; an UNKNOWN id is REJECTED (the result
    is not-ok and the reason names the offending id) so a node can never silently
    accept a row sealed under a form it does not understand.
    """
    if not rows:
        return ChainVerifyResult(ok=True, total_rows=0, first_break_at=None, reason=None)

    # One node, one chain (spec §2). monotonic_seq is unique within a
    # source_node_id, so duplicates mean two allocators raced — a non-conformant
    # in-memory counter (spec §2.1) — and MUST be reported rather than tolerated.
    seen: dict[tuple[str, int], str] = {}
    for row in sorted(rows, key=lambda r: (r.source_node_id, r.monotonic_seq, r.id)):
        if not row.hash:
            continue
        key = (row.source_node_id, row.monotonic_seq)
        if key in seen and seen[key] != row.id:
            return ChainVerifyResult(
                ok=False,
                total_rows=len(rows),
                first_break_at=row.monotonic_seq,
                reason=(
                    f"duplicate monotonic_seq {row.monotonic_seq} on node "
                    f"{row.source_node_id!r}: rows {seen[key]} and {row.id}. "
                    f"Two engines allocated independently (spec §2.1)."
                ),
            )
        seen[key] = row.id

    # Chains are per node (spec §2), so the prev_hash walk MUST be scoped by
    # source_node_id — a flat walk interleaves two nodes' sequences and reports a
    # spurious break. Dedupe by id first: replication is idempotent (spec §4) and
    # a re-delivered row must not be compared against itself.
    by_node: dict[str, dict[str, "AuditRow"]] = {}
    for row in rows:
        by_node.setdefault(row.source_node_id, {}).setdefault(row.id, row)

    for _node in sorted(by_node):
        sorted_rows = sorted(by_node[_node].values(), key=lambda r: r.monotonic_seq)
        for i, row in enumerate(sorted_rows):
            if not row.hash:
                continue  # pre-upgrade row; skip
            form_id = str(row.canonical_form_id)
            hash_fn = _HASH_FN_BY_FORM.get(form_id)
            if hash_fn is None:
                return ChainVerifyResult(
                    ok=False,
                    total_rows=len(rows),
                    first_break_at=row.monotonic_seq,
                    reason=f'row {row.id}: unknown canonical_form_id "{form_id}"',
                )
            row_d = {k: v for k, v in row.to_dict().items()}

            # Form "2" hashes detail_commitment, NOT detail. So the hash alone
            # does not protect detail: an attacker could rewrite detail and
            # leave the commitment intact. Whenever detail AND its salt are
            # still present, recompute the commitment and compare. Once the row
            # is redacted (both NULL, spec §7.1) there is nothing left to check
            # and the commitment stands on its own.
            if form_id == "2" and row.detail is not None and row.detail_salt:
                recomputed = detail_commitment(row.detail_salt, row.detail)
                if recomputed != (row.detail_commitment or ""):
                    return ChainVerifyResult(
                        ok=False,
                        total_rows=len(rows),
                        first_break_at=row.monotonic_seq,
                        reason=f"row {row.id}: detail does not match its commitment",
                    )

            expected = hash_fn(row_d)
            if expected != row.hash and form_id == "1":
                # Pre-P1-48 Python sealed form "1" over the wire "Z" spelling.
                # Accept it rather than report our own spec fix as tampering.
                if _row_hash_form_1_legacy_z(row_d) == row.hash:
                    expected = row.hash
            if expected != row.hash:
                return ChainVerifyResult(
                    ok=False,
                    total_rows=len(rows),
                    first_break_at=row.monotonic_seq,
                    reason=f"row {row.id}: hash mismatch",
                )
            if i > 0:
                prev = sorted_rows[i - 1]
                if prev.hash and row.prev_hash != prev.hash:
                    return ChainVerifyResult(
                        ok=False,
                        total_rows=len(rows),
                        first_break_at=row.monotonic_seq,
                        reason=f"row {row.id}: prev_hash does not match preceding row {prev.id}",
                    )

    return ChainVerifyResult(ok=True, total_rows=len(rows), first_break_at=None, reason=None)
