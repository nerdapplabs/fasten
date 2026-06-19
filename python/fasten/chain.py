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
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .attrs import AuditRow

# The canonical_form_id stamped on every row sealed by this SDK version.
CURRENT_CANONICAL_FORM_ID = "1"


def _canonical_json(d: dict[str, Any]) -> bytes:
    """Canonical JSON for hash chain: sorted keys, no whitespace, None->null."""
    return json.dumps(d, sort_keys=True, separators=(',', ':'), default=str).encode()


def _row_hash_form_1(row_dict: dict[str, Any]) -> str:
    """Form "1": SHA256 of canonical JSON of the row, excluding the 'hash' field.

    ``canonical_form_id`` is part of ``row_dict`` (via AuditRow.to_dict) and is
    therefore covered by the hash.
    """
    d = {k: v for k, v in row_dict.items() if k != "hash"}
    return hashlib.sha256(_canonical_json(d)).hexdigest()


# Form-id -> hash function registry. Adding a v2 is purely additive: register a
# new id here and stamp it in seal(); verify_chain dispatches automatically and
# rejects any id not present in this map.
_HASH_FN_BY_FORM: dict[str, Callable[[dict[str, Any]], str]] = {
    "1": _row_hash_form_1,
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
    sealed = dataclasses.replace(
        row,
        canonical_form_id=CURRENT_CANONICAL_FORM_ID,
        prev_hash=prev_hash,
    )
    return dataclasses.replace(sealed, hash=_row_hash(sealed.to_dict()))


@dataclasses.dataclass
class ChainVerifyResult:
    """Result of verify_chain()."""
    ok: bool
    total_rows: int
    first_break_at: Optional[int]   # monotonic_seq of first tampered row
    reason: Optional[str]


def verify_chain(rows: "list[AuditRow]") -> ChainVerifyResult:
    """Walk the per-row hash chain and return a verification result.

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

    sorted_rows = sorted(rows, key=lambda r: r.monotonic_seq)
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
        expected = hash_fn({k: v for k, v in row.to_dict().items()})
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
