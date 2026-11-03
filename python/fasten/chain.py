"""Row hashing, sealing and chain verification.

Each row records the hash form it was sealed with in ``canonical_form_id``;
``_HASH_FN_BY_FORM`` maps each id to its hash function. Both forms hash

    json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)

over ``AuditRow.to_dict()`` minus some fields, ``canonical_form_id`` included.

- Form "1" hashes ``detail`` directly, with timestamps in
  ``datetime.isoformat()`` form (``+00:00``).
- Form "2" (current) hashes ``detail_commitment`` instead of ``detail``, and
  timestamps as written on the wire.

``pii_in_detail`` is not an AuditRow field, so it is never hashed; the Go SDK
leaves it out too. The full rules are in spec/chain-replication.md.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .attrs import AuditRow

# Form stamped by seal(). Form "2" commits to detail rather than hashing it,
# so detail can be destroyed for retention without changing the row hash
# (spec 1.4). Form "1" stays registered so older rows still verify.
CURRENT_CANONICAL_FORM_ID = "2"


def _canonical_json(d: dict[str, Any]) -> bytes:
    """Canonical JSON for hash chain: sorted keys, no whitespace, None->null."""
    return json.dumps(d, sort_keys=True, separators=(',', ':'), default=str).encode()


# detail_salt and detail_commitment belong to form "2" and are not hashed
# by form "1".
_FORM_1_EXCLUDED = frozenset({"hash", "detail_salt", "detail_commitment"})

# Form "2" commits to detail instead of hashing it, so `detail` and its salt
# leave the hashed set and `detail_commitment` enters it.
_FORM_2_EXCLUDED = frozenset({"hash", "detail", "detail_salt"})


def detail_commitment(salt: str, detail: Any) -> str:
    """sha256(salt + canonical JSON of detail) (spec 1.4).

    Without the salt a short value such as an email address could be
    recovered by guessing, so redaction clears the salt along with detail.
    """
    return hashlib.sha256(salt.encode() + _canonical_json(detail)).hexdigest()


_TS_HASHED_FIELDS = ("timestamp", "shipped_at")


def _hashed_ts(value: Any) -> Any:
    """Convert a wire timestamp (``Z``, always six-digit microseconds, spec
    4.3) to the form "1" hashed form (``datetime.isoformat()``, spec 1.2):
    ``+00:00``, with microseconds only when nonzero. Go's pyISOFormat does
    the same."""
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
    """Form "1": hash of the row with timestamps in isoformat form."""
    d = {k: v for k, v in row_dict.items() if k not in _FORM_1_EXCLUDED}
    return hashlib.sha256(_canonical_json(_to_hashed_form(d))).hexdigest()


def _row_hash_form_1_legacy_z(row_dict: dict[str, Any]) -> str:
    """Form "1" as Python ACTUALLY sealed it before the §1.2 conformance fix.

    Python hashed the wire timestamp verbatim (always-``Z``) while the spec and
    Go used ``+00:00`` — the divergence in #91. Fixing it changed every hash
    Python had already written, so a pre-upgrade row fails against the
    conformant function and is reported as "hash mismatch" — which reads as
    tampering, the exact false signal this chain exists to avoid.

    ``verify_chain`` falls back to this for form-"1" rows ONLY. Delete it when
    form "1" is retired.
    """
    d = {k: v for k, v in row_dict.items() if k not in _FORM_1_EXCLUDED}
    return hashlib.sha256(_canonical_json(d)).hexdigest()


def _row_hash_form_2(row_dict: dict[str, Any]) -> str:
    """Form "2" (spec 1.4): ``detail_commitment`` is hashed instead of
    ``detail``, so detail can be cleared without changing the hash."""
    # Timestamps are hashed as written on the wire; no _to_hashed_form.
    d = {k: v for k, v in row_dict.items() if k not in _FORM_2_EXCLUDED}
    return hashlib.sha256(_canonical_json(d)).hexdigest()


# A new form is added here and stamped in seal(). verify_chain rejects ids
# not in this map.
_HASH_FN_BY_FORM: dict[str, Callable[[dict[str, Any]], str]] = {
    "1": _row_hash_form_1,
    "2": _row_hash_form_2,
}


def _row_hash(row_dict: dict[str, Any]) -> str:
    """Hash a row dict with its canonical_form_id's function, or the current
    form if it has none. Raises KeyError on an unknown id."""
    form_id = str(row_dict.get("canonical_form_id", CURRENT_CANONICAL_FORM_ID))
    return _HASH_FN_BY_FORM[form_id](row_dict)


def seal(prev_hash: str, row: "AuditRow") -> "AuditRow":
    """Return a copy of ``row`` with the current canonical_form_id,
    ``prev_hash``, a detail salt and commitment, and its ``hash`` set."""
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
    """Return a copy with ``detail`` and ``detail_salt`` cleared (spec 7.1).
    The hash is unchanged, so the chain still verifies.

    Raises ValueError for a form "1" row, whose hash covers ``detail``.
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
    detect tail truncation; that needs an external anchor for the latest
    hash.

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
            if form_id == "2" and row.detail is not None:
                # detail present means the commitment MUST be checkable. An
                # attacker who rewrites detail and clears detail_salt would
                # otherwise skip this branch entirely and the row would verify
                # — the salt is not a switch for turning verification off.
                # Redaction clears detail AND salt together (spec §7.1), so a
                # legitimately redacted row never reaches here.
                if not row.detail_salt:
                    return ChainVerifyResult(
                        ok=False,
                        total_rows=len(rows),
                        first_break_at=row.monotonic_seq,
                        reason=(f"row {row.id}: detail present but detail_salt "
                                "is missing — commitment cannot be verified"),
                    )
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
                # Before #91, Python sealed form "1" over the wire "Z" spelling.
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
