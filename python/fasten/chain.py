"""Row hashing, sealing and chain verification.

Each row records the hash form it was sealed with in ``canonical_form_id``;
``_HASH_FN_BY_FORM`` maps each id to its hash function. Both forms hash

    json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)

over ``AuditRow.to_dict()`` minus some fields, ``canonical_form_id`` included.
``shipped_at`` is always hashed as null, since it is set after sealing
(spec §1.1).

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
import re
import secrets
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .attrs import AuditRow

# Form stamped by seal(). Form "2" commits to detail rather than hashing it,
# so detail can be destroyed for retention without changing the row hash
# (spec 1.4). Form "1" stays registered so older rows still verify.
CURRENT_CANONICAL_FORM_ID = "2"


def _canonical_json(d: Any) -> bytes:
    """Canonical JSON for hash chain: sorted keys, no whitespace, None->null."""
    return json.dumps(d, sort_keys=True, separators=(',', ':'), default=str).encode()


# Matched left to right, so an escaped backslash (\\) is taken whole and the
# text \u007f, which JSON writes as \\u007f, is left as it is.
_BACKSLASH_OR_DEL_ESCAPE = re.compile(r"\\\\|\\u007f")


def _canonical_json_raw_del(d: Any) -> bytes:
    """``_canonical_json`` with DEL (0x7f) left raw, as the Go SDK wrote it
    before it escaped DEL as ``\\u007f``. Verification fallback only, never
    used to seal."""
    s = json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)
    return _BACKSLASH_OR_DEL_ESCAPE.sub(
        lambda m: "\x7f" if m.group() == "\\u007f" else m.group(), s).encode()


_Canon = Callable[[Any], bytes]


def _has_del(row_dict: dict[str, Any]) -> bool:
    """Whether any string the row hashes holds DEL."""
    return "\x7f" in json.dumps(row_dict, default=str, ensure_ascii=False)


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
    return _detail_commitment(salt, detail, _canonical_json)


def _detail_commitment(salt: str, detail: Any, canon: _Canon) -> str:
    return hashlib.sha256(salt.encode() + canon(detail)).hexdigest()


_TS_HASHED_FIELDS = ("timestamp",)


def _hashed_fields(row_dict: dict[str, Any], excluded: frozenset[str]) -> dict[str, Any]:
    """Row fields hashed by one form. ``shipped_at`` is hashed as null:
    ``mark_shipped`` sets it after sealing (spec §1.1)."""
    d = {k: v for k, v in row_dict.items() if k not in excluded}
    if "shipped_at" in d:
        d["shipped_at"] = None
    return d


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


def _row_hash_form_1(row_dict: dict[str, Any], canon: _Canon = _canonical_json) -> str:
    """Form "1": hash of the row with timestamps in isoformat form."""
    d = _hashed_fields(row_dict, _FORM_1_EXCLUDED)
    return hashlib.sha256(canon(_to_hashed_form(d))).hexdigest()


def _row_hash_form_1_legacy_z(row_dict: dict[str, Any], canon: _Canon = _canonical_json) -> str:
    """Form "1" as Python ACTUALLY sealed it before the §1.2 conformance fix.

    Python hashed the wire timestamp verbatim (always-``Z``) while the spec and
    Go used ``+00:00`` — the divergence in #91. Fixing it changed every hash
    Python had already written, so a pre-upgrade row fails against the
    conformant function and is reported as "hash mismatch" — which reads as
    tampering, the exact false signal this chain exists to avoid.

    ``verify_chain`` falls back to this for form-"1" rows ONLY. Delete it when
    form "1" is retired.
    """
    d = _hashed_fields(row_dict, _FORM_1_EXCLUDED)
    return hashlib.sha256(canon(d)).hexdigest()


def _row_hash_form_2(row_dict: dict[str, Any], canon: _Canon = _canonical_json) -> str:
    """Form "2" (spec 1.4): ``detail_commitment`` is hashed instead of
    ``detail``, so detail can be cleared without changing the hash."""
    # Timestamps are hashed as written on the wire; no _to_hashed_form.
    d = _hashed_fields(row_dict, _FORM_2_EXCLUDED)
    return hashlib.sha256(canon(d)).hexdigest()


def _row_hashes_over_shipped_at(
    form_id: str, row_dict: dict[str, Any], canon: _Canon = _canonical_json,
) -> list[str]:
    """Hashes of a row sealed with ``shipped_at`` already set, as every form
    hashed it before §1.1 nulled it: the stored value, rendered like the
    timestamp next to it. Emit never sealed such rows; a caller passing
    ``shipped_at`` to ``seal()`` or ``allocate_and_insert_originated`` did.

    ``verify_chain`` falls back to these only when the row has a ``shipped_at``.
    """
    if form_id == "1":
        d = {k: v for k, v in row_dict.items() if k not in _FORM_1_EXCLUDED}
        hashed = _to_hashed_form(d)
        hashed["shipped_at"] = _hashed_ts(d["shipped_at"])
        # The second is the legacy-"Z" spelling (#91), both fields verbatim.
        return [hashlib.sha256(canon(x)).hexdigest() for x in (hashed, d)]
    if form_id == "2":
        d = {k: v for k, v in row_dict.items() if k not in _FORM_2_EXCLUDED}
        return [hashlib.sha256(canon(d)).hexdigest()]
    return []


# A new form is added here and stamped in seal(). verify_chain rejects ids
# not in this map.
_HASH_FN_BY_FORM: dict[str, Callable[[dict[str, Any], _Canon], str]] = {
    "1": _row_hash_form_1,
    "2": _row_hash_form_2,
}


def _row_hash(row_dict: dict[str, Any]) -> str:
    """Hash a row dict with its canonical_form_id's function, or the current
    form if it has none. Raises KeyError on an unknown id."""
    form_id = str(row_dict.get("canonical_form_id", CURRENT_CANONICAL_FORM_ID))
    return _HASH_FN_BY_FORM[form_id](row_dict, _canonical_json)


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

    Unsealed rows (empty ``hash``) are redacted too, since no hash covers
    their detail. Raises ValueError for a sealed form "1" row, whose hash
    covers ``detail``.
    """
    if str(row.canonical_form_id) != "2" and row.hash:
        raise ValueError(
            f"row {row.id!r} is canonical form {row.canonical_form_id!r}; only "
            'form "2" and unsealed rows can be redacted without re-sealing the '
            "chain suffix (spec §7.1). This row predates committed detail."
        )
    return dataclasses.replace(row, detail=None, detail_salt=None)


@dataclasses.dataclass
class ChainVerifyResult:
    """Result of verify_chain()."""
    ok: bool
    total_rows: int
    first_break_at: Optional[int]   # monotonic_seq of first tampered row
    reason: Optional[str]


def _row_break(row: "AuditRow") -> Optional[str]:
    """Check a sealed row on its own: its form, its detail commitment and its
    hash. Returns why it fails, or None if it checks out."""
    # A row without the field predates it, so it is form "1" (spec §1.5).
    form_id = str(row.canonical_form_id or "1")
    hash_fn = _HASH_FN_BY_FORM.get(form_id)
    if hash_fn is None:
        return f'row {row.id}: unknown canonical_form_id "{form_id}"'
    row_d = {**row.to_dict(), "canonical_form_id": form_id}

    # Go wrote DEL (0x7f) raw before it escaped it as \u007f, so a row it
    # sealed with DEL in a hashed string matches only that way. Each check
    # below is retried with DEL raw on a miss; nothing else about the
    # encoding changes. Looking for DEL costs an encode, so only a miss pays.
    has_del: Optional[bool] = None

    def matches(check: Callable[[_Canon], bool]) -> bool:
        nonlocal has_del
        if check(_canonical_json):
            return True
        if has_del is None:
            has_del = _has_del(row_d)
        return has_del and check(_canonical_json_raw_del)

    # Form "2" hashes detail_commitment, not detail, so a changed detail
    # with the commitment left as it was still matches the hash. While
    # detail and its salt are present, recompute the commitment and
    # compare. Once the row is redacted (both NULL, spec §7.1) the
    # commitment stands on its own.
    if form_id == "2" and row.detail is not None:
        # Detail present means the commitment must be checkable; a
        # missing salt is a break, not a reason to skip the check.
        # Redaction clears detail and salt together (spec §7.1), so a
        # redacted row never reaches here.
        if not row.detail_salt:
            return (f"row {row.id}: detail present but detail_salt "
                    "is missing — commitment cannot be verified")
        salt = row.detail_salt
        if not matches(lambda c: _detail_commitment(salt, row.detail, c)
                       == (row.detail_commitment or "")):
            return f"row {row.id}: detail does not match its commitment"

    if not matches(lambda c: _hash_matches(row, form_id, hash_fn, row_d, c)):
        return f"row {row.id}: hash mismatch"
    return None


def _hash_matches(row: "AuditRow", form_id: str,
                  hash_fn: Callable[[dict[str, Any], _Canon], str],
                  row_d: dict[str, Any], canon: _Canon) -> bool:
    """Whether row.hash is the row's hash under canon, its form's own or one
    of the fallbacks below."""
    if hash_fn(row_d, canon) == row.hash:
        return True
    # Before #91, Python sealed form "1" over the wire "Z" spelling.
    # Accept it rather than report our own spec fix as tampering.
    if form_id == "1" and _row_hash_form_1_legacy_z(row_d, canon) == row.hash:
        return True
    # Sealed with shipped_at already set, before §1.1 hashed it as
    # null. Such a row matches only over its exact stored value.
    return (row.shipped_at is not None
            and row.hash in _row_hashes_over_shipped_at(form_id, row_d, canon))


def _first_break(sorted_rows: "list[AuditRow]") -> "tuple[int, str] | None":
    """The first break in one node's chain, sorted by monotonic_seq, as
    (monotonic_seq, reason); None if the chain verifies."""
    sealed = [r.monotonic_seq for r in sorted_rows if r.hash]
    first_sealed = min(sealed) if sealed else None
    seen: dict[int, str] = {}
    for i, row in enumerate(sorted_rows):
        if not row.hash:
            if first_sealed is not None and row.monotonic_seq >= first_sealed:
                return row.monotonic_seq, f"row {row.id}: no hash after the node's chain started"
            continue  # written before chaining, or stdout-only
        # monotonic_seq is unique within a node, so a duplicate means two
        # allocators raced — a non-conformant in-memory counter (spec §2.1).
        if seen.get(row.monotonic_seq, row.id) != row.id:
            return row.monotonic_seq, (
                f"duplicate monotonic_seq {row.monotonic_seq} on node "
                f"{row.source_node_id!r}: rows {seen[row.monotonic_seq]} and {row.id}. "
                f"Two engines allocated independently (spec §2.1).")
        seen[row.monotonic_seq] = row.id
        reason = _row_break(row)
        if reason is not None:
            return row.monotonic_seq, reason
        if i > 0:
            prev = sorted_rows[i - 1]
            if prev.hash and row.prev_hash != prev.hash:
                return row.monotonic_seq, f"row {row.id}: prev_hash does not match preceding row {prev.id}"
            # Only a node's first sealed row may skip the check above: the
            # store links it to "genesis" when the unsealed row before it is
            # at seq-1, and a purged head leaves a gap where the window starts.
            if (not prev.hash and prev.monotonic_seq == row.monotonic_seq - 1
                    and row.prev_hash != "genesis"):
                return row.monotonic_seq, f"row {row.id}: first sealed row does not link to genesis"
    return None


def verify_chain(rows: "list[AuditRow]") -> ChainVerifyResult:
    """Walk the per-row hash chain and return a verification result.

    The canonical hashed form, the cross-language rendering rules (including the
    whole-number-float hazard), the canonical_form_id registry, and the
    replication contract are normative in ``spec/chain-replication.md``.

    Detects field tampering, row insertion, deletion, and reorder. Does NOT
    detect tail truncation; that needs an external anchor for the latest
    hash.

    Rows with an empty ``hash`` field (written before hash-chain support, or in
    stdout-only mode) are skipped below their node's first sealed seq; they are
    not covered by the chain. A conformant store never writes one at or above
    it, so one there breaks the chain. A sealed row right after an unsealed one
    must link to "genesis", as the store allocates it (spec §2). With several
    nodes, ``first_break_at`` is the lowest seq at which any of them breaks.
    A row given more than once is checked once: a sealed copy wins over an
    unsealed one, and two sealed copies must have the same, valid hash.

    Each row's ``canonical_form_id`` is dispatched against the form registry: a
    known id is recomputed and compared; an UNKNOWN id is REJECTED (the result
    is not-ok and the reason names the offending id) so a node can never silently
    accept a row sealed under a form it does not understand.
    """
    if not rows:
        return ChainVerifyResult(ok=True, total_rows=0, first_break_at=None, reason=None)

    # Chains are per node (spec §2), so the prev_hash walk MUST be scoped by
    # source_node_id — a flat walk interleaves two nodes' sequences and reports a
    # spurious break. Dedupe by id first: replication is idempotent (spec §4) and
    # a re-delivered row must not be compared against itself. A sealed copy
    # replaces an unsealed one, since a stdout capture has the phase-1 line
    # first. A second sealed copy must be the same row: the same hash, and a
    # hash that checks out. Go does the same.
    by_node: dict[str, dict[str, "AuditRow"]] = {}
    dup: "tuple[int, str] | None" = None
    for row in rows:
        kept = by_node.setdefault(row.source_node_id, {})
        old = kept.get(row.id)
        if old is None or (not old.hash and row.hash):
            kept[row.id] = row
        elif old.hash and row.hash:
            reason = (f"row {row.id}: two sealed copies with different hashes"
                      if row.hash != old.hash else _row_break(row))
            seq = min(row.monotonic_seq, old.monotonic_seq)
            if reason is not None and (dup is None or seq < dup[0]):
                dup = seq, reason

    # A break on any node fails the chain; report the lowest seq at which one
    # occurs, so every SDK gives the same first_break_at for the same rows.
    first: "tuple[int, str] | None" = None
    for _node in sorted(by_node):
        sorted_rows = sorted(by_node[_node].values(), key=lambda r: r.monotonic_seq)
        found = _first_break(sorted_rows)
        if found is not None and (first is None or found[0] < first[0]):
            first = found
    if dup is not None and (first is None or dup[0] < first[0]):
        first = dup
    if first is not None:
        return ChainVerifyResult(ok=False, total_rows=len(rows), first_break_at=first[0], reason=first[1])

    return ChainVerifyResult(ok=True, total_rows=len(rows), first_break_at=None, reason=None)
