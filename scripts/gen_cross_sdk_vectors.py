#!/usr/bin/env python3
"""Generate spec/python-sealed-forms.json — the Python->Go cross-SDK vector.

Rows are sealed by the Python SDK's own code paths, never hand-written, so the
file always reflects what Python actually produces. Go reads it in
TestCrossLanguage_GoAcceptsEveryPythonSealedForm; Python checks the committed
copy still matches in test_canonical_form_2.py.

Deterministic by construction — fixed instants and PINNED salts. seal() reuses
row.detail_salt when set and mints one otherwise, so without pinning every run
would differ and a regenerate-and-compare test could not exist.

Usage:  python3 scripts/gen_cross_sdk_vectors.py [--check]
        --check exits 1 if the committed file differs from a fresh build.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "python"))

from fasten.attrs import AuditRow                                    # noqa: E402
from fasten.chain import (                                           # noqa: E402
    CURRENT_CANONICAL_FORM_ID,
    _row_hash_form_1,
    _row_hash_form_1_legacy_z,
    seal,
)

OUT = REPO / "spec" / "python-sealed-forms.json"

# Two instants: microseconds present, and a whole second. The whole-second case
# is the one that diverges under both halves of the #91 defect at once (the
# offset spelling AND the omitted fractional part), so it must be covered
# explicitly — a suffix-only fix still passes the microsecond case.
MICROS = datetime(2026, 6, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)
WHOLE = datetime(2026, 6, 15, 10, 30, 45, 0, tzinfo=timezone.utc)

# A row sealed by a REAL pre-conformance release, captured once and frozen.
#
# Every other legacy-Z case here is built by today's _row_hash_form_1_legacy_z,
# so on its own it only proves both SDKs agree with the current reconstruction.
# If that reconstruction drifted from what the old release actually wrote, the
# vector would not notice. This row and its hash are LITERALS — nothing here
# recomputes them — so the test that compares them to today's function is the
# one non-circular check in the file.
#
# Provenance: sealed on commit 99bd8f4 (parent of 5a8f684, which introduced the
# spec 1.2 hashed form). To re-capture, check out that tree and call
# chain._row_hash on the row below with "hash" removed.
#
# Do NOT regenerate this. If today's reconstruction stops reproducing this hash,
# the fallback has stopped accepting real legacy rows — that is a defect, not a
# reason to update the constant.
FROZEN_PREFIX_ROW = {
    "action": "create",
    "actor": "alice",
    "actor_kind": "user",
    "canonical_form_id": "1",
    "category": "order",
    "code": "ORDER_PLACED",
    "detail": {"qty": 3, "sku": "WIDGET"},
    "domain": "sales",
    "hash": "10336c91db970616bacee23bf25b06c85b7e85c03bf0c8e10a3f69d6284f02ea",
    "id": "evt-real-prefix",
    "method": "http",
    "monotonic_seq": 1,
    "origin_id": "evt-real-prefix",
    "prev_hash": "genesis",
    "request_id": "req-xyz",
    "service_id": "gateway",
    "severity": "info",
    "shipped_at": None,
    "source_node_id": "node-1",
    "target": "order/42",
    "tenant_id": None,
    "timestamp": "2026-06-15T10:30:45.123456Z",
    "wire_version": "1",
}

PINNED_SALT = "b" * 64


def _row(row_id: str, ts: datetime) -> AuditRow:
    return AuditRow(
        id=row_id, origin_id=row_id, monotonic_seq=1, timestamp=ts,
        code="ORDER_PLACED", action="create", severity="info",
        service_id="gateway", source_node_id="node-1", tenant_id=None,
        actor="alice", actor_kind="user", target="order/42",
        category="order", domain="sales", method="http",
        request_id="req-xyz", detail={"qty": 3, "sku": "WIDGET"},
    )


def build() -> dict:
    cases = []

    def add(label: str, row: AuditRow) -> None:
        cases.append({
            "label": label,
            "row": json.loads(json.dumps(row.to_dict(), default=str)),
        })

    # Form "1" as this SDK seals it: spec §1.2 hashed form ("+00:00",
    # microseconds only when nonzero).
    for label, ts in (("form1_micros", MICROS), ("form1_whole_second", WHOLE)):
        r = dataclasses.replace(_row(f"evt-{label}", ts), canonical_form_id="1")
        d = r.to_dict()
        d.pop("hash", None)
        add(label, dataclasses.replace(r, prev_hash="genesis",
                                       hash=_row_hash_form_1(d)))

    # Form "1" as PRE-CONFORMANCE Python sealed it: the always-"Z" wire
    # timestamp hashed verbatim. These rows exist in deployments and are not
    # tampered; both SDKs need their legacy fallback to accept them.
    for label, ts in (("form1_legacy_Z_micros", MICROS),
                      ("form1_legacy_Z_whole", WHOLE)):
        r = dataclasses.replace(_row(f"evt-{label}", ts), canonical_form_id="1")
        d = r.to_dict()
        d.pop("hash", None)
        add(label, dataclasses.replace(r, prev_hash="genesis",
                                       hash=_row_hash_form_1_legacy_z(d)))

    # Form "2" through the real public sealing path, salt pinned.
    for label, ts in (("form2_micros", MICROS), ("form2_whole_second", WHOLE)):
        r = dataclasses.replace(_row(f"evt-{label}", ts),
                                detail_salt=PINNED_SALT)
        add(label, seal("genesis", r))

    # Shipped rows: sealed with shipped_at null, then marked shipped. Every
    # form hashes shipped_at as null (spec §1.1), so marking moves no hash.
    shipped_at = datetime(2026, 6, 16, 8, 0, 0, 250000, tzinfo=timezone.utc)
    form1 = dataclasses.replace(_row("evt-form1_shipped", MICROS), canonical_form_id="1")
    d = form1.to_dict()
    d.pop("hash", None)
    form1 = dataclasses.replace(form1, prev_hash="genesis", hash=_row_hash_form_1(d))
    add("form1_shipped", dataclasses.replace(form1, shipped_at=shipped_at))
    legacy = dataclasses.replace(_row("evt-form1_legacy_Z_shipped", MICROS),
                                 canonical_form_id="1")
    d = legacy.to_dict()
    d.pop("hash", None)
    legacy = dataclasses.replace(legacy, prev_hash="genesis",
                                 hash=_row_hash_form_1_legacy_z(d))
    add("form1_legacy_Z_shipped", dataclasses.replace(legacy, shipped_at=shipped_at))
    form2 = seal("genesis", dataclasses.replace(_row("evt-form2_shipped", MICROS),
                                                detail_salt=PINNED_SALT))
    add("form2_shipped", dataclasses.replace(form2, shipped_at=shipped_at))

    # The frozen real-release row, passed through verbatim.
    cases.append({"label": "form1_real_prefix_release",
                  "row": dict(FROZEN_PREFIX_ROW)})

    return {"current_form": CURRENT_CANONICAL_FORM_ID, "cases": cases}


def main() -> int:
    fresh = json.dumps(build(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print(f"{OUT} is missing — run without --check to generate it")
            return 1
        if OUT.read_text() != fresh:
            print(f"{OUT} is stale. Python's sealing changed; regenerate with:\n"
                  f"  python3 scripts/{Path(__file__).name}")
            return 1
        print(f"{OUT} matches current sealing")
        return 0
    OUT.write_text(fresh)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
