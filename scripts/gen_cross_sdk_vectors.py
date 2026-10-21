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
# is the one that diverges under both halves of the P1-48 defect at once (the
# offset spelling AND the omitted fractional part), so it must be covered
# explicitly — a suffix-only fix still passes the microsecond case.
MICROS = datetime(2026, 6, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)
WHOLE = datetime(2026, 6, 15, 10, 30, 45, 0, tzinfo=timezone.utc)

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
