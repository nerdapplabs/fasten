#!/usr/bin/env python3
"""Generate spec/python-sealed-forms.json, rows sealed by Python for Go to verify.

The rows come from the Python SDK's own sealing code, not written by hand. Go
reads the file in TestCrossLanguage_GoAcceptsEveryPythonSealedForm; Python
checks the committed copy is current in test_canonical_form_2.py.

Timestamps and salts are fixed so the output is the same on every run. seal()
reuses row.detail_salt when set and mints a random one otherwise.

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

# One timestamp with microseconds and one on a whole second. The whole second
# covers both parts of #91 (the "+00:00" offset and the dropped fraction); the
# microsecond case alone passes with only the offset fixed.
MICROS = datetime(2026, 6, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)
WHOLE = datetime(2026, 6, 15, 10, 30, 45, 0, tzinfo=timezone.utc)

# A row sealed by a release from before the spec 1.2 hashed form, stored as
# literals. The other legacy-Z cases are built with today's
# _row_hash_form_1_legacy_z, so only this row checks that function against
# what an old release really wrote.
#
# Sealed on commit 99bd8f4 (parent of 5a8f684, which introduced the spec 1.2
# hashed form) by calling chain._row_hash on this row without "hash".
#
# Don't update it to match new code: if today's function no longer reproduces
# this hash, the legacy fallback is broken.
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

    # Form "1" as Python seals it now: spec §1.2 hashed form ("+00:00",
    # microseconds only when nonzero).
    for label, ts in (("form1_micros", MICROS), ("form1_whole_second", WHOLE)):
        r = dataclasses.replace(_row(f"evt-{label}", ts), canonical_form_id="1")
        d = r.to_dict()
        d.pop("hash", None)
        add(label, dataclasses.replace(r, prev_hash="genesis",
                                       hash=_row_hash_form_1(d)))

    # Form "1" as older Python releases sealed it: the "Z" wire timestamp
    # hashed as is. Deployed stores hold such rows, so both SDKs must accept them.
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

    # The row from the old release, unchanged.
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
