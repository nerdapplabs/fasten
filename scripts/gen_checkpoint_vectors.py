#!/usr/bin/env python3
"""Generate spec/checkpoint-vectors.json: rows, checkpoints and the
verify_chain result Python gives for them, whole-chain or partial (spec chain-replication.md §9).

Python and Go both run every case and must give the same ok, first_break_at
and reason. Salts are pinned so the output is the same on every run.

Usage:  python3 scripts/gen_checkpoint_vectors.py [--check]
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

from fasten.attrs import AuditRow                     # noqa: E402
from fasten.chain import seal, verify_chain           # noqa: E402
from fasten.checkpoints import Checkpoint             # noqa: E402

OUT = REPO / "spec" / "checkpoint-vectors.json"
ANCHORED_AT = "2026-06-15T11:00:00.000000Z"


def _row(seq: int, node: str, target: str) -> AuditRow:
    rid = f"evt-{node}-{seq}-{target.replace('/', '')}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, seq, 250000, tzinfo=timezone.utc),
        code="ORDER_PLACED", action="create", severity="info",
        service_id="gateway", source_node_id=node, tenant_id=None,
        actor="alice", actor_kind="user", target=target,
        category="order", domain="sales", method="http",
        request_id=f"req-{seq}", detail={"qty": seq, "sku": "WIDGET"},
        detail_salt=f"{seq:064x}",
    )


def _chain(n: int, node: str = "node-1", target: str = "order/1",
           start: int = 1) -> list[AuditRow]:
    out, prev = [], "genesis"
    for seq in range(start, start + n):
        row = seal(prev, _row(seq, node, target))
        prev = row.hash
        out.append(row)
    return out


def _cp(row: AuditRow) -> Checkpoint:
    return Checkpoint(source_node_id=row.source_node_id, monotonic_seq=row.monotonic_seq,
                      hash=row.hash, anchored_at=ANCHORED_AT)


def build() -> dict:
    cases = []

    def add(label: str, rows: list[AuditRow], cps: list[Checkpoint],
            partial: bool = False) -> None:
        result = verify_chain(rows, checkpoints=cps, partial=partial)
        cases.append({
            "label": label,
            "partial": partial,
            "rows": [json.loads(json.dumps(r.to_dict(), default=str)) for r in rows],
            "checkpoints": [c.to_dict() for c in cps],
            "expected": {"ok": result.ok, "first_break_at": result.first_break_at,
                         "reason": result.reason},
        })

    chain = _chain(6)
    add("matches_tip", chain, [_cp(chain[-1])])
    add("older_checkpoint_inside", chain, [_cp(chain[1]), _cp(chain[-1])])
    add("tail_truncated", chain[:4], [_cp(chain[-1])])
    add("resealed_from_genesis", _chain(6, target="order/2"), [_cp(chain[-1])])
    add("checkpoint_below_rows", chain[3:], [_cp(chain[0]), _cp(chain[-1])])
    add("checkpoint_below_rows_partial", chain[3:], [_cp(chain[0]), _cp(chain[-1])],
        partial=True)
    unsealed = [dataclasses.replace(_row(s, "node-1", "order/0"), hash="", prev_hash="",
                                    detail_salt=None) for s in (1, 2)]
    add("missing_row_in_span", unsealed + chain[3:], [_cp(chain[2])])
    other = [_cp(_chain(3, node="node-2")[-1])]
    add("checkpointed_node_without_rows", chain, other)
    add("node_not_in_rows_skipped_partial", chain, other, partial=True)
    add("no_rows", [], [_cp(chain[-1])])
    add("no_rows_partial", [], [_cp(chain[-1])], partial=True)
    resealed_above = _chain(6, target="order/3", start=7)
    add("rows_start_after_checkpoints", resealed_above, [_cp(chain[2]), _cp(chain[-1])])
    add("rows_start_after_checkpoints_partial", resealed_above,
        [_cp(chain[2]), _cp(chain[-1])], partial=True)
    # Rows deleted and re-sealed above the checkpoint at 6, and the next
    # publish checkpointed the new tip.
    add("resealed_above_with_new_tip_checkpoint", resealed_above,
        [_cp(chain[-1]), _cp(resealed_above[-1])])
    add("resealed_above_with_new_tip_checkpoint_partial", resealed_above,
        [_cp(chain[-1]), _cp(resealed_above[-1])], partial=True)
    a, b = _chain(6, node="node-a"), _chain(6, node="node-b")
    add("two_nodes_lowest_break", a[:5] + b[:2], [_cp(a[-1]), _cp(b[-1])])
    edited = list(chain[:4])
    edited[1] = dataclasses.replace(edited[1], target="order/edited")
    add("chain_break_below_checkpoint_break", edited, [_cp(chain[-1])])
    add("no_checkpoints", chain[:4], [])
    return {"cases": cases}


def main() -> int:
    fresh = json.dumps(build(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print(f"{OUT} is missing; run without --check to generate it")
            return 1
        if OUT.read_text() != fresh:
            print(f"{OUT} is stale; regenerate with:\n  python3 scripts/{Path(__file__).name}")
            return 1
        print(f"{OUT} matches current verification")
        return 0
    OUT.write_text(fresh)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
