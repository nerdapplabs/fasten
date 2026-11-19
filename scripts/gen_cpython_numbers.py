#!/usr/bin/env python3
"""Rewrite js/test/fixtures/cpython-numbers.json with CPython's output.

The fixture pairs number tokens with json.dumps(json.loads(token)): "tokens"
are tokens as stored text holds them, "js_numbers" the text String(n) gives
for a JS number n. The JS tests check canonicalJSON against the second
column; python/tests/test_canonical_form_2.py checks the second column
against this interpreter. The first column is kept; add tokens there and
run this to fill in the second.

Usage:  python3 scripts/gen_cpython_numbers.py [--check]
        --check exits 1 if the committed file differs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "js" / "test" / "fixtures" / "cpython-numbers.json"


def build() -> str:
    old = json.loads(PATH.read_text())

    def pairs(key: str) -> str:
        rows = [json.dumps([tok, json.dumps(json.loads(tok))]) for tok, _ in old[key]]
        return "[\n  " + ",\n  ".join(rows) + "\n]"

    return (
        "{\n"
        f'"_about": {json.dumps(old["_about"])},\n'
        f'"tokens": {pairs("tokens")},\n'
        f'"js_numbers": {pairs("js_numbers")}\n'
        "}\n"
    )


def main() -> int:
    text = build()
    if "--check" in sys.argv[1:]:
        if PATH.read_text() != text:
            print(f"{PATH} is stale; run scripts/gen_cpython_numbers.py", file=sys.stderr)
            return 1
        return 0
    PATH.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
