"""Runs every case in spec/redact-conformance.json.

The same cases run against fasten-core and every SDK.
"""
import json
from pathlib import Path

import pytest
from fasten.redact import Redactor

_SPEC_PATH = Path(__file__).parent.parent.parent / "spec" / "redact-conformance.json"


def _load_cases():
    with _SPEC_PATH.open() as f:
        spec = json.load(f)
    return spec["cases"]


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["name"])
def test_redact_conformance(case):
    r = Redactor()
    result = r.redact(case["input"])
    assert result == case["expected"], (
        f"[{case['name']}] got {result!r}, want {case['expected']!r}"
    )
