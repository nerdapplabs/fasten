"""Redact conformance — loads spec/redact-conformance.json, runs every case.

The spec is the single source of truth (fasten-core/src/redact.rs is canonical).
All SDKs must pass every case; failures indicate a divergence from the Rust impl.
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
