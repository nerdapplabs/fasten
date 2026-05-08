"""
Secret-key and value-shape redaction — thin Python adapter.

All redaction logic lives in fasten-core (Rust).  This module exposes the
same `Redactor` class API as before; for the common case (all-string-keyed
dicts) the value is serialised to JSON and delegated to `fasten_redact` /
`fasten_redact_full` via ctypes.

Non-JSON-serialisable keys (integers, tuples, etc.) are handled by a minimal
Python fallback path: key-pattern matching uses a compiled Python regex (built
from the same `_REDACT_PATTERNS` constants that the Rust core uses), while
per-string value-shape checking still delegates to the Rust core.

Two-pass algorithm (canonical implementation in store-core/src/redact.rs):
  1. Key-pattern — keys matching REDACT_PATTERNS → replacement token.
  2. Value-shape — string values matching known secret shapes → typed token.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional

from . import core_ffi
from .codes import _REDACT_PATTERNS, _REDACT_REPLACEMENT

# Structlog internals that are never redacted regardless of key name.
_STRUCTLOG_SKIP = frozenset({
    "timestamp", "level", "logger", "event", "_record", "_from_structlog",
})

# Default key-pattern regex — same patterns as the Rust REDACT_PATTERNS.
# Used ONLY for the non-string-key fallback path.
_DEFAULT_KEY_RE: re.Pattern[str] = re.compile(
    r"(?i)(" + "|".join(_REDACT_PATTERNS) + r")"
)


class Redactor:
    def __init__(
        self,
        extra_keys: list[str] | None = None,
        replacement: str = _REDACT_REPLACEMENT,
        extra_value_patterns: Optional[list[tuple[str, str, str]]] = None,
    ) -> None:
        self._extra_keys  = extra_keys or []
        self._replacement = replacement or _REDACT_REPLACEMENT
        # Convert (name, pattern, repl) → (pattern, repl) — name is docs-only.
        self._extra_vp: list[tuple[str, str]] = [
            (pat, repl) for (_name, pat, repl) in (extra_value_patterns or [])
        ]
        # Use the simple fasten_redact path when no customisation is needed.
        self._is_default = (
            not self._extra_keys
            and self._replacement == _REDACT_REPLACEMENT
            and not self._extra_vp
        )
        # Python regex for the non-string-key fallback path.
        if self._extra_keys:
            extra_esc = "|".join(re.escape(k) for k in self._extra_keys)
            combined  = "|".join(_REDACT_PATTERNS) + "|" + extra_esc
            self._key_re: re.Pattern[str] = re.compile(r"(?i)(" + combined + r")")
        else:
            self._key_re = _DEFAULT_KEY_RE

    def _check_str_value(self, s: str) -> str:
        """Run value-shape redaction on a single string via Rust core."""
        out = json.loads(core_ffi.redact_json(json.dumps({"_": s})))
        return out["_"]  # type: ignore[no-any-return]

    def _redact_native(self, value: Any) -> Any:
        """Python fallback for values that cannot be JSON-serialised (non-string dict keys).

        Delegates to Rust for all-string-keyed sub-dicts and for individual
        string value-shape checks, so no redaction logic is duplicated here.
        """
        if isinstance(value, dict):
            # If ALL keys are strings in this sub-dict, hand off to Rust.
            if all(isinstance(k, str) for k in value):
                return json.loads(self._fast_redact_json(json.dumps(value)))
            result = {}
            for k, v in value.items():
                if isinstance(k, str) and self._key_re.search(k):
                    result[k] = self._replacement
                else:
                    result[k] = self._redact_native(v)
            return result
        if isinstance(value, list):
            return [self._redact_native(v) for v in value]
        if isinstance(value, str):
            return self._check_str_value(value)
        return value

    def _fast_redact_json(self, in_json: str) -> str:
        if self._is_default:
            return core_ffi.redact_json(in_json)
        return core_ffi.redact_json_full(
            in_json,
            extra_keys=self._extra_keys or None,
            replacement=self._replacement if self._replacement != _REDACT_REPLACEMENT else None,
            extra_value_patterns=self._extra_vp or None,
        )

    def redact(self, value: Any) -> Any:
        """Deep-redact a value (dict / list / scalar) via the Rust core."""
        # For dicts with non-string keys, json.dumps would fail; use the Python fallback.
        if isinstance(value, dict) and any(not isinstance(k, str) for k in value):
            return self._redact_native(value)
        try:
            in_json = json.dumps(value)
        except (TypeError, ValueError):
            return self._redact_native(value)
        return json.loads(self._fast_redact_json(in_json))

    def as_structlog_processor(self) -> Callable[..., Any]:
        """Return a structlog processor that redacts sensitive keys from event_dict.

        Structlog internal keys (timestamp, level, event, …) are always skipped.
        All other keys are redacted via the Rust core.
        """
        def _processor(logger_: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
            # Separate structlog internals from user payload; redact payload; merge.
            internals = {k: v for k, v in event_dict.items() if k in _STRUCTLOG_SKIP}
            payload   = {k: v for k, v in event_dict.items() if k not in _STRUCTLOG_SKIP}
            redacted  = self.redact(payload)
            return {**internals, **redacted}
        return _processor
