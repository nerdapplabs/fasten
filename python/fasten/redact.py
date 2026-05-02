"""
Secret-key redaction processor.

Runs before emit. Keys whose name matches the pattern have values replaced
with the replacement token (default "***"); keys stay visible so the
*presence* of a secret is observable.

Adopters extend the default pattern via fasten.init(extra_redact_keys=[...])
and override the replacement token via fasten.init(redact_replacement="<hidden>").
"""
from __future__ import annotations

import re
from typing import Any, Callable

# Patterns generated from spec/row-schema.json — see codes._REDACT_PATTERNS.
from .codes import _REDACT_PATTERNS, _REDACT_REPLACEMENT as _DEFAULT_REPLACEMENT

_DEFAULT_KEY_PATTERN = re.compile(
    r"(?i)(" + "|".join(_REDACT_PATTERNS) + r")"
)

# Structlog internal keys that must never be redacted even if they match a pattern.
_STRUCTLOG_SKIP = frozenset({
    "timestamp", "level", "logger", "event", "_record", "_from_structlog",
})


class Redactor:
    def __init__(
        self,
        extra_keys: list[str] | None = None,
        replacement: str = _DEFAULT_REPLACEMENT,
    ) -> None:
        self._replacement = replacement
        self._pattern = _DEFAULT_KEY_PATTERN
        if extra_keys:
            extra_escaped = "|".join(re.escape(k) for k in extra_keys)
            combined = "|".join(_REDACT_PATTERNS) + "|" + extra_escaped
            self._pattern = re.compile(r"(?i)(" + combined + r")")

    def redact(self, value: Any) -> Any:
        """Deep-redact a value (dict / list / scalar)."""
        if isinstance(value, dict):
            return {
                k: (self._replacement if self._pattern.search(k) else self.redact(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        return value

    def as_structlog_processor(self) -> Callable[..., Any]:
        """Return a structlog processor that redacts sensitive keys from event_dict.

        Skips structlog internals (timestamp, level, event, etc.) so they are
        never accidentally masked. Recurses into nested dicts.
        """
        def _processor(logger_: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
            for key in list(event_dict.keys()):
                if key in _STRUCTLOG_SKIP:
                    continue
                if self._pattern.search(key):
                    event_dict[key] = self._replacement
                elif isinstance(event_dict[key], (dict, list)):
                    event_dict[key] = self.redact(event_dict[key])
            return event_dict
        return _processor
