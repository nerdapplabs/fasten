"""
Secret-key redaction processor.

Runs before emit. Keys whose name matches the pattern have values replaced
with the replacement token (default "***"); keys stay visible so the
*presence* of a secret is observable.

Adopters extend the default pattern via rivet.init(extra_redact_keys=[...])
and override the replacement token via rivet.init(redact_replacement="<hidden>").
"""
from __future__ import annotations

import re
from typing import Any, Callable

_DEFAULT_KEY_PATTERN = re.compile(
    r"(?i)(api[_-]?key|password|passwd|token|secret|authorization|"
    r"bearer|m2m[_-]?key|cert[_-]?private|private[_-]?key|"
    r"access_key|session_id|cookie|credential|auth)"
)

# Structlog internal keys that must never be redacted even if they match a pattern.
_STRUCTLOG_SKIP = frozenset({
    "timestamp", "level", "logger", "event", "_record", "_from_structlog",
})


class Redactor:
    def __init__(
        self,
        extra_keys: list[str] | None = None,
        replacement: str = "***",
    ) -> None:
        self._replacement = replacement
        self._pattern = _DEFAULT_KEY_PATTERN
        if extra_keys:
            joined = "|".join(re.escape(k) for k in extra_keys)
            self._pattern = re.compile(
                f"(?i)({_DEFAULT_KEY_PATTERN.pattern}|{joined})"
            )

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

    def as_structlog_processor(self) -> Callable:
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
