"""
Secret-key and value-shape redaction processor.

Two complementary passes run before emit:
  1. Key-pattern redaction — keys matching a regex have values replaced with
     the replacement token (default "***"). Keys stay visible so the *presence*
     of a secret is observable.
  2. Value-shape redaction — string values matching known secret shapes (credit
     card numbers, JWTs, PEM private keys, AWS/GH tokens) are replaced with a
     type-hinting token (e.g. "***CC***"). Runs after key-pattern pass so
     already-redacted values are never double-processed.

Adopters extend via:
  fasten.init(extra_redact_keys=[...])          — add key-pattern entries
  fasten.init(extra_value_redact_patterns=[...]) — add (name, regex_str, repl) tuples
  fasten.init(redact_replacement="<hidden>")     — override key-redact token
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

# Patterns generated from spec/row-schema.json — see codes._REDACT_PATTERNS.
from .codes import _REDACT_PATTERNS, _REDACT_REPLACEMENT as _DEFAULT_REPLACEMENT

_DEFAULT_KEY_PATTERN = re.compile(
    r"(?i)(" + "|".join(_REDACT_PATTERNS) + r")"
)

# Structlog internal keys that must never be redacted even if they match a pattern.
_STRUCTLOG_SKIP = frozenset({
    "timestamp", "level", "logger", "event", "_record", "_from_structlog",
})


# ── Value-shape patterns ──────────────────────────────────────────────────────

def _luhn_valid(digits: str) -> bool:
    """Return True iff the digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Matches 13–19 digit groups with optional space/dash separators (card formatting).
_CC_DIGIT_RE = re.compile(r'\b\d[\d\s\-]{11,17}\d\b')

# Default value patterns: (name, compiled_regex, replacement_token).
# Applied in order; first match wins.
_DEFAULT_VALUE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # JWT: three base64url segments, first two starting with eyJ (standard header + payload)
    ("JWT",
     re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
     "***JWT***"),
    # PEM private key block header (any standard algorithm prefix)
    ("PRIVATE_KEY",
     re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
     "***PRIVATE_KEY***"),
    # AWS access key (permanent AKIA or short-lived ASIA)
    ("AWS_KEY",
     re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
     "***AWS_KEY***"),
    # GitHub personal / OAuth / actions token
    ("GH_TOKEN",
     re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}'),
     "***GH_TOKEN***"),
    # Stripe live secret key
    ("STRIPE_KEY",
     re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
     "***STRIPE_KEY***"),
    # OpenAI API key (sk-... legacy and sk-proj-... org format)
    ("OPENAI_KEY",
     re.compile(r'sk-(?:proj-)?[A-Za-z0-9_-]{32,}'),
     "***OPENAI_KEY***"),
]


class Redactor:
    def __init__(
        self,
        extra_keys: list[str] | None = None,
        replacement: str = _DEFAULT_REPLACEMENT,
        extra_value_patterns: Optional[list[tuple[str, str, str]]] = None,
    ) -> None:
        self._replacement = replacement
        self._pattern = _DEFAULT_KEY_PATTERN
        if extra_keys:
            extra_escaped = "|".join(re.escape(k) for k in extra_keys)
            combined = "|".join(_REDACT_PATTERNS) + "|" + extra_escaped
            self._pattern = re.compile(r"(?i)(" + combined + r")")

        self._value_patterns: list[tuple[str, re.Pattern[str], str]] = list(
            _DEFAULT_VALUE_PATTERNS
        )
        if extra_value_patterns:
            for name, pat_str, repl in extra_value_patterns:
                self._value_patterns.append((name, re.compile(pat_str), repl))

    def _check_value(self, s: str) -> Optional[str]:
        """Return replacement token if s matches any value-shape pattern, else None."""
        # Credit card: digit group matching Luhn (guards against order-number false-positives)
        m = _CC_DIGIT_RE.search(s)
        if m:
            digits = re.sub(r'[\s\-]', '', m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                return "***CC***"
        # Named pattern list
        for _name, pattern, replacement in self._value_patterns:
            if pattern.search(s):
                return replacement
        return None

    def redact(self, value: Any) -> Any:
        """Deep-redact a value (dict / list / scalar).

        Pass 1 — key-pattern: dict keys matching the secret-key regex have their
        values replaced unconditionally.
        Pass 2 — value-shape: string scalar values not already redacted by pass 1
        are checked against known secret shapes (CC, JWT, private key, etc.).

        Non-string dict keys (int, tuple, etc.) are tolerated: the pattern only
        matches against str keys, so non-str keys are not flagged and we just
        recurse into the value.
        """
        if isinstance(value, dict):
            return {
                k: (self._replacement
                    if isinstance(k, str) and self._pattern.search(k)
                    else self.redact(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if isinstance(value, str):
            repl = self._check_value(value)
            if repl is not None:
                return repl
        return value

    def as_structlog_processor(self) -> Callable[..., Any]:
        """Return a structlog processor that redacts sensitive keys from event_dict.

        Skips structlog internals (timestamp, level, event, etc.) so they are
        never accidentally masked. Recurses into nested dicts, and applies value-
        shape redaction on string scalar values.
        """
        def _processor(logger_: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
            for key in list(event_dict.keys()):
                if key in _STRUCTLOG_SKIP:
                    continue
                if isinstance(key, str) and self._pattern.search(key):
                    event_dict[key] = self._replacement
                elif isinstance(event_dict[key], (dict, list)):
                    event_dict[key] = self.redact(event_dict[key])
                elif isinstance(event_dict[key], str):
                    repl = self._check_value(event_dict[key])
                    if repl is not None:
                        event_dict[key] = repl
            return event_dict
        return _processor
