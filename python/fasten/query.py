"""Query translation — natural-language / smart-box input to structured chips.

Per the §3.7 design, discovery input (structured chips, the smart search box, or
plain-English prose) is translated into the SAME small set of primitives the
reader already exposes: structured field filters, a correlation ``request_id``,
and the bounded free-text ``q=`` escape hatch. The translator is an interpreter
one layer above the reader — **not a fourth query surface** — and it never
invents semantics the store does not support (an unknown ``field:value`` becomes
search text, not a fake filter).

OSS ships this interface plus a deterministic reference parser
(:class:`RuleTranslator`, the §6.3 smart-box rules). A richer plain-English
model (the fasten-cloud ``/investigate`` surface) implements the same
:class:`Translator` protocol and returns the same :class:`Chips`, so the UI and
store contract are identical whether the prose was parsed by rules or a model.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Protocol, runtime_checkable

from .context import is_sentinel

# Structured filter fields the reader actually supports (audit + stream reads).
# A field:value chip is only produced for one of these; anything else is treated
# as literal search text so the translator never fabricates a filter the store
# would ignore.
KNOWN_FIELDS = frozenset({
    "request_id", "code", "domain", "source_node_id", "tenant_id",
    "actor", "target", "method", "path", "status", "service_id",
    "event", "level", "since", "until",
})

# A bare token that looks like a correlation id → pivot straight to /correlate.
# fasten's own mint_id() is 12 hex chars; require >= 8 to avoid matching short
# words. Sentinel ids (boot-/orphan-/...) are correlation ids too.
_HEXID = re.compile(r"^[0-9a-f]{8,}$")
_QUOTED = re.compile(r'"([^"]*)"')


@dataclasses.dataclass
class Chips:
    """The translated query: the three reader primitives, side by side.

    ``request_id`` is the correlation pivot (exclusive — when set the consumer
    should correlate, not filter). ``filters`` are structured field chips
    (exact-match, composed with AND). ``q`` is the bounded free-text fallback.
    """
    request_id: str | None = None
    filters: dict[str, str] = dataclasses.field(default_factory=dict)
    q: str | None = None


@runtime_checkable
class Translator(Protocol):
    """Anything that turns query text into :class:`Chips`. The OSS
    :class:`RuleTranslator` and a cloud NL model are interchangeable behind it."""

    def translate(self, text: str) -> Chips: ...


class RuleTranslator:
    """Deterministic reference translator — the §6.3 smart-box rules.

    - ``"quoted text"``           → ``q`` (bounded free-text)
    - ``field:value`` (known)     → structured filter chip
    - ``request_id:X`` / bare id  → correlation ``request_id``
    - a long hex / sentinel token → correlation ``request_id``
    - anything else               → accumulated into ``q``

    An ``ask:`` prefix is stripped and the remainder parsed by the same rules.
    Prose like "yesterday 2pm" is left to a cloud NL model — this parser does not
    guess time ranges it cannot ground.
    """

    def translate(self, text: str) -> Chips:
        text = text.strip()
        if text.lower().startswith("ask:"):
            text = text[4:].strip()

        chips = Chips()
        q_parts: list[str] = []

        # Quoted spans are free-text, verbatim (spaces preserved).
        def _lift_quote(m: re.Match[str]) -> str:
            q_parts.append(m.group(1))
            return " "

        remainder = _QUOTED.sub(_lift_quote, text)

        for tok in remainder.split():
            field, sep, value = tok.partition(":")
            if sep and value and field.lower() in KNOWN_FIELDS:
                if field.lower() == "request_id":
                    chips.request_id = value
                else:
                    chips.filters[field.lower()] = value
                continue
            if _looks_like_request_id(tok):
                chips.request_id = tok
                continue
            q_parts.append(tok)

        if q_parts:
            chips.q = " ".join(q_parts)
        return chips


def _looks_like_request_id(token: str) -> bool:
    return bool(_HEXID.match(token)) or is_sentinel(token)


_default = RuleTranslator()


def translate(text: str) -> Chips:
    """Translate query text to :class:`Chips` with the default rule translator."""
    return _default.translate(text)
