"""Turn search box text into the reader's query parameters.

The result (:class:`Chips`) only uses what the reader already supports: field
filters, a ``request_id`` to correlate on, and free-text ``q``. Other
:class:`Translator` implementations return the same type.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Protocol, runtime_checkable

from .context import is_sentinel

# Fields the reader can filter on. Any other field:value is search text.
KNOWN_FIELDS = frozenset({
    "request_id", "code", "domain", "source_node_id", "tenant_id",
    "actor", "target", "method", "path", "status", "service_id",
    "event", "level", "since", "until",
})

# A bare token that looks like a request id (mint_id() gives 12 hex chars;
# 8 or more avoids short words) or a sentinel id is treated as one.
_HEXID = re.compile(r"^[0-9a-f]{8,}$")
_QUOTED = re.compile(r'"([^"]*)"')


@dataclasses.dataclass
class Chips:
    """A translated query.

    When ``request_id`` is set the caller should correlate on it rather than
    filter. ``filters`` are exact matches combined with AND; ``q`` is free text.
    """
    request_id: str | None = None
    filters: dict[str, str] = dataclasses.field(default_factory=dict)
    q: str | None = None


@runtime_checkable
class Translator(Protocol):
    """Anything that turns query text into :class:`Chips`."""

    def translate(self, text: str) -> Chips: ...


class RuleTranslator:
    """Rule-based translator.

    - ``"quoted text"`` goes to ``q``
    - ``field:value`` for a known field becomes a filter
    - ``request_id:X``, a long hex token or a sentinel id sets ``request_id``
    - anything else is added to ``q``

    An ``ask:`` prefix is ignored. Time phrases like "yesterday 2pm" are not
    interpreted.
    """

    def translate(self, text: str) -> Chips:
        text = text.strip()
        if text.lower().startswith("ask:"):
            text = text[4:].strip()

        chips = Chips()
        q_parts: list[str] = []

        # Quoted text goes to q as is, spaces included.
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
