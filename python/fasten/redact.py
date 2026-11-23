"""Redaction of secrets in log and audit payloads.

Values are serialised to JSON and redacted by fasten-core
(fasten-core/src/redact.rs): values under keys matching REDACT_PATTERNS are
replaced, then string values that look like known secrets are replaced with a
typed token. Dicts with keys JSON cannot encode keep those keys: their keys are
matched here with the same patterns and each value is handed to the core with
the same settings. Values JSON cannot encode, such as datetime, are converted
with str() first.
"""
from __future__ import annotations

import json
import os
import re
import sys
import traceback
from typing import Any, Callable, Optional

from . import core_ffi
from .codes import _REDACT_PATTERNS, _REDACT_REPLACEMENT

# Per-value size cap. 64 KiB fits the largest real audit rows and keeps 2000
# ring slots under 128 MiB. Override with FASTEN_MAX_DETAIL_BYTES.
_MAX_DETAIL_BYTES_DEFAULT = 64 * 1024


def _max_detail_bytes() -> int:
    raw = os.environ.get("FASTEN_MAX_DETAIL_BYTES", "").strip()
    if not raw:
        return _MAX_DETAIL_BYTES_DEFAULT
    try:
        n = int(raw)
    except ValueError:
        return _MAX_DETAIL_BYTES_DEFAULT
    return n if n > 0 else _MAX_DETAIL_BYTES_DEFAULT

def _truncated_marker(value: Any, size: int, cap: int) -> Any:
    """Replacement for an oversize value. A dict becomes a marker dict,
    anything else a marker string; the original is never returned."""
    marker = {
        "_truncated": True,
        "_truncated_bytes": size,
        "_max_detail_bytes": cap,
        "_summary": f"<truncated {size} bytes; cap {cap}>",
    }
    if isinstance(value, dict):
        return marker
    return marker["_summary"]


def _unredactable_marker(value: Any) -> Any:
    """Replacement for a value the core failed to redact (deep nesting,
    invalid utf-8). The original is never returned."""
    marker = {
        "_redact_failed": True,
        "_summary": "<unredactable>",
    }
    if isinstance(value, dict):
        return marker
    return marker["_summary"]


def _str_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _str_keys(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_str_keys(v) for v in value]
    return value


def _json_for_size(value: Any) -> str:
    """JSON text of a value json.dumps refused, for the size cap: keys and
    values it cannot encode go through str()."""
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return json.dumps(_str_keys(value), default=str)


_warned_no_core = False


def _warn_no_core(exc: OSError) -> None:
    """One line on stderr, once per process. A log call must not raise, so
    a closed or missing stderr is ignored."""
    global _warned_no_core
    if _warned_no_core:
        return
    _warned_no_core = True
    try:
        sys.stderr.write(
            f"fasten: {exc}; log values are replaced by <unredactable> until it loads\n")
    except Exception:  # noqa: BLE001  stderr is None under pythonw, or closed
        pass


# Structlog internals that are never redacted regardless of key name. Not
# "event": it is the message, and a secret can be in it, so the processor
# redacts it on its own.
_STRUCTLOG_SKIP = frozenset({
    "timestamp", "level", "logger", "_record", "_from_structlog",
})

# Only used for dicts with keys JSON cannot encode.
# The patterns use `$` for the end of the key. In Python `$` also matches
# before a final newline, so they are compiled with `\Z`, as the core reads
# them.
_KEY_PATTERNS = tuple(re.sub(r"\$$", r"\\Z", p) for p in _REDACT_PATTERNS)

_DEFAULT_KEY_RE: re.Pattern[str] = re.compile(
    r"(?i)(" + "|".join(_KEY_PATTERNS) + r")"
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
        # (name, pattern, repl) to (pattern, repl); the name is only a label.
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
            combined  = "|".join(_KEY_PATTERNS) + "|" + extra_esc
            self._key_re: re.Pattern[str] = re.compile(r"(?i)(" + combined + r")")
        else:
            self._key_re = _DEFAULT_KEY_RE

    def _redact_leaf(self, value: Any) -> Any:
        """Redact one value through the core with this Redactor's settings.
        It goes in a list, which has no keys, so only value shapes apply."""
        out = json.loads(self._fast_redact_json(json.dumps([value], default=str)))
        return out[0]

    def _redact_native(self, value: Any) -> Any:
        """Redact a value json.dumps cannot encode as it is: a dict with keys
        such as tuples, or a value such as datetime. Keys are kept; every
        part JSON can encode, with str() as the fallback, goes through the
        core with the same settings as redact()."""
        if isinstance(value, dict):
            if all(isinstance(k, str) for k in value):
                try:
                    in_json = json.dumps(value, default=str)
                except TypeError:  # a nested dict has a key JSON cannot encode
                    pass
                else:
                    return json.loads(self._fast_redact_json(in_json))
            result = {}
            for k, v in value.items():
                if isinstance(k, str) and self._key_re.search(k):
                    result[k] = self._replacement
                else:
                    result[k] = self._redact_native(v)
            return result
        if isinstance(value, (list, tuple)):
            return [self._redact_native(v) for v in value]
        return self._redact_leaf(value)

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
        """Return a redacted copy of a dict, list or scalar.

        Values over FASTEN_MAX_DETAIL_BYTES (default 64 KiB) are replaced by a
        truncation marker, and values the core fails on (e.g. nesting deeper
        than 128) by an ``<unredactable>`` marker, so emit() does not raise.
        The original value is never returned in either case.

        Raises OSError when libfasten_core can't be loaded.
        """
        native = False
        try:
            in_json = json.dumps(value)
            # json.dumps turns int keys into strings; keep them as they are.
            native = isinstance(value, dict) and any(not isinstance(k, str) for k in value)
        except (TypeError, ValueError):
            try:
                in_json = _json_for_size(value)
            except (TypeError, ValueError, RecursionError):  # e.g. a circular reference
                return _unredactable_marker(value)
            native = True
        cap = _max_detail_bytes()
        raw_bytes = len(in_json.encode("utf-8", errors="replace"))
        if raw_bytes > cap:
            return _truncated_marker(value, raw_bytes, cap)
        try:
            if native:
                return self._redact_native(value)
            return json.loads(self._fast_redact_json(in_json))
        except OSError:  # libfasten_core didn't load
            raise
        except Exception:  # noqa: BLE001  deep nesting or invalid utf-8
            return _unredactable_marker(value)

    def _redact_for_log(self, value: Any) -> Any:
        """redact() for a log line, which must not raise: when
        libfasten_core can't be loaded, the value becomes the unredactable
        marker and stderr gets one warning."""
        try:
            return self.redact(value)
        except OSError as exc:
            _warn_no_core(exc)
            return _unredactable_marker(value)

    def with_extra_keys(self, keys: Optional[list[str]]) -> "Redactor":
        """Copy of this Redactor with ``keys`` added to the key patterns."""
        if not keys:
            return self
        return Redactor(
            extra_keys=[*self._extra_keys, *keys],
            replacement=self._replacement,
            extra_value_patterns=[("", pat, repl) for pat, repl in self._extra_vp],
        )

    def as_structlog_processor(self) -> Callable[..., Any]:
        """Return a structlog processor that redacts event_dict, leaving
        structlog's own keys (timestamp, level, logger, ...) alone. The event
        gets the value-shape pass on its own, so an oversize payload does not
        drop it."""
        def _processor(logger_: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
            internals = {k: v for k, v in event_dict.items() if k in _STRUCTLOG_SKIP}
            payload   = {k: v for k, v in event_dict.items()
                         if k not in _STRUCTLOG_SKIP and k != "event"}
            if "event" in event_dict:
                # A list has no keys, so only value shapes apply.
                ev = self._redact_for_log([event_dict["event"]])
                internals["event"] = ev[0] if isinstance(ev, list) else ev
            redacted  = self._redact_for_log(payload)
            return {**internals, **redacted}
        return _processor


# Exceptions in a chain that describe_error() prints.
_MAX_CHAIN = 5


def _redact_text(exc: BaseException, redactor: Optional[Redactor]) -> str:
    try:
        text = str(exc)
    except Exception:  # noqa: BLE001
        return "<str failed>"
    try:
        out = (redactor or Redactor()).redact([text])
        msg = out[0] if isinstance(out, list) else out
    except Exception:  # noqa: BLE001
        msg = None
    return msg if isinstance(msg, str) else "<unredactable>"


def _frames(exc: BaseException) -> list[str]:
    try:
        return [f"  {f.filename}:{f.lineno} in {f.name}"
                for f in traceback.extract_tb(exc.__traceback__)]
    except Exception:  # noqa: BLE001
        return ["  <traceback failed>"]


def describe_error(exc: BaseException, redactor: Optional[Redactor] = None) -> str:
    """``type: message`` with the message redacted, then the traceback
    frames as ``file:line in function``, for ``exc`` and the exceptions it
    was raised from or during. No source lines or locals. A message the
    core can't redact is the unredactable marker. Never raises."""
    lines: list[str] = []
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen and len(seen) < _MAX_CHAIN:
        seen.add(id(cur))
        lines.append(f"{type(cur).__name__}: {_redact_text(cur, redactor)}")
        lines.extend(_frames(cur))
        if cur.__cause__ is not None:
            cur, link = cur.__cause__, "caused by"
        elif cur.__context__ is not None and not cur.__suppress_context__:
            cur, link = cur.__context__, "during handling of"
        else:
            cur = None
        if cur is not None:
            lines.append(link + ":")
    if cur is not None:
        lines.pop()     # the link to an exception not printed
        if id(cur) not in seen:
            lines.append(f"  ... (chain cut at {_MAX_CHAIN})")
    return "\n".join(lines)


def redacted_json(raw: Any, redactor: Optional[Redactor] = None) -> str:
    """A JSON payload, redacted, for a log line. Not JSON, or not
    redactable: a placeholder. Never raises."""
    try:
        value = json.loads(raw)
    except Exception:  # noqa: BLE001  not JSON, or nested too deep
        return "<not json>"
    try:
        return json.dumps((redactor or Redactor()).redact(value), default=str)
    except Exception:  # noqa: BLE001
        return "<unredactable>"
