"""
structlog processor shim — pushes every log event into rivet's syslog ring buffer.

Adopters add this to their shared processors list (before the renderer):

    from rivet.shim.structlog import make_rivet_processor

    structlog.configure(
        processors=[
            ...
            redact_secrets,
            make_rivet_processor(),   # ← push to rivet ring buffer
            renderer,
        ]
    )

The processor is a side-effect: it writes to rivet's ring buffer and then
returns event_dict unchanged so structlog continues its own pipeline.
It does NOT write to stdout (no double-output).

If rivet is not initialised (init() not yet called), the processor is a no-op.
"""
from __future__ import annotations

from typing import Any, Callable


def make_rivet_processor() -> Callable[[Any, str, dict[str, Any]], dict[str, Any]]:
    """Return a structlog processor that pushes events to rivet's syslog buffer."""

    def _processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        try:
            from rivet.emit import _get_stdout
            transport = _get_stdout()
            if transport is None:
                return event_dict

            # Build a clean syslog row — exclude structlog internals
            _skip = {"_record", "_from_structlog"}
            row = {k: v for k, v in event_dict.items() if k not in _skip}

            # Normalise level key (structlog uses "log_level" in some configs)
            if "log_level" in row and "level" not in row:
                row["level"] = row.pop("log_level")

            transport.push_syslog(row)
        except Exception:
            pass  # never let observability break the app
        return event_dict

    return _processor
