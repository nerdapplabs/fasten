"""
stdlib logging bridge — push every ``import logging`` record into fasten's
syslog ring + apply secret redaction.

Without this, code that uses ``logging.getLogger("foo").info(...)`` writes
to whatever stdlib handler is configured but never reaches fasten's ring,
so ``GET /logs/sys`` queries miss it. Most upstream library code uses
stdlib logging — adopters don't get to choose.

Usage standalone (when not using ``fasten.shim.structlog.configure()``):

    import logging
    from fasten.shim.stdlib import LoggingHandler

    logging.getLogger().addHandler(LoggingHandler())

Auto-installed by ``fasten.shim.structlog.configure()``.

Mirrors Go's ``fasten.NewSlogHandler(base)`` — every log record reaches
the same destination regardless of which logging library produced it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..canonical_ts import canonical_ts

# Records originating from fasten itself are tagged with this attribute on
# the LogRecord so the handler can skip them and avoid recursion. fasten's
# own ``log._emit`` falls back to stdlib logging pre-init().
_FASTEN_RECORD_TAG = "_fasten_internal"


class LoggingHandler(logging.Handler):
    """Push every stdlib ``LogRecord`` into fasten's syslog ring buffer.

    The handler is intentionally side-effect-only: it does NOT write to
    stdout. The adopter's existing stdlib handlers (StreamHandler,
    FileHandler, etc.) keep their stdout/file behaviour. fasten's ring is
    the addition.

    If ``fasten.init()`` has not been called, the handler is a no-op.
    """

    def emit(self, record: logging.LogRecord) -> None:  # noqa: A003
        try:
            # Recursion guard: skip records emitted by fasten itself
            # (its ``log._emit`` falls back to stdlib pre-init).
            if getattr(record, _FASTEN_RECORD_TAG, False):
                return

            from fasten import redactor as _redactor
            from fasten import transport as _transport

            transport = _transport()
            if transport is None:
                return

            # Format the message and pull a flat row out of the record.
            # Skip stdlib internals; carry adopter-supplied ``extra`` fields.
            try:
                message = record.getMessage()
            except Exception:
                message = str(record.msg)

            row: dict[str, Any] = {
                "level": record.levelname.lower(),
                "event": message,
                "logger": record.name,
                "timestamp": canonical_ts(
                    datetime.fromtimestamp(record.created, tz=timezone.utc)
                ),
            }

            # Pull the ambient request_id if any.
            try:
                from fasten import current_request_id
                rid = current_request_id()
                if rid:
                    row["request_id"] = rid
            except Exception:
                pass

            # Adopter-supplied extras (logger.info("msg", extra={"k": "v"}))
            # are scattered across LogRecord attributes; copy the ones that
            # aren't stdlib-reserved.
            _stdlib_attrs = {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process",
                "getMessage", "asctime",
            }
            for k, v in record.__dict__.items():
                if k in _stdlib_attrs or k.startswith("_") or k in row:
                    continue
                row[k] = v

            # Apply redaction to scrub secrets from any extras.
            row = _redactor().redact(row)

            transport.push_syslog(row)
        except Exception:
            # Never let observability break the app.
            pass
