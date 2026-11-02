"""structlog integration.

``configure()`` sets up structlog with the fasten and redaction processors, a
JSON or console renderer, and the stdlib bridge. ``make_fasten_processor()``
returns just the processor, for an existing structlog setup.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterable, Optional


def make_fasten_processor() -> Callable[[Any, str, dict[str, Any]], dict[str, Any]]:
    """Return a structlog processor that pushes each event to fasten's sys
    stream and returns ``event_dict`` unchanged. Does nothing before init()."""

    def _processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        try:
            from fasten import transport as _transport
            transport = _transport()
            if transport is None:
                return event_dict

            # Drop structlog's internal keys.
            _skip = {"_record", "_from_structlog"}
            row = {k: v for k, v in event_dict.items() if k not in _skip}

            # Some structlog configs use "log_level".
            if "log_level" in row and "level" not in row:
                row["level"] = row.pop("log_level")

            transport.push_syslog(row)
        except Exception:
            pass  # never let observability break the app
        return event_dict

    return _processor


# Loggers set to WARNING by configure() unless quiet= is given.
_DEFAULT_QUIET = (
    "urllib3",
    "botocore",
    "boto3",
    "asyncio",
)


def configure(
    *,
    json: bool = True,
    debug: bool = False,
    extra_processors: Optional[Iterable[Callable]] = None,
    quiet: Optional[Iterable[str]] = None,
    extra_redact_keys: Optional[list[str]] = None,
) -> None:
    """Configure structlog and the stdlib bridge.

    Args:
        json: True for JSON output (prod), False for ConsoleRenderer (dev).
        debug: True to allow DEBUG level; otherwise INFO.
        extra_processors: ordered after fasten's default processors and
            before the renderer. Adopters can inject custom processors here.
        quiet: iterable of logger names to set to WARNING. Defaults to a
            small list of noisy libs (``urllib3``, ``botocore``, ...).
            Pass ``()`` to disable; pass your own iterable to override.
        extra_redact_keys: extra patterns for the redaction processor.

    Calls ``structlog.configure()``, sets the root logger's level, attaches
    one ``LoggingHandler`` to the root logger (replacing any earlier one) and
    sets the ``quiet`` loggers to WARNING.
    """
    try:
        import structlog
    except ImportError as e:
        raise RuntimeError(
            "fasten.shim.structlog.configure() requires structlog; "
            "install with: pip install structlog"
        ) from e

    from fasten import redactor as _redactor
    from fasten.shim.stdlib import LoggingHandler

    level = logging.DEBUG if debug else logging.INFO

    # PrintLoggerFactory writes straight to stdout without stdlib logging, so
    # make_fasten_processor() is how structlog events reach fasten.
    # add_logger_name is left out because it needs a stdlib logger; bind a
    # logger field instead.
    processors: list[Callable] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _redactor().as_structlog_processor(),
        make_fasten_processor(),
    ]
    if extra_processors:
        processors.extend(extra_processors)

    renderer = (
        structlog.processors.JSONRenderer()
        if json
        else structlog.dev.ConsoleRenderer(colors=True)
    )
    processors.append(renderer)

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Send stdlib logging to fasten too. Existing handlers are kept.
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [
        h for h in root.handlers if not isinstance(h, LoggingHandler)
    ]
    root.addHandler(LoggingHandler())

    quiet_libs = quiet if quiet is not None else _DEFAULT_QUIET
    for name in quiet_libs:
        logging.getLogger(name).setLevel(logging.WARNING)
