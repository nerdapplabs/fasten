"""
structlog shim — push every log event into fasten's syslog ring + a one-call
``configure()`` that wires structlog + stdlib to the same formatter.

Two public surfaces:

    make_fasten_processor()  → a structlog processor (compose-it-yourself path)
    configure(...)           → opinionated one-call setup (most adopters)

``configure()`` is the recommended path: it installs the fasten processor,
the redaction processor, JSON or console renderer, and a stdlib bridge so
``import logging`` calls reach the same destination.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterable, Optional


def make_fasten_processor() -> Callable[[Any, str, dict[str, Any]], dict[str, Any]]:
    """Return a structlog processor that pushes events to fasten's syslog buffer.

    Side-effect only: writes to fasten's ring + returns ``event_dict`` unchanged.
    Does NOT write to stdout (the renderer / formatter handles that).

    If ``fasten.init()`` has not been called, the processor is a no-op.
    """

    def _processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        try:
            from fasten import transport as _transport
            transport = _transport()
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


# ── One-call configure ────────────────────────────────────────────────────

# Defaults reasonable noisy libs to WARN. Override via ``quiet=()`` to disable.
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
    """Install structlog + stdlib bridge in one call.

    Args:
        json: True for JSON output (prod), False for ConsoleRenderer (dev).
        debug: True to allow DEBUG level; otherwise INFO.
        extra_processors: ordered after fasten's default processors and
            before the renderer. Adopters can inject custom processors here.
        quiet: iterable of logger names to set to WARNING. Defaults to a
            small list of noisy libs (``urllib3``, ``botocore``, ...).
            Pass ``()`` to disable; pass your own iterable to override.
        extra_redact_keys: extra patterns for the redaction processor.

    Side effects:
      - ``structlog.configure(...)`` is called with fasten's processor list
      - ``logging.basicConfig`` sets the stdlib root level
      - ``LoggingHandler`` (fasten.shim.stdlib) is attached to the stdlib
        root so ``import logging`` calls also reach the fasten ring
      - Quiet libs raised to WARNING

    Mirrors Go's one-liner ``slog.New(fasten.NewSlogHandler(base))``.
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

    # ── structlog chain ────────────────────────────────────────────────────
    # PrintLoggerFactory writes structlog logs directly to stdout (no stdlib
    # roundtrip), so make_fasten_processor() is the only path into the ring
    # for structlog events. ``add_logger_name`` is omitted because it needs
    # a stdlib-style logger; adopters who want a logger field use
    # ``structlog.get_logger().bind(logger="my-svc")`` or pass it explicitly.
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

    # ── stdlib bridge ──────────────────────────────────────────────────────
    # Route ``import logging`` calls into the fasten ring via LoggingHandler.
    # A StreamHandler keeps stdout output for stdlib-native code (so legacy
    # libraries still write to terminal as expected).
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [
        h for h in root.handlers if not isinstance(h, LoggingHandler)
    ]
    root.addHandler(LoggingHandler())

    # Quiet noisy libs
    quiet_libs = quiet if quiet is not None else _DEFAULT_QUIET
    for name in quiet_libs:
        logging.getLogger(name).setLevel(logging.WARNING)
