"""Background retention threads.

Each thread wakes every ``check_interval`` (default 1h). It deletes stream
rows older than ``retention`` with ``store.purge(before=...)`` and, if a PII
horizon is set, redacts audit rows of pii codes. Errors are reported through
``on_error`` and the loop carries on. Setting ``stop_event`` stops the thread.

Durations are a positive integer and one unit: ``"7d"``, ``"24h"``, ``"90m"``,
``"3600s"``.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("fasten.retention")


class RetentionConfigError(ValueError):
    """Raised for a malformed retention duration string."""


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(s: str) -> timedelta:
    """Parse ``"7d"``, ``"24h"``, ``"90m"`` or ``"3600s"`` into a positive
    timedelta. Raises RetentionConfigError for anything else."""
    if not s or not isinstance(s, str):
        raise RetentionConfigError(f"retention duration must be a non-empty string (got {s!r})")
    token = s.strip().lower()
    if len(token) < 2 or token[-1] not in _UNITS:
        raise RetentionConfigError(
            f"retention duration {s!r}: unit must be one of s/m/h/d (e.g. '7d', '24h')"
        )
    try:
        n = int(token[:-1])
    except ValueError as e:
        raise RetentionConfigError(
            f"retention duration {s!r}: expected integer before the unit"
        ) from e
    if n <= 0:
        raise RetentionConfigError(f"retention duration {s!r}: must be positive")
    return timedelta(seconds=n * _UNITS[token[-1]])


def _cutoff_iso(now: datetime, retention: timedelta) -> str:
    """``now - retention`` as a canonical timestamp string."""
    from .canonical_ts import canonical_ts
    return canonical_ts(now - retention)


def start_purger(
    *,
    store: Any,
    stream: str,
    # None means no deletes, only PII redaction. Used for the audit store,
    # where deleting rows would break the chain (spec 7.1).
    retention: Optional[timedelta] = None,
    # Rows with a code in codes.pii_codes() older than this are redacted.
    pii_retention: Optional[timedelta] = None,
    # Defaults to store.redact_expired, which writes no record. Engine passes
    # Engine.redact_expired so AUDIT_ROW_REDACTED rows are written (spec 7.2).
    redact_fn: Optional[Callable[..., Any]] = None,
    check_interval: timedelta = timedelta(hours=1),
    stop_event: Optional[threading.Event] = None,
    on_error: Optional[Callable[[str, Exception], None]] = None,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> threading.Thread:
    """Start a daemon thread that purges or redacts ``store`` once right
    away, then every ``check_interval``. Set ``stop_event`` to stop it.

    Raises ValueError if neither ``retention`` nor ``pii_retention`` is set.
    """
    if retention is None and pii_retention is None:
        raise ValueError(
            "fasten.start_purger: at least one of retention (age purge) or "
            "pii_retention (PII redaction) must be set"
        )
    if stop_event is None:
        stop_event = threading.Event()

    def _loop() -> None:
        first = True
        while True:
            if not first:
                if stop_event.wait(check_interval.total_seconds()):
                    return
            first = False
            try:
                now = now_fn()
            except Exception:  # noqa: BLE001
                logger.exception("fasten retention now_fn raised")
                continue

            def _report(label: str, e: BaseException) -> None:
                """Report through on_error (the Engine logs it to the sys
                stream), or the module logger if there is none."""
                if on_error is not None:
                    try:
                        on_error(label, e)  # type: ignore[arg-type]
                    except Exception:  # noqa: BLE001
                        logger.exception("retention on_error callback raised")
                else:
                    logger.warning(
                        "fasten retention %s failed: %s: %s",
                        label, type(e).__name__, e,
                    )

            # Separate try blocks so a redaction failure does not skip the
            # purge.
            if pii_retention is not None:
                try:
                    redact = redact_fn or getattr(store, "redact_expired", None)
                    if not callable(redact):
                        logger.warning(
                            "fasten retention [%s]: a PII horizon is configured "
                            "but the store exposes no redact_expired — personal "
                            "data is NOT being redacted. Use an audit store that "
                            "implements spec §7.1, or clear the PII horizon.",
                            stream,
                        )
                    else:
                        from .codes import pii_codes
                        codes_ = pii_codes()
                        if codes_:
                            redact(before=now - pii_retention, codes=codes_)
                except Exception as e:  # noqa: BLE001
                    _report(f"{stream}/pii-redaction", e)

            if retention is not None:
                try:
                    store.purge(before=now - retention)
                except Exception as e:  # noqa: BLE001
                    _report(f"{stream}/age-purge", e)

    t = threading.Thread(target=_loop, name=f"fasten-retention-{stream}", daemon=True)
    t.start()
    return t
