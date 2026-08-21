"""FR1 retention — background purger for per-stream stores.

Spec §1 lists ``retention.api`` / ``retention.sys`` in FR1's body. The stream
stores already expose ``purge(before=...)`` (age-based delete backed by
``idx_{table}_ts``), but nothing in the library called it — hosted deployments
grew unbounded stream tables. This module is the driver.

Contract
========

- One background thread per configured stream (``api`` / ``sys``).
- Wakes every ``check_interval`` (default 1 h), computes ``cutoff = now - retention``,
  calls ``store.purge(before=cutoff_iso)``.
- Never raises on the caller's thread. Purge errors are logged via the
  drainer sys stream (``retention_purge_failed``) and the loop keeps
  running, so a transient database blip doesn't stop the purger from
  catching up on the next tick.
- Shutdown is cooperative: ``stop_event.set()`` on Engine reset / atexit
  makes the sleep wake early and the loop exit before the next purge.

Duration syntax
===============

A small, forgiving parser: ``"7d"``, ``"24h"``, ``"90m"``, ``"3600s"``.
No compound forms (``"1d12h"`` — reject). No negatives. Empty / None disables
retention on that stream.
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
    """Parse a duration string like ``"7d"`` / ``"24h"`` / ``"90m"`` / ``"3600s"``.

    Raises RetentionConfigError on anything else (empty, unknown unit,
    non-positive, compound). Returned timedelta is strictly positive."""
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
    """Cutoff = now - retention, stamped as a canonical UTC ISO string that
    matches the stream stores' comparison form."""
    return (now - retention).astimezone(timezone.utc).isoformat(timespec="milliseconds")


def start_purger(
    *,
    store: Any,
    stream: str,
    retention: timedelta,
    check_interval: timedelta = timedelta(hours=1),
    stop_event: Optional[threading.Event] = None,
    on_error: Optional[Callable[[str, Exception], None]] = None,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> threading.Thread:
    """Spawn a daemon thread that periodically purges rows older than
    ``retention`` from ``store``. Returns the started thread; the caller
    owns ``stop_event`` and must call ``stop_event.set()`` to shut it down.

    The first purge runs immediately (so operators see the effect on init
    without waiting a full interval), then every ``check_interval``."""
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
                cutoff = _cutoff_iso(now_fn(), retention)
                store.purge(before=cutoff)
            except Exception as e:  # noqa: BLE001
                # Never propagate — a transient DB blip must not stop the
                # loop. Log via the caller's on_error hook so the retention
                # miss lands in the sys stream (drainer_sys_log), not just
                # stderr, and shows up on /logs/sys under the operator's
                # existing monitoring.
                if on_error is not None:
                    try:
                        on_error(stream, e)
                    except Exception:  # noqa: BLE001
                        logger.exception("retention on_error callback raised")
                else:
                    logger.warning(
                        "fasten retention purge for stream %s failed: %s: %s",
                        stream, type(e).__name__, e,
                    )

    t = threading.Thread(target=_loop, name=f"fasten-retention-{stream}", daemon=True)
    t.start()
    return t
