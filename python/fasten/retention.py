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
    """Cutoff = now - retention, stamped in the canonical form so the
    lexicographic compare against the stream stores' `timestamp` column
    agrees byte-for-byte with the writer format (spec §4.3)."""
    from .canonical_ts import canonical_ts
    return canonical_ts(now - retention)


def start_purger(
    *,
    store: Any,
    stream: str,
    # None means REDACTION-ONLY: tick the PII horizon but never age-delete.
    # That is the audit stream's mode — removing a row from a hash-chained
    # stream is the tampering signature verify_chain exists to detect (spec
    # §7.1), so the audit store must never be handed an age purge.
    retention: Optional[timedelta] = None,
    # Shorter horizon for codes carrying personal data. None keeps the old
    # behaviour (age-only purge). When set, every tick ALSO redacts rows whose
    # code is in codes.pii_codes() and is older than this — the thing that
    # makes pii_in_detail=True mean something at runtime instead of being a
    # comment that only forces retention_class.
    pii_retention: Optional[timedelta] = None,
    # How to redact. Defaults to store.redact_expired, which destroys the data
    # but emits nothing. Engine passes Engine.redact_expired so the spec §7.2
    # AUDIT_ROW_REDACTED row is written — without it an honest erasure and a
    # quiet redaction are indistinguishable, which is most of the reason to
    # redact rather than DELETE.
    redact_fn: Optional[Callable[..., Any]] = None,
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
    if retention is None and pii_retention is None:
        # A thread that ticks forever and does nothing is a configuration
        # error, not a default. Fail at the call, not silently at 3am.
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
                # now_fn is caller-supplied; a raise here must not kill the
                # thread any more than a store blip does.
                logger.exception("fasten retention now_fn raised")
                continue

            def _report(label: str, e: BaseException) -> None:
                """Never propagate — a transient DB blip must not stop the
                loop. Report via the caller's on_error hook so the miss lands
                in the sys stream (drainer_sys_log), not just stderr, and
                shows up on /logs/sys under existing monitoring."""
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

            # Two horizons, two try blocks, two labels: a shared try let a
            # redaction failure skip the age purge, under one error label.
            # PII runs first — its rows sit mid-chain, where only redaction is
            # safe; the age purge below only ever removes a prefix.
            if pii_retention is not None:
                try:
                    redact = redact_fn or getattr(store, "redact_expired", None)
                    if not callable(redact):
                        # Configured but impossible — don't do that silently.
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

            # retention is None for the audit stream: redact, never delete.
            if retention is not None:
                try:
                    # A datetime: both store families take one and
                    # canonicalise internally, so there is one representation.
                    store.purge(before=now - retention)
                except Exception as e:  # noqa: BLE001
                    _report(f"{stream}/age-purge", e)

    t = threading.Thread(target=_loop, name=f"fasten-retention-{stream}", daemon=True)
    t.start()
    return t
