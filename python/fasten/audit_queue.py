"""
P1-15: bounded audit queue + background drainer with exponential backoff.

When ``fasten.init(audit_store_failure_strategy="queue")`` is set (the
v1.0 default), ``emit()`` pushes audit rows onto a bounded in-memory queue
and a background thread drains them into the durable store. Store failures
trigger exponential backoff (with jitter) instead of raising on the
request path.

The drainer self-reports state transitions to the sys stream so adopters
see audit-pipeline health through the same channel they already monitor:

    {"shape":"sys","level":"warn","event":"audit_drain_failed", ...}
    {"shape":"sys","level":"error","event":"audit_drain_degraded", ...}
    {"shape":"sys","level":"warn","event":"audit_queue_high_water", ...}
    {"shape":"sys","level":"error","event":"audit_queue_near_full", ...}
    {"shape":"sys","level":"info","event":"audit_drain_recovered", ...}

See `fasten-cloud/issues/P1-15-audit-store-failure-handling.md` for the
full design + acceptance criteria.
"""
from __future__ import annotations

import collections
import queue
import random
import threading
import time

from typing import Any, Callable, Optional


class AuditStoreError(RuntimeError):
    """Raised by ``emit()`` in ``raise`` mode when the store insert fails.

    Wraps the underlying store-specific exception so callers can catch a
    single fasten-namespaced type without depending on sqlite3 / psycopg /
    sqlalchemy types.
    """


# ── Drainer ────────────────────────────────────────────────────────────────


class _AuditQueueDrainer:
    """Single bounded queue + single drainer thread.

    ``put(row)`` blocks if the queue is full — most honest semantic for
    audit (don't silently drop). Adopters who can't tolerate the block
    bump ``capacity``.
    """

    # Backoff schedule cap — 60 s. Initial 100 ms doubles each consecutive
    # failure. Jitter ±20 % avoids thundering-herd on store recovery.
    _BACKOFF_FLOOR_MS = 100
    _BACKOFF_CEIL_MS = 60_000

    # Sys-stream report thresholds. 50 % = warn, 80 % = error.
    _HIGH_WATER_WARN_PCT = 0.50
    _HIGH_WATER_ERR_PCT = 0.80

    # Drainer reports "degraded" once retry_count crosses this floor.
    _DEGRADED_AFTER = 5

    # Default max insert attempts before a row is dead-lettered.
    _MAX_ATTEMPTS = 50

    def __init__(
        self,
        store: Any,
        sys_log: Callable[[str, str, dict[str, Any]], None],
        *,
        capacity: int = 100,
        retry_initial_ms: int = 100,
        retry_max_ms: int = 60_000,
        retry_jitter: bool = True,
        max_attempts: int = 50,
    ) -> None:
        self._store = store
        # sys_log(level, event, fields) — non-recursive: writes to ring +
        # stdout only, never through emit() / the audit store.
        self._sys_log = sys_log
        self._capacity = capacity
        self._retry_initial_ms = retry_initial_ms
        self._retry_max_ms = retry_max_ms
        self._retry_jitter = retry_jitter
        self._max_attempts = max_attempts

        # Capacity is enforced by a semaphore over (queued + in-flight) rows
        # rather than just queue depth. A row the drainer is currently
        # retrying still occupies an audit-pipeline slot — emit() must
        # block until that retry succeeds, otherwise an outage with even a
        # single in-flight row makes "capacity" a lie.
        self._q: queue.Queue[Any] = queue.Queue()
        self._slots = threading.Semaphore(capacity)
        # Parallel counter for occupied slots — incremented after a slot
        # is acquired, decremented before it is released. Used by
        # _used_slots() / stats() / flush() so callers don't have to read
        # threading.Semaphore._value (a CPython implementation detail).
        # All access goes through _stats_lock for consistency with the
        # rest of the stats fields.
        self._used_slots_count = 0
        self._stop = threading.Event()
        self._stats_lock = threading.Lock()

        # Stats — readable via queue_stats()
        self._high_water = 0
        self._drained_total = 0
        self._retry_count = 0
        self._in_backoff_until = 0.0  # monotonic ts; 0 = not in backoff
        self._last_error: Optional[str] = None
        self._failure_burst_started_at: Optional[float] = None
        # In-flight = row popped from queue but not yet inserted. Tracked so
        # flush() doesn't return prematurely while a slow insert is mid-call.
        self._in_flight = 0
        # Dead-letter queue: bounded ring of rows that exceeded max_attempts.
        # Oldest falls off automatically (maxlen). Access under _stats_lock.
        self._dlq: collections.deque = collections.deque(maxlen=10)
        self._dead_lettered_total = 0

        # Threshold debouncing — only emit transition once per crossing.
        self._warn_high_water_emitted = False
        self._err_high_water_emitted = False
        self._degraded_emitted = False

        self._thread = threading.Thread(
            target=self._run, name="fasten-audit-drainer", daemon=True
        )
        self._thread.start()

    # ── Public API ─────────────────────────────────────────────────────────

    def put(self, row: Any) -> None:
        """Push a row onto the queue. Blocks if all capacity slots are taken
        (queued + in-flight retry combined). If the drainer has been
        signalled to stop (re-init swap or shutdown), emit
        ``audit_drain_abandoned`` and return without enqueueing — the
        row would otherwise stall on a semaphore the drainer will
        never service."""
        if self._stop.is_set():
            self._sys_log(
                "error",
                "audit_drain_abandoned",
                {"reason": "drainer_stopped",
                 "row_id": getattr(row, "id", None)},
            )
            return
        # Block until a slot frees up. The drainer releases the permit only
        # on successful insert (or shutdown abandon), so emit() blocks while
        # an in-flight row is in retry-backoff — capacity really means
        # "max audit work pending", not just "max queued".
        self._slots.acquire()
        self._q.put(row)
        cap = self._capacity
        with self._stats_lock:
            self._used_slots_count += 1
            used = self._used_slots_count
            if used > self._high_water:
                self._high_water = used
        # Threshold sys-log fires AFTER the row is pending so the warn lands
        # the moment used capacity crosses 50 % / 80 %, not the emit-after.
        if cap > 0:
            pct = used / cap
            if pct >= self._HIGH_WATER_ERR_PCT and not self._err_high_water_emitted:
                self._err_high_water_emitted = True
                self._sys_log(
                    "error",
                    "audit_queue_near_full",
                    {"depth": used, "capacity": cap},
                )
            elif pct >= self._HIGH_WATER_WARN_PCT and not self._warn_high_water_emitted:
                self._warn_high_water_emitted = True
                self._sys_log(
                    "warn",
                    "audit_queue_high_water",
                    {"depth": used, "capacity": cap},
                )
            elif pct < self._HIGH_WATER_WARN_PCT:
                # Reset watermarks once depth recovers below 50 % so a new
                # surge re-emits the leading-indicator warn.
                self._warn_high_water_emitted = False
                self._err_high_water_emitted = False

    def _used_slots(self) -> int:
        # Reads the parallel counter (kept in sync with semaphore
        # acquire/release) instead of poking at Semaphore._value, which
        # is a CPython implementation detail.
        with self._stats_lock:
            return self._used_slots_count

    def _release_slot(self) -> None:
        """Release a slot permit + decrement the parallel counter atomically.

        Decrement BEFORE the semaphore release so a put() that wakes up on
        the freed permit reads a consistent counter. The reverse order
        leaves a brief window where another emit() acquires a permit but
        sees the OLD count, briefly over-reporting `used`.
        """
        with self._stats_lock:
            self._used_slots_count -= 1
        self._slots.release()

    def stats(self) -> dict[str, Any]:
        """Snapshot of queue + drainer state. See P1-15 spec for fields.

        ``depth`` is total occupied capacity (queued + in-flight retry)
        because that is what determines whether the next emit() blocks.
        """
        with self._stats_lock:
            now = time.monotonic()
            in_backoff = max(0.0, self._in_backoff_until - now)
            return {
                "depth": self._used_slots_count,
                "capacity": self._capacity,
                "high_water": self._high_water,
                "drained_total": self._drained_total,
                "retry_count_active": self._retry_count,
                "in_backoff_seconds": round(in_backoff, 3),
                "last_error": self._last_error,
                "dead_lettered_total": self._dead_lettered_total,
                "dead_letter_depth": len(self._dlq),
                "capacity_semantics": "block",
            }

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the drainer to stop and wait briefly for it to exit.

        Pending rows in the queue are not abandoned — the drainer attempts
        a final pass before returning. Backoff sleeps are interrupted.
        """
        self._stop.set()
        self._thread.join(timeout=timeout)

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until every row pending AT CALL TIME reaches the store
        (or shutdown abandon), or the timeout elapses. Returns True iff
        drained.

        Snapshot semantics: flush() targets the rows that exist when
        flush() is invoked. Concurrent emit() calls during the wait do
        not extend the flush horizon, otherwise a steady incoming rate
        ≥ drain rate would keep flush() blocked until timeout even
        though every row pending at call time was successfully drained.

        Implementation: snapshot `drained_total + used_slots` under the
        stats lock at call time → that is the value `drained_total` must
        reach for everything-pending-now to have drained. Any row added
        after the snapshot only bumps `drained_total` AFTER our target
        is met, so it cannot block the flush.
        """
        with self._stats_lock:
            target = self._drained_total + self._used_slots_count
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._stats_lock:
                if self._drained_total >= target:
                    return True
            time.sleep(0.01)
        with self._stats_lock:
            return self._drained_total >= target

    # ── Drainer loop ───────────────────────────────────────────────────────

    def _run(self) -> None:
        # The drainer always honours the stop event. Even when the queue is
        # empty we use a short get-with-timeout so stop() returns promptly.
        while not self._stop.is_set():
            try:
                row = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            self._drain_one(row)

        # Stop signalled — best-effort drain of remaining rows so atexit
        # doesn't lose them. We honour backoff but skip the long sleep so
        # process shutdown isn't held up by a 60 s wait.
        while True:
            try:
                row = self._q.get_nowait()
            except queue.Empty:
                return
            self._drain_one(row, in_shutdown=True)

    def _drain_one(self, row: Any, *, in_shutdown: bool = False) -> None:
        # in_flight tracks "popped from queue but not yet inserted" so flush()
        # can't return prematurely while a slow insert is mid-call. The
        # capacity semaphore permit travels with the row from emit() →
        # queue → drainer; we release it only on successful insert (or
        # shutdown abandonment), so emit() blocks while a row is in retry.
        with self._stats_lock:
            self._in_flight += 1
        slot_released = False
        attempt = 0
        try:
            while True:
                attempt += 1
                try:
                    self._store.insert(row)
                except Exception as e:  # noqa: BLE001 — drainer must catch all
                    if attempt >= self._max_attempts:
                        # Row cannot be inserted after max_attempts. Move it to
                        # the DLQ ring so the pipeline makes progress on others.
                        self._on_dead_letter(row, attempt, e)
                        self._release_slot()
                        slot_released = True
                        return
                    self._on_failure(e)
                    if in_shutdown:
                        # Process is exiting; one attempt is enough.
                        self._release_slot()
                        slot_released = True
                        return
                    if self._wait_backoff():
                        # stop signalled mid-backoff — release slot.
                        self._release_slot()
                        slot_released = True
                        return
                    continue

                self._on_success()
                self._release_slot()
                slot_released = True
                return
        finally:
            with self._stats_lock:
                self._in_flight -= 1
            if not slot_released:
                # Defensive: guarantee no permit leak under unexpected exits.
                self._release_slot()

    def _on_failure(self, err: Exception) -> None:
        msg = f"{type(err).__name__}: {err}"
        first_failure = False
        crossed_degraded = False
        with self._stats_lock:
            if self._retry_count == 0:
                first_failure = True
                self._failure_burst_started_at = time.monotonic()
            self._retry_count += 1
            self._last_error = msg
            if (
                self._retry_count >= self._DEGRADED_AFTER
                and not self._degraded_emitted
            ):
                crossed_degraded = True
                self._degraded_emitted = True

        if first_failure:
            self._sys_log("warn", "audit_drain_failed", {"error": msg})
        if crossed_degraded:
            stats = self.stats()
            self._sys_log(
                "error",
                "audit_drain_degraded",
                {
                    "retry_count": stats["retry_count_active"],
                    "in_backoff_seconds": stats["in_backoff_seconds"],
                    "last_error": msg,
                },
            )

    def _on_success(self) -> None:
        recovered_after: Optional[float] = None
        with self._stats_lock:
            if self._retry_count > 0 and self._failure_burst_started_at is not None:
                recovered_after = time.monotonic() - self._failure_burst_started_at
            self._retry_count = 0
            self._in_backoff_until = 0.0
            self._failure_burst_started_at = None
            self._last_error = None
            self._degraded_emitted = False
            self._drained_total += 1

        if recovered_after is not None:
            self._sys_log(
                "info",
                "audit_drain_recovered",
                {"recovery_after_seconds": round(recovered_after, 3)},
            )

    def _on_dead_letter(self, row: Any, attempt: int, err: Exception) -> None:
        msg = f"{type(err).__name__}: {err}"
        row_id = getattr(row, "id", None)
        with self._stats_lock:
            self._dlq.appendleft(row)
            self._dead_lettered_total += 1
            self._retry_count = 0
            self._last_error = msg
        self._sys_log("error", "audit_drain_dead_letter", {
            "row_id": row_id,
            "attempt_count": attempt,
            "last_error": msg,
        })

    def _wait_backoff(self) -> bool:
        """Sleep the current backoff window; return True if stop was signalled."""
        with self._stats_lock:
            n = self._retry_count
        delay_ms = min(
            self._retry_initial_ms * (2 ** max(0, n - 1)),
            self._retry_max_ms,
        )
        if self._retry_jitter:
            jitter = delay_ms * 0.2
            delay_ms = max(0.0, delay_ms + random.uniform(-jitter, jitter))
        delay_s = delay_ms / 1000.0

        with self._stats_lock:
            self._in_backoff_until = time.monotonic() + delay_s

        # stop().wait returns True iff the event was set during the wait,
        # so the drainer cuts a 60 s sleep short when shutdown is requested.
        return self._stop.wait(timeout=delay_s)


# ── Backward-compat shims ─────────────────────────────────────────────────────
#
# The module-level singleton (``_drainer``, ``install``, ``uninstall``, …)
# has been replaced by ``Engine`` (see ``fasten/engine.py``).  These shims
# delegate to the default Engine so existing call sites (tests, reader,
# conftest) continue to work without modification.


def _default_engine():
    from .emit import _default
    return _default


def install(
    *,
    store: Any,
    sys_log: Callable[[str, str, dict[str, Any]], None],
    capacity: int,
    retry_initial_ms: int,
    retry_max_ms: int,
    retry_jitter: bool,
    max_attempts: int = 50,
) -> _AuditQueueDrainer:
    eng = _default_engine()
    eng._install_drainer(
        store=store,
        capacity=capacity,
        retry_initial_ms=retry_initial_ms,
        retry_max_ms=retry_max_ms,
        retry_jitter=retry_jitter,
        max_attempts=max_attempts,
    )
    return eng._drainer  # type: ignore[return-value]


def uninstall() -> None:
    """Stop the default Engine's drainer (test helper)."""
    _default_engine()._uninstall_drainer()


def active() -> Optional[_AuditQueueDrainer]:
    """Return the default Engine's active drainer, if any."""
    return _default_engine()._drainer


def queue_stats() -> Optional[dict[str, Any]]:
    """Snapshot of queue + drainer state. None when raise mode is active."""
    return _default_engine().queue_stats()


def flush(timeout: float = 5.0) -> bool:
    """Block until pending rows drain. Delegates to the default Engine."""
    return _default_engine().flush(timeout=timeout)


def _mark_init() -> None:
    pass  # last_init_at now lives on Engine; call is a no-op here.


def last_init_at():
    return _default_engine().last_init_at()
