# Drainer conformance spec

**Version:** 1.1  
**Date:** 2026-05-14  
**Status:** Normative — all SDK drainer implementations MUST conform.

---

## Purpose

All SDKs expose the same bounded-queue / exponential-backoff / sys-event
drainer surface to adopters.  The drainer implementation is provided by
the shared `fasten-core` C ABI (`libfasten_core.so` / `.dylib`).
Python, Go, Swift, and C++ bind to it via FFI (ctypes / cgo / Swift's
C interop / `extern "C"`); Rust implements it natively as the
authoritative reference.  JS still runs its own in-process drainer loop
(migration tracked in P1-26).

This document is the single source of truth for the externally visible
drainer contract.  When an SDK deviates from it, the spec wins.

Each SDK's test suite SHOULD include the test vectors in §7 to prevent
silent re-divergence.

---

## §1 Concepts

**Queue** — a bounded in-memory FIFO that holds audit `Row` objects
awaiting durable insertion.

**Drainer thread** — a single long-lived background thread (goroutine /
Worker thread) that pops rows from the queue and calls `store.insert(row)`.

**Slot** — one unit of capacity.  A slot is _occupied_ from the moment
`put()` acquires it until `store.insert` succeeds (or the row is
dead-lettered / abandoned).  This means a row in retry backoff still
occupies a slot; `capacity` therefore represents the maximum number of
rows in-flight across the whole audit pipeline, not just queue depth.

**`depth`** — the count of occupied slots at a given instant
(`queued + in-flight`).

**Backoff window** — the current sleep duration the drainer observes
between consecutive failed insert attempts.  Starts at `retry_initial`
(default 100 ms), doubles on each failure, caps at `retry_max`
(default 60 s), with optional ±20 % jitter.

---

## §2 Configuration parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `capacity` | int | 100 | Maximum occupied slots (queued + in-flight) |
| `retry_initial` | duration | 100 ms | First backoff window |
| `retry_max` | duration | 60 s | Maximum backoff window |
| `retry_jitter` | bool | true | ±20 % uniform jitter on each window |
| `max_attempts` | int | 50 | Insert attempts before dead-lettering a row |

---

## §3 State machine

```
                        ┌──────────────────────────────────────────────────────┐
  emit()                │                 DRAINER THREAD                        │
  ─────                 │                                                        │
  [stop set]──►emit abandons (audit_drain_abandoned)                            │
                        │                                                        │
  [slot free] ──acquire─►──────────────► pop row from queue                    │
  [slot full] ──block──►                      │                                 │
  (unblocks when        │                      ▼                                │
   slot is released)    │              call store.insert(row)                   │
                        │                      │                                │
                        │          ┌───────────┴────────────┐                  │
                        │          │ success                 │ failure          │
                        │          ▼                         ▼                  │
                        │    _on_success()           attempt < max_attempts?    │
                        │    release slot                     │                 │
                        │    (→ HEALTHY                  yes  │  no             │
                        │     if recovering)              │   │                 │
                        │                                 ▼   ▼                 │
                        │                         _on_failure()  _on_dead_letter()│
                        │                         wait_backoff()  release slot  │
                        │                         (→ retry)    (dead-letter)    │
                        └──────────────────────────────────────────────────────┘
```

### States

| State | Entry condition | Sys event emitted |
|---|---|---|
| **HEALTHY** | Initial; or `retry_count` drops to 0 after a success | `audit_drain_recovered` (only when recovering _from_ a failure burst) |
| **FAILING** | First insert failure in a burst (`retry_count` goes 0 → 1) | `audit_drain_failed` |
| **DEGRADED** | `retry_count` reaches `DEGRADED_AFTER = 5` within the same burst | `audit_drain_degraded` |
| **STOPPED** | `stop()` called | — |

The degraded flag (`_degraded_emitted`) resets to `false` on every
successful insert so the next failure burst can re-emit `audit_drain_degraded`.

---

## §4 Sys-stream events

All events MUST be written to **stderr** (not stdout).  Writing to
stdout risks deadlock: a slow stdout consumer stalls the drainer thread,
which fills the queue, which blocks every `emit()`.

Events are JSON objects with `shape:"sys"` (same shape as the structured
log output), emitted via the `sys_log` callback injected at drainer
construction time.

### Capacity threshold events

Fired from `put()` immediately after the slot is acquired and the
counter is incremented.

| Event | Level | Condition | Reset condition |
|---|---|---|---|
| `audit_queue_high_water` | `warn` | `depth / capacity >= 0.50` | `depth / capacity < 0.50` |
| `audit_queue_near_full` | `error` | `depth / capacity >= 0.80` | (same reset as above) |

**Debouncing:** each threshold fires AT MOST ONCE per crossing.  The
crossing flag is reset when `depth` drops back below 50 % so a new
surge re-emits the leading-indicator warning.  The two flags share one
reset condition (below 50 %) so a brief dip between 50–80 % re-arms
both.

**Fields** (in addition to standard `shape/level/event/timestamp`):

```json
{ "depth": <int>, "capacity": <int> }
```

### Drain-state events

| Event | Level | When |
|---|---|---|
| `audit_drain_failed` | `warn` | First failure in a new burst (`retry_count` 0→1) |
| `audit_drain_degraded` | `error` | `retry_count` reaches 5 within the burst |
| `audit_drain_recovered` | `info` | Insert succeeds after one or more failures |
| `audit_drain_dead_letter` | `error` | Row exhausts `max_attempts` |
| `audit_drain_abandoned` | `error` | `put()` called after drainer is stopped |

**`audit_drain_failed` fields:**

```json
{ "error": "<ExceptionType>: <message>" }
```

**`audit_drain_degraded` fields:**

```json
{
  "retry_count": <int>,
  "in_backoff_seconds": <float, 3 decimals>,
  "last_error": "<ExceptionType>: <message>"
}
```

**`audit_drain_recovered` fields:**

```json
{ "recovery_after_seconds": <float, 3 decimals> }
```

**`audit_drain_dead_letter` fields:**

```json
{
  "row_id": "<string|null>",
  "attempt_count": <int>,
  "last_error": "<ExceptionType>: <message>"
}
```

**`audit_drain_abandoned` fields:**

```json
{ "reason": "drainer_stopped", "row_id": "<string|null>" }
```

---

## §5 `queue_stats()` shape

`queue_stats()` MUST return `null` / `None` when the failure strategy is
`raise` (no drainer).  Otherwise it returns a snapshot with the
following fields:

| Field | Type | Description |
|---|---|---|
| `depth` | int | Occupied slots at snapshot time (queued + in-flight) |
| `capacity` | int | Configured maximum |
| `high_water` | int | Peak `depth` since drainer started (monotonic) |
| `drained_total` | int | Cumulative successful inserts |
| `retry_count_active` | int | Consecutive failures in the current burst (0 = healthy) |
| `in_backoff_seconds` | float | Remaining backoff sleep, 3 decimal places (0 = not in backoff) |
| `last_error` | string\|null | Error string from the most recent failure, null when healthy |
| `dead_lettered_total` | int | Cumulative rows moved to the DLQ |
| `dead_letter_depth` | int | Rows currently in the DLQ ring |
| `capacity_semantics` | string | `"block"` — `put()` blocks when full (all SDKs except JS) |

The `dead_letter_depth` is bounded by an internal ring of size 10; the
oldest entry falls off automatically once the ring is full.

---

## §6 Flush semantics

`flush(timeout)` MUST use **snapshot semantics**:

1. Under the stats lock, snapshot `target = drained_total + depth`.
2. Poll (≤ 10 ms interval) until `drained_total >= target` or timeout
   elapses.
3. Return `true` iff the target was reached.

**Rationale:** a steady incoming rate ≥ drain rate would keep a
naïve "wait until queue empty" blocked indefinitely.  Snapshot semantics
guarantee `flush()` terminates as long as the rows pending at call time
eventually succeed (or are dead-lettered).

`flush()` MUST return `true` immediately (no-op) when the failure
strategy is `raise`.

---

## §7 Test vectors

These test scenarios are the normative conformance corpus.  Each SDK's
test suite SHOULD cover all of them.  See
`python/tests/test_audit_queue.py` for the reference implementation.

### V-1 Happy path: queue mode drains within 1 second

```
Config: capacity=100, retry_initial=10ms, retry_max=50ms, jitter=off
Sink:   always succeeds
Actions:
  emit("USER_CREATED", target="u-1")
  emit("USER_CREATED", target="u-2")
  ok = flush(timeout=1s)
Assert:
  ok == true
  rows_received == 2
```

### V-2 Raise mode: throws `AuditStoreError`

```
Config: failure_strategy="raise"
Sink:   throws/panics "store down"
Actions:
  try { emit("USER_CREATED", target="u-1") }
  catch AuditStoreError as e
Assert:
  exception caught
  e.message contains "store down"
```

### V-3 Raise mode: no drainer installed

```
Config: failure_strategy="raise"
Assert:
  queue_stats() == null/None
```

### V-4 Outage then recovery

```
Config: retry_initial=10ms, retry_max=50ms, jitter=off
Sink:   fails first 2 calls, succeeds from call 3 onward
Actions:
  emit("USER_CREATED", target="u-1")
  ok = flush(timeout=2s)
Assert:
  ok == true
  success_count == 1
  attempt_count >= 3
```

### V-5 queue_stats fields after drain

```
Config: capacity=100
Sink:   always succeeds
Actions:
  emit("USER_CREATED", target="u-1")
  flush(timeout=1s)
  s = queue_stats()
Assert:
  s.depth == 0
  s.capacity == 100
  s.high_water >= 1
  s.drained_total == 1
  s.retry_count_active == 0
  s.last_error == null
```

### V-6 flush() no-op in raise mode

```
Config: failure_strategy="raise"
Sink:   always succeeds
Actions:
  emit("USER_CREATED", target="u-1")
  ok = flush(timeout=100ms)
Assert:
  ok == true   -- no-op, returns immediately
```

### V-7 high_water is monotonically non-decreasing

```
Config: capacity=10
Sink:   always succeeds
Actions:
  emit x5; flush(1s); hw1 = queue_stats().high_water
  emit x1; flush(1s); hw2 = queue_stats().high_water
Assert:
  hw2 >= hw1
```

### V-8 Capacity threshold debouncing under contention

```
Config: capacity=10, sink sleeps 20ms
Actions:
  8 concurrent emits (exceeds 80% threshold)
  flush(timeout=5s)
  read syslog
Assert:
  count(audit_queue_high_water) <= 1
  count(audit_queue_near_full)  <= 1
```

### V-9 Sync fallback emits sys event on sink failure

```
Config: failure_strategy="queue"
Sink:   always throws
Actions:
  install drainer; immediately uninstall drainer
  emit("USER_CREATED", target="u")
  syslog = query_syslog(100)
Assert:
  syslog contains entry with event=="audit_sync_fallback_failed"
```

### V-10 Dead-letter after max_attempts

```
Config: max_attempts=3, retry_initial=1ms, retry_max=5ms, jitter=off
Sink:   always throws
Actions:
  emit("USER_CREATED", target="u-1")
  flush(timeout=2s)
  s = queue_stats()
Assert:
  s.dead_lettered_total == 1
  s.depth == 0           -- slot released after DLQ
  syslog contains event=="audit_drain_dead_letter"
```

### V-11 Drain-state sys events fire in order

```
Config: retry_initial=10ms, retry_max=20ms, jitter=off, max_attempts=50
Sink:   fails 5 times, then succeeds
Actions:
  emit("USER_CREATED", target="u-1")
  flush(timeout=5s)
  syslog = query_syslog(100)
Assert:
  events appear in order: audit_drain_failed, audit_drain_degraded, audit_drain_recovered
  each event appears exactly once
```

### V-12 Abandoned emit after drainer stopped

```
Config: failure_strategy="queue"
Sink:   always succeeds
Actions:
  uninstall drainer
  emit("USER_CREATED", target="u")  -- no drainer active
  syslog = query_syslog(100)
Assert:
  syslog contains event=="audit_drain_abandoned"  OR
  event=="audit_sync_fallback_failed"
  (implementation may take either path; both are conformant)
```

---

## §8 Backoff formula

```
delay(n) = min(retry_initial_ms × 2^(n-1), retry_max_ms)
  n = retry_count at time of sleep (1-indexed: first failure = n=1)

if jitter:
  delay(n) = max(0, delay(n) + uniform(-0.2 × delay(n), +0.2 × delay(n)))
```

When `jitter=false` the first five delays (with `retry_initial=100ms`,
`retry_max=60000ms`) are: 100 ms, 200 ms, 400 ms, 800 ms, 1600 ms.

---

## §9 Thread-safety requirements

- `put()` and `stats()` MUST be safe to call from multiple concurrent
  threads.
- `flush()` MUST be safe to call concurrently with `put()`.
- Slot accounting MUST NOT race: `used_slots_count` MUST be decremented
  _before_ the semaphore/permit is released so a concurrent `put()` that
  wakes on the freed permit reads the correct count.
- `high_water` and threshold flags MUST be updated under the same lock
  to prevent duplicate sys events under concurrent puts (see V-8).

---

## §10 Shutdown protocol

`stop()` / `shutdown()`:

1. Set the stop signal.
2. Interrupt any in-progress backoff sleep immediately.
3. Drain remaining queue entries with at most one attempt each
   (no retry in shutdown path).
4. Join the drainer thread with a short timeout.

`install_drainer()` / `init()` on a running engine MUST:

1. Build the new drainer first.
2. Atomically swap the slot (under a mutex).
3. Flush the old drainer (outside the mutex) then stop it.

This race-safe swap prevents dropping in-flight rows during re-init.
