# Drainer conformance spec

**Version:** 1.1  
**Date:** 2026-05-14  
**Status:** Normative. All SDK drainer implementations MUST conform.

---

## Purpose

Every SDK gives adopters the same drainer: a bounded queue, exponential
backoff on insert failures, and sys events that report its state.

- The shared `fasten-core` C ABI (`libfasten_core.so` / `.dylib`) provides
  the implementation.
- Python, Go and C++ bind to it over FFI (ctypes, cgo, `extern "C"`).
- Rust implements it natively and is the reference implementation.
- JS and Swift each run their own in-process drainer loop in the host
  language, with no Rust dependency, conforming to this spec.

This document is the single source of truth for the externally visible
drainer contract. Where an SDK differs from it, the spec wins.

Each SDK's test suite SHOULD include the test vectors in §7 so the SDKs
do not drift apart again unnoticed.

---

## §1 Concepts

**Queue.** A bounded in-memory FIFO of audit `Row` objects waiting to be
inserted into the store.

**Drainer thread.** One long-lived background thread (goroutine, Worker
thread) that pops rows from the queue and calls `store.insert(row)`.

**Slot.** One unit of capacity. A slot is _occupied_ from the moment
`put()` acquires it until `store.insert` succeeds, or until the row is
dead-lettered or abandoned. A row waiting in retry backoff still holds its
slot. `capacity` is therefore the maximum number of rows in flight across
the whole audit pipeline, not just the queue depth.

**`depth`.** The number of occupied slots at a given instant
(`queued + in-flight`).

**Backoff window.** How long the drainer sleeps between two failed insert
attempts. It starts at `retry_initial` (default 100 ms), doubles after
each failure, is capped at `retry_max` (default 60 s), and optionally has
+/-20 % jitter applied.

---

## §2 Configuration parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `capacity` | int | 100 | Maximum occupied slots (queued + in-flight) |
| `retry_initial` | duration | 100 ms | First backoff window |
| `retry_max` | duration | 60 s | Maximum backoff window |
| `retry_jitter` | bool | true | +/-20 % uniform jitter on each window |
| `max_attempts` | int | 50 | Insert attempts before a row is dead-lettered |

---

## §3 State machine

```
emit()
  stop set    -> abandon the row (audit_drain_abandoned)
  slot full   -> block until a slot is released
  slot free   -> acquire a slot, push the row onto the queue

drainer thread
  pop row from queue
  store.insert(row)
    success                           -> _on_success(): release slot
                                         (HEALTHY again if recovering)
    failure, attempt <  max_attempts  -> _on_failure(), wait_backoff(), retry
    failure, attempt >= max_attempts  -> _on_dead_letter(): release slot
```

### States

| State | Entry condition | Sys event emitted |
|---|---|---|
| **HEALTHY** | Initial state, or `retry_count` returns to 0 after a success | `audit_drain_recovered`, only when recovering from a failure burst |
| **FAILING** | First insert failure in a burst (`retry_count` goes from 0 to 1) | `audit_drain_failed` |
| **DEGRADED** | `retry_count` reaches `DEGRADED_AFTER = 5` within the same burst | `audit_drain_degraded` |
| **STOPPED** | `stop()` called | none |

The degraded flag (`_degraded_emitted`) resets to `false` on every
successful insert, so the next failure burst can emit
`audit_drain_degraded` again.

---

## §4 Sys-stream events

All events MUST be written to **stderr**, not stdout. A slow stdout
consumer would stall the drainer thread, the queue would fill, and every
`emit()` would block.

Events are JSON objects with `shape:"sys"`, the same shape as the
structured log output. They are emitted through the `sys_log` callback
passed in when the drainer is constructed.

### Capacity threshold events

Fired from `put()` right after the slot is acquired and the counter is
incremented.

| Event | Level | Condition | Reset condition |
|---|---|---|---|
| `audit_queue_high_water` | `warn` | `depth / capacity >= 0.50` | `depth / capacity < 0.50` |
| `audit_queue_near_full` | `error` | `depth / capacity >= 0.80` | (same reset as above) |

**Debouncing.** Each threshold fires AT MOST ONCE per crossing. Both flags
reset only when `depth` drops below 50 %, so the next surge emits the
early warning again. A dip into the 50 to 80 % band re-arms neither flag.

**Fields**, in addition to the standard `shape`, `level`, `event` and
`timestamp`:

```json
{ "depth": <int>, "capacity": <int> }
```

### Drain-state events

| Event | Level | When |
|---|---|---|
| `audit_drain_failed` | `warn` | First failure in a new burst (`retry_count` goes from 0 to 1) |
| `audit_drain_degraded` | `error` | `retry_count` reaches 5 within the burst |
| `audit_drain_recovered` | `info` | An insert succeeds after one or more failures |
| `audit_drain_dead_letter` | `error` | A row uses up `max_attempts` |
| `audit_drain_abandoned` | `error` | `put()` is called after the drainer has stopped |

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
`raise`, since there is no drainer. Otherwise it returns a snapshot with
these fields:

| Field | Type | Description |
|---|---|---|
| `depth` | int | Occupied slots at snapshot time (queued + in-flight) |
| `capacity` | int | Configured maximum |
| `high_water` | int | Peak `depth` since the drainer started (monotonic) |
| `drained_total` | int | Total successful inserts |
| `retry_count_active` | int | Consecutive failures in the current burst (0 = healthy) |
| `in_backoff_seconds` | float | Backoff sleep remaining, 3 decimal places (0 = not in backoff) |
| `last_error` | string\|null | Error string from the most recent failure, null when healthy |
| `dead_lettered_total` | int | Total rows moved to the DLQ |
| `dead_letter_depth` | int | Rows currently in the DLQ ring |
| `capacity_semantics` | string | `"block"`: `put()` blocks when full. All SDKs except JS, which reports `"warn_only"` and never blocks. |

`dead_letter_depth` is bounded by an internal ring of 10 entries. Once the
ring is full, the oldest entry is dropped.

---

## §6 Flush semantics

`flush(timeout)` MUST use **snapshot semantics**:

1. Under the stats lock, take `target = drained_total + depth`.
2. Poll (at most every 10 ms) until `drained_total >= target` or the
   timeout elapses.
3. Return `true` if and only if the target was reached.

**Why.** If rows keep arriving at least as fast as they drain, a plain
"wait until the queue is empty" never returns. With a snapshot,
`flush()` returns once the rows that were pending at call time succeed
(or are dead-lettered).

`flush()` MUST return `true` immediately (no-op) when the failure
strategy is `raise`.

---

## §7 Test vectors

These scenarios are the normative conformance corpus. Each SDK's test
suite SHOULD cover all of them. The reference implementation is
`python/tests/test_audit_queue.py`.

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

With `jitter=false`, `retry_initial=100ms` and `retry_max=60000ms`, the
first five delays are 100 ms, 200 ms, 400 ms, 800 ms and 1600 ms.

---

## §9 Thread-safety requirements

- `put()` and `stats()` MUST be safe to call from multiple threads at
  once.
- `flush()` MUST be safe to call concurrently with `put()`.
- Slot accounting MUST NOT race. `used_slots_count` MUST be decremented
  _before_ the semaphore/permit is released, so a concurrent `put()` that
  wakes on the freed permit reads the correct count.
- `high_water` and the threshold flags MUST be updated under the same
  lock, so concurrent puts cannot emit duplicate sys events (see V-8).

---

## §10 Shutdown protocol

`stop()` / `shutdown()`:

1. Set the stop signal.
2. Interrupt any backoff sleep in progress immediately.
3. Drain the remaining queue entries with at most one attempt each. There
   is no retry on the shutdown path.
4. Join the drainer thread with a short timeout.

`install_drainer()` / `init()` on a running engine MUST:

1. Build the new drainer first.
2. Swap it into the slot atomically, under a mutex.
3. Flush the old drainer, outside the mutex, then stop it.

This order means no in-flight rows are dropped during re-init.
