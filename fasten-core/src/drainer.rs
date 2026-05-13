//! Bounded audit queue + background drainer (shared Rust engine).
//!
//! Implements the 12-state machine from `spec/drainer-conformance.md`:
//! HEALTHY → FAILING → DEGRADED → STOPPED, with dead-letter after
//! `max_attempts` insert failures.
//!
//! Sys-stream events are written to **stderr** as NDJSON per the spec.
//! Each event is a JSON line: `{"shape":"sys","level":"...","event":"...", ...}`.
//!
//! # Thread safety
//!
//! `Drainer` is `Send + Sync`. The background thread is a plain OS thread
//! owned by the Drainer; it terminates when `stop()` is called or
//! `Drainer` is dropped.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{row::Row, store::Store};

// ── Conformance constants ──────────────────────────────────────────────────

const HW_WARN_PCT: f64 = 0.50;
const HW_ERR_PCT: f64 = 0.80;
const DEGRADED_AFTER: usize = 5;
const DLQ_RING_SIZE: usize = 10;

// ── DrainerConfig ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DrainerConfig {
    pub capacity: usize,
    pub retry_initial: Duration,
    pub retry_max: Duration,
    pub retry_jitter: bool,
    pub max_attempts: usize,
}

impl Default for DrainerConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            retry_initial: Duration::from_millis(100),
            retry_max: Duration::from_secs(60),
            retry_jitter: true,
            max_attempts: 50,
        }
    }
}

// ── QueueStats ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueueStats {
    pub depth: usize,
    pub capacity: usize,
    pub high_water: usize,
    pub drained_total: usize,
    pub retry_count_active: usize,
    pub in_backoff_seconds: f64,
    pub last_error: Option<String>,
    pub dead_lettered_total: usize,
    pub dead_letter_depth: usize,
    pub capacity_semantics: &'static str,
}

// ── Counting semaphore ─────────────────────────────────────────────────────

struct Sem {
    capacity: usize,
    state: Mutex<usize>,
    cv: Condvar,
}

impl Sem {
    fn new(capacity: usize) -> Self {
        Self { capacity, state: Mutex::new(capacity), cv: Condvar::new() }
    }
    fn acquire(&self) {
        let mut n = lock_or_recover(&self.state);
        while *n == 0 {
            n = cv_wait_or_recover(&self.cv, n);
        }
        *n -= 1;
    }
    fn release(&self) {
        let mut n = lock_or_recover(&self.state);
        if *n < self.capacity {
            *n += 1;
        }
        self.cv.notify_one();
    }
    fn used(&self) -> usize {
        self.capacity - *lock_or_recover(&self.state)
    }
    fn release_all(&self) {
        let mut n = lock_or_recover(&self.state);
        *n = self.capacity;
        self.cv.notify_all();
    }
}

fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn cv_wait_or_recover<'a, T>(cv: &Condvar, g: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    cv.wait(g).unwrap_or_else(|e| e.into_inner())
}

// ── Internal stats ─────────────────────────────────────────────────────────

#[derive(Default)]
struct InternalStats {
    high_water: usize,
    drained_total: usize,
    retry_count: usize,
    in_backoff_until: Option<Instant>,
    last_error: Option<String>,
    failure_burst_at: Option<Instant>,
    warn_hw_fired: bool,
    err_hw_fired: bool,
    degraded_fired: bool,
    dead_lettered_total: usize,
    dlq: VecDeque<Row>,
}

// ── DrainerInner ──────────────────────────────────────────────────────────

struct DrainerInner {
    store: Box<dyn Store>,
    cfg: DrainerConfig,
    queue: Mutex<VecDeque<Row>>,
    queue_cv: Condvar,
    flush_cv: Condvar,
    slots: Sem,
    stop: AtomicBool,
    stats: Mutex<InternalStats>,
}

// SAFETY: `Box<dyn Store>` is `Send` (Store trait requires `Send`).
// The inner mutex protects all shared state.
unsafe impl Send for DrainerInner {}
unsafe impl Sync for DrainerInner {}

// ── Drainer ────────────────────────────────────────────────────────────────

pub struct Drainer {
    inner: Arc<DrainerInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drainer {
    pub fn new(store: Box<dyn Store>, cfg: DrainerConfig) -> Arc<Self> {
        let capacity = cfg.capacity;
        let inner = Arc::new(DrainerInner {
            store,
            cfg,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            queue_cv: Condvar::new(),
            flush_cv: Condvar::new(),
            slots: Sem::new(capacity),
            stop: AtomicBool::new(false),
            stats: Mutex::new(InternalStats::default()),
        });
        let inner2 = inner.clone();
        let handle = thread::Builder::new()
            .name("fasten-drainer".into())
            .spawn(move || drain_loop(inner2))
            .expect("spawn drainer thread");
        Arc::new(Self { inner, handle: Mutex::new(Some(handle)) })
    }

    /// Enqueue a row. Blocks when the queue is full (back-pressure).
    /// Returns `false` if the drainer is already stopped (row abandoned).
    pub fn enqueue(&self, row: Row) -> bool {
        if self.inner.stop.load(Ordering::SeqCst) {
            sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                "reason": "drainer_stopped",
                "row_id": row.id,
            }));
            return false;
        }
        // Acquire a slot — blocks under back-pressure.
        self.inner.slots.acquire();
        if self.inner.stop.load(Ordering::SeqCst) {
            // Shutdown raced us; release and abandon.
            self.inner.slots.release();
            sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                "reason": "drainer_stopped",
                "row_id": row.id,
            }));
            return false;
        }
        // Update high-water + threshold events.
        {
            let mut st = lock_or_recover(&self.inner.stats);
            let capacity = self.inner.cfg.capacity;
            let depth = self.inner.slots.used();
            if depth > st.high_water {
                st.high_water = depth;
            }
            let ratio = depth as f64 / capacity as f64;
            if ratio >= HW_ERR_PCT && !st.err_hw_fired {
                st.err_hw_fired = true;
                sys_event("error", "audit_queue_near_full", &serde_json::json!({
                    "depth": depth, "capacity": capacity,
                }));
            } else if ratio >= HW_WARN_PCT && !st.warn_hw_fired {
                st.warn_hw_fired = true;
                sys_event("warn", "audit_queue_high_water", &serde_json::json!({
                    "depth": depth, "capacity": capacity,
                }));
            } else if ratio < HW_WARN_PCT && (st.warn_hw_fired || st.err_hw_fired) {
                st.warn_hw_fired = false;
                st.err_hw_fired = false;
            }
        }
        let mut q = lock_or_recover(&self.inner.queue);
        q.push_back(row);
        self.inner.queue_cv.notify_one();
        true
    }

    /// Block until all rows currently queued have been drained (or timeout).
    /// Returns `true` if fully drained within the deadline.
    pub fn flush(&self, timeout: Duration) -> bool {
        // Snapshot the target: drained_total + current depth.
        let target = {
            let st = lock_or_recover(&self.inner.stats);
            st.drained_total + st.dead_lettered_total + self.inner.slots.used()
        };
        let deadline = Instant::now() + timeout;
        let mut st = lock_or_recover(&self.inner.stats);
        loop {
            let done = st.drained_total + st.dead_lettered_total;
            if done >= target {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let result = self.inner.flush_cv.wait_timeout(st, remaining)
                .unwrap_or_else(|e| e.into_inner());
            st = result.0;
        }
    }

    /// Snapshot queue stats as a typed struct.
    pub fn stats(&self) -> QueueStats {
        let st = lock_or_recover(&self.inner.stats);
        let depth = self.inner.slots.used();
        let in_backoff = st.in_backoff_until
            .and_then(|t| {
                let rem = t.saturating_duration_since(Instant::now());
                if rem.is_zero() { None } else { Some(rem.as_secs_f64()) }
            })
            .unwrap_or(0.0);
        QueueStats {
            depth,
            capacity: self.inner.cfg.capacity,
            high_water: st.high_water,
            drained_total: st.drained_total,
            retry_count_active: st.retry_count,
            in_backoff_seconds: (in_backoff * 1000.0).round() / 1000.0,
            last_error: st.last_error.clone(),
            dead_lettered_total: st.dead_lettered_total,
            dead_letter_depth: st.dlq.len(),
            capacity_semantics: "block",
        }
    }

    /// Snapshot queue stats as a JSON string.
    pub fn stats_json(&self) -> String {
        let st = lock_or_recover(&self.inner.stats);
        let depth = self.inner.slots.used();
        let in_backoff = st.in_backoff_until
            .and_then(|t| {
                let rem = t.saturating_duration_since(Instant::now());
                if rem.is_zero() { None } else { Some(rem.as_secs_f64()) }
            })
            .unwrap_or(0.0);
        let stats = QueueStats {
            depth,
            capacity: self.inner.cfg.capacity,
            high_water: st.high_water,
            drained_total: st.drained_total,
            retry_count_active: st.retry_count,
            in_backoff_seconds: (in_backoff * 1000.0).round() / 1000.0,
            last_error: st.last_error.clone(),
            dead_lettered_total: st.dead_lettered_total,
            dead_letter_depth: st.dlq.len(),
            capacity_semantics: "block",
        };
        serde_json::to_string(&stats).unwrap_or_else(|_| "{}".into())
    }

    /// Stop the drainer: signal the background thread to exit, then join.
    /// Remaining rows get one final drain attempt with no retry.
    pub fn stop(&self, timeout: Duration) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.slots.release_all();
        self.inner.queue_cv.notify_all();
        let deadline = Instant::now() + timeout;
        if let Some(h) = lock_or_recover(&self.handle).take() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = h.join(); // join ignores timeout — thread exits quickly on stop
            let _ = remaining;
        }
    }
}

impl Drop for Drainer {
    fn drop(&mut self) {
        self.stop(Duration::from_secs(2));
    }
}

// ── Drain loop (background thread) ────────────────────────────────────────

fn drain_loop(inner: Arc<DrainerInner>) {
    loop {
        let row = {
            let mut q = lock_or_recover(&inner.queue);
            loop {
                if let Some(r) = q.pop_front() {
                    break r;
                }
                if inner.stop.load(Ordering::Acquire) {
                    return; // exit cleanly
                }
                q = cv_wait_or_recover(&inner.queue_cv, q);
                if inner.stop.load(Ordering::Acquire) && q.is_empty() {
                    return;
                }
            }
        };

        let mut attempt = 0usize;
        let in_shutdown = inner.stop.load(Ordering::Relaxed);

        loop {
            let result = inner.store.insert(&row);
            match result {
                Ok(()) => {
                    on_success(&inner);
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    attempt += 1;
                    if attempt >= inner.cfg.max_attempts || in_shutdown {
                        on_dead_letter(&inner, &row, attempt, &msg);
                        break;
                    }
                    on_failure(&inner, &msg, attempt);
                    // Wait out the backoff
                    let backoff = compute_backoff(&inner, attempt);
                    let deadline = Instant::now() + backoff;
                    loop {
                        let rem = deadline.saturating_duration_since(Instant::now());
                        if rem.is_zero() { break; }
                        if inner.stop.load(Ordering::Relaxed) { break; }
                        thread::sleep(rem.min(Duration::from_millis(50)));
                    }
                }
            }
        }
    }
}

fn on_success(inner: &DrainerInner) {
    let mut st = lock_or_recover(&inner.stats);
    let recovering = st.retry_count > 0 && st.failure_burst_at.is_some();
    let recovery_secs = if recovering {
        st.failure_burst_at.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0)
    } else {
        0.0
    };
    st.retry_count = 0;
    st.in_backoff_until = None;
    st.failure_burst_at = None;
    st.last_error = None;
    st.degraded_fired = false;
    st.drained_total += 1;
    drop(st);
    inner.slots.release();
    inner.flush_cv.notify_all();
    if recovering {
        let r = (recovery_secs * 1000.0).round() / 1000.0;
        sys_event("info", "audit_drain_recovered", &serde_json::json!({
            "recovery_after_seconds": r,
        }));
    }
}

fn on_failure(inner: &DrainerInner, msg: &str, attempt: usize) {
    let mut st = lock_or_recover(&inner.stats);
    let first = st.retry_count == 0;
    if first {
        st.failure_burst_at = Some(Instant::now());
    }
    st.retry_count = attempt;
    st.last_error = Some(msg.to_owned());
    let backoff = compute_backoff_val(
        attempt, inner.cfg.retry_initial, inner.cfg.retry_max, inner.cfg.retry_jitter,
    );
    st.in_backoff_until = Some(Instant::now() + backoff);
    let should_degraded = attempt >= DEGRADED_AFTER && !st.degraded_fired;
    let should_failed = first;
    drop(st);

    if should_failed {
        sys_event("warn", "audit_drain_failed", &serde_json::json!({ "error": msg }));
    }
    if should_degraded {
        let st2 = lock_or_recover(&inner.stats);
        let remaining = st2.in_backoff_until
            .map(|t| {
                let r = t.saturating_duration_since(Instant::now()).as_secs_f64();
                (r * 1000.0).round() / 1000.0
            })
            .unwrap_or(0.0);
        drop(st2);
        lock_or_recover(&inner.stats).degraded_fired = true;
        sys_event("error", "audit_drain_degraded", &serde_json::json!({
            "retry_count": attempt,
            "in_backoff_seconds": remaining,
            "last_error": msg,
        }));
    }
}

fn on_dead_letter(inner: &DrainerInner, row: &Row, attempts: usize, msg: &str) {
    let mut st = lock_or_recover(&inner.stats);
    st.dead_lettered_total += 1;
    if st.dlq.len() >= DLQ_RING_SIZE {
        st.dlq.pop_front();
    }
    st.dlq.push_back(row.clone());
    st.retry_count = 0;
    st.in_backoff_until = None;
    st.failure_burst_at = None;
    drop(st);
    inner.slots.release();
    inner.flush_cv.notify_all();
    sys_event("error", "audit_drain_dead_letter", &serde_json::json!({
        "row_id": row.id,
        "attempt_count": attempts,
        "last_error": msg,
    }));
}

fn compute_backoff(inner: &DrainerInner, attempt: usize) -> Duration {
    compute_backoff_val(
        attempt, inner.cfg.retry_initial, inner.cfg.retry_max, inner.cfg.retry_jitter,
    )
}

fn compute_backoff_val(
    attempt: usize,
    initial: Duration,
    max: Duration,
    jitter: bool,
) -> Duration {
    let shift = attempt.saturating_sub(1).min(63) as u32;
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base = initial * factor.try_into().unwrap_or(u32::MAX);
    let capped = base.min(max);
    if !jitter {
        return capped;
    }
    // ±20% uniform jitter
    let ms = capped.as_millis() as u64;
    let jitter_range = ms / 5; // 20%
    // Simple LCG for no-std jitter (no rand dep)
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345);
    let j = seed as u64 % (jitter_range * 2 + 1);
    let jittered = ms.saturating_add(j).saturating_sub(jitter_range);
    Duration::from_millis(jittered)
}

// ── Sys-stream emission ────────────────────────────────────────────────────

fn sys_event(level: &str, event: &str, fields: &serde_json::Value) {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut obj = serde_json::json!({
        "shape": "sys",
        "level": level,
        "event": event,
        "timestamp": ts,
    });
    if let (Some(o), Some(f)) = (obj.as_object_mut(), fields.as_object()) {
        for (k, v) in f {
            o.insert(k.clone(), v.clone());
        }
    }
    let line = serde_json::to_string(&obj).unwrap_or_default();
    let _ = writeln!(std::io::stderr(), "{line}");
}
