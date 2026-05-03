//! P1-15: bounded audit queue + background drainer thread (Rust).
//!
//! When [`Config::audit_store_failure_strategy`] is `"queue"` (the v1.0
//! default) and an `audit_store` is configured, [`EmitBuilder::submit`]
//! pushes audit rows onto a bounded in-memory queue and a background
//! `std::thread` drainer writes them to the store with exponential
//! backoff (100 ms → 60 s, ±20 % jitter). Store failures stay off the
//! request path; capacity covers queued + in-flight retry combined, so
//! `submit()` blocks only when the audit pipeline is genuinely
//! saturated, never silently drops.
//!
//! See the Python reference + the cross-SDK design notes in
//! `fasten-cloud/issues/P1-15-audit-store-failure-handling.md`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{AuditStore, Error, Row};

const HW_WARN_PCT: f64 = 0.50;
const HW_ERR_PCT: f64 = 0.80;
const DEGRADED_AFTER: usize = 5;

/// `submit()` returns this in `raise` mode when the store insert fails.
/// Wraps the store-side `Error` so callers don't depend on sqlx /
/// rusqlite types.
#[derive(Debug, thiserror::Error)]
#[error("fasten audit store: {source}")]
pub struct AuditStoreError {
    #[source]
    pub source: Error,
}

/// Snapshot returned by [`queue_stats`]. `depth` = queued + in-flight;
/// it's what determines whether the next `submit()` blocks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueueStats {
    pub depth: usize,
    pub capacity: usize,
    pub high_water: usize,
    pub drained_total: usize,
    pub retry_count_active: usize,
    pub in_backoff_seconds: f64,
    pub last_error: Option<String>,
}

/// Counting semaphore (no `std::sync::Semaphore` in stable yet).
struct Sem {
    capacity: usize,
    state: Mutex<usize>,
    cv: Condvar,
}

impl Sem {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(capacity),
            cv: Condvar::new(),
        }
    }
    fn acquire(&self) {
        let mut n = self.state.lock().unwrap();
        while *n == 0 {
            n = self.cv.wait(n).unwrap();
        }
        *n -= 1;
    }
    fn release(&self) {
        let mut n = self.state.lock().unwrap();
        if *n < self.capacity {
            *n += 1;
        }
        self.cv.notify_one();
    }
    fn used(&self) -> usize {
        self.capacity - *self.state.lock().unwrap()
    }
    /// Force-release so blocked acquirers can return on shutdown.
    fn release_all(&self) {
        let mut n = self.state.lock().unwrap();
        *n = self.capacity;
        self.cv.notify_all();
    }
}

#[derive(Default)]
struct Stats {
    high_water: usize,
    drained_total: usize,
    retry_count: usize,
    in_backoff_until: Option<Instant>,
    last_error: Option<String>,
    failure_burst_at: Option<Instant>,
    in_flight: usize,
    warn_hw_fired: bool,
    err_hw_fired: bool,
    degraded_fired: bool,
}

pub(crate) struct DrainerInner {
    store: Arc<dyn AuditStore>,
    sys_log: Box<dyn Fn(&str, &str, &serde_json::Value) + Send + Sync>,
    capacity: usize,
    retry_initial: Duration,
    retry_max: Duration,
    retry_jitter: bool,

    queue: Mutex<VecDeque<Row>>,
    queue_cv: Condvar,
    slots: Sem,
    stop: AtomicBool,

    stats: Mutex<Stats>,
}

pub(crate) struct Drainer {
    inner: Arc<DrainerInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drainer {
    pub(crate) fn new(
        store: Arc<dyn AuditStore>,
        sys_log: Box<dyn Fn(&str, &str, &serde_json::Value) + Send + Sync>,
        capacity: usize,
        retry_initial: Duration,
        retry_max: Duration,
        retry_jitter: bool,
    ) -> Arc<Self> {
        let inner = Arc::new(DrainerInner {
            store,
            sys_log,
            capacity,
            retry_initial,
            retry_max,
            retry_jitter,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            queue_cv: Condvar::new(),
            slots: Sem::new(capacity),
            stop: AtomicBool::new(false),
            stats: Mutex::new(Stats::default()),
        });
        let inner_for_thread = inner.clone();
        let handle = thread::Builder::new()
            .name("fasten-audit-drainer".into())
            .spawn(move || run(inner_for_thread))
            .expect("spawn drainer thread");
        Arc::new(Drainer {
            inner,
            handle: Mutex::new(Some(handle)),
        })
    }

    pub(crate) fn put(&self, row: Row) {
        // Reject early if the drainer has already been signalled to
        // stop (re-init swap or shutdown). Without this, shutdown's
        // release_all() wakes blocked acquirers after stop is set —
        // they push onto a queue the drainer thread will never drain.
        if self.inner.stop.load(Ordering::SeqCst) {
            (self.inner.sys_log)(
                "error",
                "audit_drain_abandoned",
                &serde_json::json!({
                    "reason": "drainer_stopped",
                    "row_id": row.id,
                }),
            );
            return;
        }
        // Acquire slot — blocks until capacity frees. The drainer
        // releases the permit only on successful insert (or shutdown
        // abandon), so submit() blocks while a row is in retry-backoff —
        // capacity covers queued + in-flight retry combined.
        self.inner.slots.acquire();
        // Re-check after acquire: shutdown may have run release_all()
        // between our stop-check above and now. Release the slot back
        // and abandon the row instead of stalling on a dead drainer.
        if self.inner.stop.load(Ordering::SeqCst) {
            self.inner.slots.release();
            (self.inner.sys_log)(
                "error",
                "audit_drain_abandoned",
                &serde_json::json!({
                    "reason": "drainer_stopped_mid_put",
                    "row_id": row.id,
                }),
            );
            return;
        }
        {
            let mut q = self.inner.queue.lock().unwrap();
            q.push_back(row);
            self.inner.queue_cv.notify_one();
        }
        let used = self.inner.slots.used();
        let mut s = self.inner.stats.lock().unwrap();
        if used > s.high_water {
            s.high_water = used;
        }
        let cap = self.inner.capacity;
        let prev_warn = s.warn_hw_fired;
        let prev_err = s.err_hw_fired;
        if cap > 0 {
            let pct = used as f64 / cap as f64;
            if pct >= HW_ERR_PCT && !s.err_hw_fired {
                s.err_hw_fired = true;
            } else if pct >= HW_WARN_PCT && !s.warn_hw_fired {
                s.warn_hw_fired = true;
            } else if pct < HW_WARN_PCT {
                s.warn_hw_fired = false;
                s.err_hw_fired = false;
            }
        }
        let fire_err = s.err_hw_fired && !prev_err;
        let fire_warn = s.warn_hw_fired && !prev_warn && !fire_err;
        drop(s);

        if fire_err {
            (self.inner.sys_log)(
                "error",
                "audit_queue_near_full",
                &serde_json::json!({"depth": used, "capacity": cap}),
            );
        } else if fire_warn {
            (self.inner.sys_log)(
                "warn",
                "audit_queue_high_water",
                &serde_json::json!({"depth": used, "capacity": cap}),
            );
        }
    }

    pub(crate) fn stats(&self) -> QueueStats {
        let s = self.inner.stats.lock().unwrap();
        let in_backoff = s
            .in_backoff_until
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .map(|d| (d.as_secs_f64() * 1000.0).round() / 1000.0)
            .unwrap_or(0.0);
        QueueStats {
            depth: self.inner.slots.used(),
            capacity: self.inner.capacity,
            high_water: s.high_water,
            drained_total: s.drained_total,
            retry_count_active: s.retry_count,
            in_backoff_seconds: in_backoff,
            last_error: s.last_error.clone(),
        }
    }

    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        // Use the slot semaphore as the canonical "rows pending"
        // signal: it's acquired by put() before queue.push and
        // released only after successful insert, so it covers the
        // transient window where a row has been popped from the queue
        // but in_flight has not yet been incremented in drain_one.
        // Checking queue + in_flight separately allowed flush() to
        // return prematurely during that gap.
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.inner.slots.used() == 0 {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.inner.slots.used() == 0
    }

    pub(crate) fn shutdown(&self, timeout: Duration) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.queue_cv.notify_all();
        // Force-wake any submit() blocked on the slot semaphore so they
        // can proceed once shutdown completes.
        self.inner.slots.release_all();

        let handle = self.handle.lock().unwrap().take();
        if let Some(h) = handle {
            // Best-effort join; we can't actually time-bound a thread
            // join in stable Rust without crossbeam. Detach if it
            // doesn't return promptly.
            let h_thread = h.thread().clone();
            let join = std::thread::spawn(move || {
                let _ = h.join();
            });
            let waited = Instant::now();
            while waited.elapsed() < timeout {
                if join.is_finished() {
                    let _ = join.join();
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            // Timed out — forget about the join thread. The drainer
            // will eventually exit (it polls stop flag), and the OS
            // will clean it up on process exit.
            std::mem::drop(h_thread);
        }
    }
}

fn run(inner: Arc<DrainerInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        let row = {
            let q = inner.queue.lock().unwrap();
            let (mut q, _wait) = inner
                .queue_cv
                .wait_timeout_while(q, Duration::from_millis(100), |q| {
                    q.is_empty() && !inner.stop.load(Ordering::SeqCst)
                })
                .unwrap();
            q.pop_front()
        };
        if let Some(row) = row {
            drain_one(&inner, row, false);
        }
    }
    // Shutdown drain — best-effort, in_shutdown=true (one attempt only).
    loop {
        let row = {
            let mut q = inner.queue.lock().unwrap();
            q.pop_front()
        };
        match row {
            Some(r) => drain_one(&inner, r, true),
            None => break,
        }
    }
}

fn drain_one(inner: &Arc<DrainerInner>, row: Row, in_shutdown: bool) {
    {
        let mut s = inner.stats.lock().unwrap();
        s.in_flight += 1;
    }
    let mut slot_released = false;
    let release_slot = |released: &mut bool| {
        if !*released {
            inner.slots.release();
            *released = true;
        }
    };

    loop {
        match inner.store.insert(&row) {
            Ok(()) => {
                on_success(inner);
                release_slot(&mut slot_released);
                break;
            }
            Err(e) => {
                on_failure(inner, &e);
                if in_shutdown {
                    // Shutdown contract: one attempt, abandon on
                    // failure. Adopters who need durability under
                    // crash use raise mode.
                    release_slot(&mut slot_released);
                    break;
                }
                if wait_backoff(inner) {
                    // stop signalled mid-backoff
                    release_slot(&mut slot_released);
                    break;
                }
            }
        }
    }
    {
        let mut s = inner.stats.lock().unwrap();
        s.in_flight -= 1;
    }
    if !slot_released {
        inner.slots.release();
    }
}

fn on_failure(inner: &Arc<DrainerInner>, err: &Error) {
    let msg = err.to_string();
    let (first, crossed_degraded, rc, bo) = {
        let mut s = inner.stats.lock().unwrap();
        let first = s.retry_count == 0;
        if first {
            s.failure_burst_at = Some(Instant::now());
        }
        s.retry_count += 1;
        s.last_error = Some(msg.clone());
        let bo = s
            .in_backoff_until
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .map(|d| (d.as_secs_f64() * 1000.0).round() / 1000.0)
            .unwrap_or(0.0);
        let crossed = s.retry_count >= DEGRADED_AFTER && !s.degraded_fired;
        if crossed {
            s.degraded_fired = true;
        }
        (first, crossed, s.retry_count, bo)
    };
    if first {
        (inner.sys_log)(
            "warn",
            "audit_drain_failed",
            &serde_json::json!({"error": msg}),
        );
    }
    if crossed_degraded {
        (inner.sys_log)(
            "error",
            "audit_drain_degraded",
            &serde_json::json!({
                "retry_count": rc,
                "in_backoff_seconds": bo,
                "last_error": msg,
            }),
        );
    }
}

fn on_success(inner: &Arc<DrainerInner>) {
    let recovered = {
        let mut s = inner.stats.lock().unwrap();
        let r = if s.retry_count > 0 {
            s.failure_burst_at
                .map(|t| t.elapsed().as_secs_f64())
        } else {
            None
        };
        s.retry_count = 0;
        s.in_backoff_until = None;
        s.failure_burst_at = None;
        s.last_error = None;
        s.degraded_fired = false;
        s.drained_total += 1;
        r
    };
    if let Some(secs) = recovered {
        let r = (secs * 1000.0).round() / 1000.0;
        (inner.sys_log)(
            "info",
            "audit_drain_recovered",
            &serde_json::json!({"recovery_after_seconds": r}),
        );
    }
}

fn wait_backoff(inner: &Arc<DrainerInner>) -> bool {
    let n = inner.stats.lock().unwrap().retry_count;
    let mut delay = inner.retry_initial;
    for _ in 1..n {
        delay = delay.saturating_mul(2);
        if delay >= inner.retry_max {
            delay = inner.retry_max;
            break;
        }
    }
    if delay > inner.retry_max {
        delay = inner.retry_max;
    }
    if inner.retry_jitter {
        let j = delay.as_secs_f64() * 0.2;
        let r: f64 = simple_random();
        let signed = (r * 2.0 - 1.0) * j;
        let new = (delay.as_secs_f64() + signed).max(0.0);
        delay = Duration::from_secs_f64(new);
    }
    inner.stats.lock().unwrap().in_backoff_until = Some(Instant::now() + delay);

    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if inner.stop.load(Ordering::SeqCst) {
            return true;
        }
        let step = (deadline - Instant::now()).min(Duration::from_millis(50));
        thread::sleep(step);
    }
    false
}

/// Tiny PRNG using nanos since unix epoch — avoids pulling rand crate.
fn simple_random() -> f64 {
    use std::time::SystemTime;
    let n = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    // Linear congruential — good enough for jitter, not for crypto.
    let v = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((v >> 11) as f64) / ((1u64 << 53) as f64)
}

// ── Module-level singleton ─────────────────────────────────────────────────

static DRAINER: OnceLock<Mutex<Option<Arc<Drainer>>>> = OnceLock::new();

fn drainer_slot() -> &'static Mutex<Option<Arc<Drainer>>> {
    DRAINER.get_or_init(|| Mutex::new(None))
}

pub(crate) fn install_drainer(
    store: Arc<dyn AuditStore>,
    sys_log: Box<dyn Fn(&str, &str, &serde_json::Value) + Send + Sync>,
    capacity: usize,
    retry_initial: Duration,
    retry_max: Duration,
    retry_jitter: bool,
) -> Arc<Drainer> {
    // Race-safe re-init: build the new drainer FIRST, swap the global
    // pointer atomically, then flush + shutdown the old one OUTSIDE the
    // global lock. Concurrent submit()s see either the old drainer (and
    // any post-stop put() now self-aborts via the stop check) or the
    // new one — never a stopped-but-still-published one. Holding the
    // lock through flush/shutdown (the prior shape) blocked every
    // emit() for ~5 s during re-init.
    let new = Drainer::new(
        store,
        sys_log,
        capacity,
        retry_initial,
        retry_max,
        retry_jitter,
    );
    let old = {
        let mut slot = drainer_slot().lock().unwrap();
        slot.replace(new.clone())
    };
    if let Some(old) = old {
        old.flush(Duration::from_secs(5));
        old.shutdown(Duration::from_secs(2));
    }
    new
}

/// Stop and drop the active drainer. Called automatically on next
/// `init()`; exposed for tests + adopter shutdown paths that want to
/// drop the drainer without reinitialising fasten.
pub fn uninstall_drainer() {
    // Symmetric with install_drainer: clear the global FIRST so
    // concurrent submit() sees no drainer (and falls back to sync /
    // raise per failure_strategy) instead of racing a half-stopped one.
    let old = {
        let mut slot = drainer_slot().lock().unwrap();
        slot.take()
    };
    if let Some(d) = old {
        d.shutdown(Duration::from_secs(2));
    }
}

pub(crate) fn active_drainer() -> Option<Arc<Drainer>> {
    drainer_slot().lock().unwrap().clone()
}

/// Snapshot of the active drainer, or `None` in `raise` mode.
pub fn queue_stats() -> Option<QueueStats> {
    active_drainer().map(|d| d.stats())
}

/// Block until pending audit rows drain, or `timeout` elapses. Returns
/// true iff every queued row reached the store. Useful for k8s preStop
/// hooks, CLI exit paths, and tests. No-op + true in `raise` mode.
pub fn flush(timeout: Duration) -> bool {
    match active_drainer() {
        Some(d) => d.flush(timeout),
        None => true,
    }
}
