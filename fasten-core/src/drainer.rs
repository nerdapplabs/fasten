//! Bounded audit queue and background drainer.
//!
//! Implements the state machine in `spec/drainer-conformance.md` §3
//! (HEALTHY, FAILING, DEGRADED, STOPPED), dead-lettering a row after
//! `max_attempts` failed inserts.
//!
//! Sys events go to stderr, one JSON object per line:
//! `{"shape":"sys","level":"...","event":"...", ...}`.
//!
//! # Thread safety
//!
//! `Drainer` is `Send + Sync`. The background thread is a plain OS thread
//! owned by the Drainer; it terminates when `stop()` is called or
//! `Drainer` is dropped.

use std::collections::VecDeque;
use std::io::Write;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{error::Error, row::Row, store::Store};

const HW_WARN_PCT: f64 = 0.50;
const HW_ERR_PCT: f64 = 0.80;
const DEGRADED_AFTER: usize = 5;
const DLQ_RING_SIZE: usize = 10;

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
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn cv_wait_or_recover<'a, T>(cv: &Condvar, g: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    cv.wait(g).unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    lost_at_stop_total: usize,
    dlq: VecDeque<Row>,
}

struct DrainerInner {
    store: Box<dyn Store>,
    cfg: DrainerConfig,
    queue: Mutex<VecDeque<Row>>,
    queue_cv: Condvar,
    flush_cv: Condvar,
    slots: Sem,
    stop: AtomicBool,
    /// Set (under the stats lock) once the drain thread has returned.
    exited: AtomicBool,
    /// Set with `exited` if the drain thread ended by panicking.
    panicked: AtomicBool,
    stats: Mutex<InternalStats>,
    sys_log: Option<SysLog>,
    /// FFI calls still using this drainer; see `begin_call`.
    calls: Mutex<usize>,
    calls_cv: Condvar,
}

/// Receives each sys event as one JSON line (`shape`, `level`, `event`,
/// `timestamp` and the event's fields).
pub type SysLog = Arc<dyn Fn(&str) + Send + Sync>;

// SAFETY: `Box<dyn Store>` is `Send` (Store trait requires `Send`).
// The inner mutex protects all shared state.
unsafe impl Send for DrainerInner {}
unsafe impl Sync for DrainerInner {}

pub struct Drainer {
    inner: Arc<DrainerInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drainer {
    /// Sys events go to stderr.
    ///
    /// # Panics
    ///
    /// Panics if the OS cannot spawn the drain thread.
    pub fn new(store: Box<dyn Store>, cfg: DrainerConfig) -> Arc<Self> {
        Self::with_sys_log(store, cfg, None)
    }

    /// Like `new`, but sys events go to `sys_log` instead of stderr. It is
    /// called with no drainer lock held, from the drain thread or from the
    /// thread calling enqueue or stop.
    ///
    /// # Panics
    ///
    /// Panics if the OS cannot spawn the drain thread.
    pub fn with_sys_log(store: Box<dyn Store>, mut cfg: DrainerConfig, sys_log: Option<SysLog>) -> Arc<Self> {
        // Zero slots would block every enqueue forever, and stop() resets the
        // slots to the same zero, so nothing could wake them. Zero means the
        // default here, as it does at the C ABI.
        if cfg.capacity == 0 {
            cfg.capacity = DrainerConfig::default().capacity;
        }
        let capacity = cfg.capacity;
        let inner = Arc::new(DrainerInner {
            store,
            cfg,
            // Not preallocated: the slots bound the depth, and a large
            // capacity would otherwise allocate it all up front.
            queue: Mutex::new(VecDeque::new()),
            queue_cv: Condvar::new(),
            flush_cv: Condvar::new(),
            slots: Sem::new(capacity),
            stop: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            panicked: AtomicBool::new(false),
            stats: Mutex::new(InternalStats::default()),
            sys_log,
            calls: Mutex::new(0),
            calls_cv: Condvar::new(),
        });
        let inner2 = inner.clone();
        #[allow(clippy::expect_used)]
        let handle = thread::Builder::new()
            .name("fasten-drainer".into())
            .spawn(move || drain_loop(&inner2))
            .expect("spawn drainer thread");
        Arc::new(Self { inner, handle: Mutex::new(Some(handle)) })
    }

    /// Enqueue a row. Blocks when the queue is full (back-pressure).
    /// Returns `false` if the drainer is already stopped (row abandoned).
    pub fn enqueue(&self, row: Row) -> bool {
        if self.inner.stop.load(Ordering::SeqCst) {
            self.inner.sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                "reason": "drainer_stopped",
                "row_id": row.id,
            }));
            return false;
        }
        // Blocks while the queue is full.
        self.inner.slots.acquire();
        if self.inner.stop.load(Ordering::SeqCst) {
            // Shutdown raced us; release and abandon.
            self.inner.slots.release();
            self.inner.sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                "reason": "drainer_stopped",
                "row_id": row.id,
            }));
            return false;
        }
        // High-water mark and threshold events. The event goes out after the
        // stats lock is released.
        let capacity = self.inner.cfg.capacity;
        let depth = self.inner.slots.used();
        let threshold = {
            let mut st = lock_or_recover(&self.inner.stats);
            if depth > st.high_water {
                st.high_water = depth;
            }
            // Only compared with the high-water thresholds, so precision loss
            // on a huge capacity does not matter.
            #[allow(clippy::cast_precision_loss)]
            let ratio = depth as f64 / capacity as f64;
            if ratio >= HW_ERR_PCT && !st.err_hw_fired {
                st.err_hw_fired = true;
                Some(("error", "audit_queue_near_full"))
            } else if ratio >= HW_WARN_PCT && !st.warn_hw_fired {
                st.warn_hw_fired = true;
                Some(("warn", "audit_queue_high_water"))
            } else {
                if ratio < HW_WARN_PCT && (st.warn_hw_fired || st.err_hw_fired) {
                    st.warn_hw_fired = false;
                    st.err_hw_fired = false;
                }
                None
            }
        };
        if let Some((level, event)) = threshold {
            self.inner.sys_event(level, event, &serde_json::json!({
                "depth": depth, "capacity": capacity,
            }));
        }
        let mut q = lock_or_recover(&self.inner.queue);
        // stop() may have run since the check above, and the drain loop may
        // already have exited; under the queue lock this check is final.
        if self.inner.stop.load(Ordering::SeqCst) {
            drop(q);
            self.inner.slots.release();
            self.inner.sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                "reason": "drainer_stopped",
                "row_id": row.id,
            }));
            return false;
        }
        q.push_back(row);
        self.inner.queue_cv.notify_one();
        true
    }

    /// Block until all rows currently queued have been drained (or timeout).
    /// Returns `true` if fully drained within the deadline.
    pub fn flush(&self, timeout: Duration) -> bool {
        // Wait only for rows queued before this call: rows already finished
        // plus rows in flight now.
        let target = {
            let st = lock_or_recover(&self.inner.stats);
            st.drained_total + st.dead_lettered_total + st.lost_at_stop_total
                + self.inner.slots.used()
        };
        let deadline = Instant::now() + timeout;
        let mut st = lock_or_recover(&self.inner.stats);
        loop {
            let done = st.drained_total + st.dead_lettered_total + st.lost_at_stop_total;
            // Once stopping, slot counts no longer track queued rows; wait
            // for the drain thread, which handles every queued row first.
            let stopping = self.inner.stop.load(Ordering::SeqCst);
            if done >= target && !stopping {
                return true;
            }
            if self.inner.exited.load(Ordering::SeqCst) {
                return stopping && !self.inner.panicked.load(Ordering::SeqCst);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let result = self.inner.flush_cv.wait_timeout(st, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// Rows dead-lettered or lost at stop so far.
    pub fn unstored_total(&self) -> usize {
        let st = lock_or_recover(&self.inner.stats);
        st.dead_lettered_total + st.lost_at_stop_total
    }

    /// Snapshot queue stats as a JSON string.
    pub fn stats_json(&self) -> String {
        serde_json::to_string(&self.stats()).unwrap_or_else(|_| "{}".into())
    }

    /// Stop the drainer: signal the background thread to exit, then join.
    /// Remaining rows get one final drain attempt with no retry.
    /// The join has no timeout: the thread may be inside a host callback,
    /// and the host may drop that callback once stop returns. If the join
    /// takes longer than `timeout`, an `audit_drain_stop_slow` event says so.
    pub fn stop(&self, timeout: Duration) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.slots.release_all();
        {
            // Notify under the queue lock so the drain loop can't miss it
            // between its stop check and its wait.
            let _q = lock_or_recover(&self.inner.queue);
            self.inner.queue_cv.notify_all();
        }
        if let Some(h) = lock_or_recover(&self.handle).take() {
            let started = Instant::now();
            let joined = h.join();
            let depth = lock_or_recover(&self.inner.queue).len();
            if joined.is_err() {
                self.inner.sys_event("error", "audit_drain_abandoned", &serde_json::json!({
                    "reason": "drain_thread_panicked",
                    "depth": depth,
                }));
            } else if started.elapsed() > timeout {
                self.inner.sys_event("warn", "audit_drain_stop_slow", &serde_json::json!({
                    "waited_seconds": started.elapsed().as_secs_f64(),
                }));
            }
        }
    }
}

impl Drop for Drainer {
    fn drop(&mut self) {
        self.stop(Duration::from_secs(2));
    }
}

fn drain_loop(inner: &Arc<DrainerInner>) {
    // Runs on normal return and on panic, so flush never waits on a dead thread.
    struct Exit<'a>(&'a DrainerInner);
    impl Drop for Exit<'_> {
        fn drop(&mut self) {
            let _st = lock_or_recover(&self.0.stats);
            self.0.panicked.store(thread::panicking(), Ordering::SeqCst);
            self.0.exited.store(true, Ordering::SeqCst);
            self.0.flush_cv.notify_all();
        }
    }
    let _exit = Exit(inner);
    drain_rows(inner);
}

fn drain_rows(inner: &Arc<DrainerInner>) {
    loop {
        let row = {
            let mut q = lock_or_recover(&inner.queue);
            loop {
                if let Some(r) = q.pop_front() {
                    break r;
                }
                if inner.stop.load(Ordering::Acquire) {
                    return;
                }
                q = inner.queue_cv.wait_timeout(q, Duration::from_secs(1))
                    .unwrap_or_else(std::sync::PoisonError::into_inner).0;
                if inner.stop.load(Ordering::Acquire) && q.is_empty() {
                    return;
                }
            }
        };

        let mut attempt = 0usize;
        let in_shutdown = inner.stop.load(Ordering::Relaxed);

        loop {
            // Don't let a panicking Store impl kill the thread.
            let call = panic::catch_unwind(panic::AssertUnwindSafe(|| inner.store.insert(&row)));
            let Ok(result) = call else {
                if in_shutdown || inner.stop.load(Ordering::Acquire) {
                    on_lost_at_stop(inner, &row, "panic");
                } else {
                    on_dead_letter(inner, &row, attempt + 1, "store.insert panicked");
                }
                break;
            };
            match result {
                Ok(()) => {
                    on_success(inner);
                    break;
                }
                Err(e) => {
                    let msg = error_text(&e);
                    attempt += 1;
                    // Spec §10: no retry once stopping. Spec §3: no retry for
                    // a row the store rejected.
                    if in_shutdown || inner.stop.load(Ordering::Acquire) {
                        on_lost_at_stop(inner, &row, &error_type(&e));
                        break;
                    }
                    if attempt >= inner.cfg.max_attempts || rejected(&e, &row) {
                        on_dead_letter(inner, &row, attempt, &msg);
                        break;
                    }
                    // Sleep the backoff on_failure reported, in short steps so
                    // stop() takes effect quickly.
                    let backoff = on_failure(inner, &msg, attempt);
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

/// The store refused the row itself, so retrying cannot help: an insert
/// callback returned a negative code (`FASTEN_INSERT_REJECTED`), a store
/// reported `RowRejected`, the database refused the data (see
/// `sqlstate_rejects_row` and `sqlite_rejects_row`), or a row with an
/// explicit seq clashed. A seq-0 row gets a fresh seq on the next attempt,
/// so its clash is retried. For the SDK's stores; not a stable API.
#[doc(hidden)]
pub fn rejected(e: &Error, row: &Row) -> bool {
    match e {
        Error::CallbackFailed(rc) => *rc < 0,
        Error::RowRejected(_) => true,
        Error::SeqClash(_) => row.monotonic_seq != 0,
        #[cfg(feature = "postgres")]
        Error::Postgres(pg) => pg.code().is_some_and(|c| sqlstate_rejects_row(c.code())),
        #[cfg(feature = "sqlite")]
        Error::Sqlite(e) => sqlite_rejects_row(e),
        _ => false,
    }
}

/// SQLSTATE classes that mean the statement can never succeed for this row:
/// 22 data exception, 23 integrity constraint violation, 54 program limit
/// exceeded (for example a value too long for an index). Class 42 (syntax
/// error or access rule violation) is retried: it is usually the deploy, a
/// revoked grant or a table renamed mid-migration, not the row. Connection
/// and resource errors are retried too.
pub fn sqlstate_rejects_row(sqlstate: &str) -> bool {
    matches!(sqlstate.get(..2), Some("22" | "23" | "54"))
}

/// `SQLite`'s constraint and datatype-mismatch errors.
#[cfg(feature = "sqlite")]
fn sqlite_rejects_row(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation | rusqlite::ErrorCode::TypeMismatch)
    )
}

/// The variant name, e.g. `CallbackFailed`, or the type a `Store` or
/// `RowRejected` error carries when it is a bare identifier, such as the
/// Rust SDK's `AuditStoreRejected`. One built in this crate carries a
/// message, which can name rows and nodes, so it is recorded by the
/// variant name.
fn error_type(e: &Error) -> String {
    let debug = format!("{e:?}");
    let variant = debug.split(['(', ' ', '{']).next().unwrap_or_default();
    match e {
        Error::Store(t) | Error::RowRejected(t) if is_identifier(t) => t.clone(),
        _ => variant.to_owned(),
    }
}

/// `[A-Za-z_][A-Za-z0-9_]*`: a type name, not a message.
fn is_identifier(t: &str) -> bool {
    let mut chars = t.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// What `error` and `last_error` record for `e`: its type, as
/// spec/drainer-conformance.md asks. A callback's return code is kept, as
/// it is the host's own value.
fn error_text(e: &Error) -> String {
    match e {
        Error::CallbackFailed(_) => e.to_string(),
        _ => error_type(e),
    }
}

fn on_success(inner: &DrainerInner) {
    let mut st = lock_or_recover(&inner.stats);
    // Spec: recovered fires when an insert succeeds after one or more
    // failures. A dead letter leaves failure_burst_at set for this reason,
    // so a success straight after one still counts.
    let recovering = st.failure_burst_at.is_some();
    let recovery_secs = if recovering {
        st.failure_burst_at.map_or(0.0, |t| t.elapsed().as_secs_f64())
    } else {
        0.0
    };
    st.retry_count = 0;
    st.in_backoff_until = None;
    st.failure_burst_at = None;
    st.last_error = None;
    st.degraded_fired = false;
    drop(st);
    // The event goes out before the row counts as drained, so it is visible
    // once flush returns.
    if recovering {
        let r = (recovery_secs * 1000.0).round() / 1000.0;
        inner.sys_event("info", "audit_drain_recovered", &serde_json::json!({
            "recovery_after_seconds": r,
        }));
    }
    // Count and release together, so flush's target (counted + used) never
    // sees the row twice.
    let mut st = lock_or_recover(&inner.stats);
    st.drained_total += 1;
    inner.slots.release();
    drop(st);
    inner.flush_cv.notify_all();
}

/// Records the failure and returns the backoff to sleep, the same one
/// `in_backoff_until` and `audit_drain_degraded` report.
fn on_failure(inner: &DrainerInner, msg: &str, attempt: usize) -> Duration {
    let mut st = lock_or_recover(&inner.stats);
    // Spec: audit_drain_failed fires when retry_count goes from 0 to 1, so
    // once per failing row, a row after a dead letter included.
    let first = st.retry_count == 0;
    if st.failure_burst_at.is_none() {
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
        inner.sys_event("warn", "audit_drain_failed", &serde_json::json!({ "error": msg }));
    }
    if should_degraded {
        let st2 = lock_or_recover(&inner.stats);
        let remaining = st2.in_backoff_until
            .map_or(0.0, |t| {
                let r = t.saturating_duration_since(Instant::now()).as_secs_f64();
                (r * 1000.0).round() / 1000.0
            });
        drop(st2);
        lock_or_recover(&inner.stats).degraded_fired = true;
        inner.sys_event("error", "audit_drain_degraded", &serde_json::json!({
            "retry_count": attempt,
            "in_backoff_seconds": remaining,
            "last_error": msg,
        }));
    }
    backoff
}

fn on_dead_letter(inner: &DrainerInner, row: &Row, attempts: usize, msg: &str) {
    // As in on_success, the event goes out before the row counts as handled.
    inner.sys_event("error", "audit_drain_dead_letter", &serde_json::json!({
        "row_id": row.id,
        "attempt_count": attempts,
        "last_error": msg,
    }));
    let mut st = lock_or_recover(&inner.stats);
    st.dead_lettered_total += 1;
    if st.dlq.len() >= DLQ_RING_SIZE {
        st.dlq.pop_front();
    }
    st.dlq.push_back(row.clone());
    // The next row starts its own retries, and its first failure reports
    // audit_drain_failed again. failure_burst_at is kept until a row is
    // stored, so that success reports audit_drain_recovered.
    st.retry_count = 0;
    st.in_backoff_until = None;
    inner.slots.release();
    drop(st);
    inner.flush_cv.notify_all();
}

fn on_lost_at_stop(inner: &DrainerInner, row: &Row, error_type: &str) {
    inner.sys_event("error", "audit_drain_lost_at_stop", &serde_json::json!({
        "error_type": error_type,
        "row_id": row.id,
    }));
    let mut st = lock_or_recover(&inner.stats);
    st.lost_at_stop_total += 1;
    inner.slots.release();
    drop(st);
    inner.flush_cv.notify_all();
}

fn compute_backoff_val(
    attempt: usize,
    initial: Duration,
    max: Duration,
    jitter: bool,
) -> Duration {
    // At most 63, so it fits in a u32.
    #[allow(clippy::cast_possible_truncation)]
    let shift = attempt.saturating_sub(1).min(63) as u32;
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base = initial * factor.try_into().unwrap_or(u32::MAX);
    let capped = base.min(max);
    if !jitter {
        return capped;
    }
    // +/-20% jitter, seeded from the clock's subsecond nanos (no rand dependency).
    // Only a retry_max over u64::MAX ms (about 584 million years) would truncate.
    #[allow(clippy::cast_possible_truncation)]
    let ms = capped.as_millis() as u64;
    let jitter_range = ms / 5;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345);
    let j = u64::from(seed) % (jitter_range * 2 + 1);
    let jittered = ms.saturating_add(j).saturating_sub(jitter_range);
    Duration::from_millis(jittered)
}

impl DrainerInner {
    fn sys_event(&self, level: &str, event: &str, fields: &serde_json::Value) {
        match &self.sys_log {
            // A panicking host sink must not take the drain thread down.
            Some(sink) => {
                let line = sys_line(level, event, fields);
                let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| sink(&line)));
            }
            None => {
                let _ = writeln!(std::io::stderr(), "{}", sys_line(level, event, fields));
            }
        }
    }
}

/// Ends a call started by `Drainer::begin_call`.
pub(crate) struct CallGuard(Arc<DrainerInner>);

impl Drop for CallGuard {
    fn drop(&mut self) {
        *lock_or_recover(&self.0.calls) -= 1;
        self.0.calls_cv.notify_all();
    }
}

impl Drainer {
    /// Count a call that may emit through the sys sink. The FFI starts it
    /// under the handle's drainer lock, so none starts once the drainer is
    /// taken off the handle, and `wait_calls` then bounds the rest.
    pub(crate) fn begin_call(&self) -> CallGuard {
        *lock_or_recover(&self.inner.calls) += 1;
        CallGuard(Arc::clone(&self.inner))
    }

    /// Wait until no call started by `begin_call` is running. After stop
    /// these calls return promptly: enqueue is refused and its wait released.
    pub(crate) fn wait_calls(&self) {
        let mut n = lock_or_recover(&self.inner.calls);
        while *n > 0 {
            n = self.inner.calls_cv.wait(n).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    #[cfg(test)]
    pub(crate) fn calls_in_flight(&self) -> usize {
        *lock_or_recover(&self.inner.calls)
    }

    /// Emit a sys event through this drainer's sink (stderr when it has none).
    pub(crate) fn sys_event(&self, level: &str, event: &str, fields: &serde_json::Value) {
        self.inner.sys_event(level, event, fields);
    }
}

fn sys_line(level: &str, event: &str, fields: &serde_json::Value) -> String {
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
    serde_json::to_string(&obj).unwrap_or_default()
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use crate::store::Filter;

    struct OkStore;

    impl Store for OkStore {
        fn insert(&self, _: &Row) -> Result<(), crate::error::Error> { Ok(()) }
        fn ping(&self) -> Result<(), crate::error::Error> { Ok(()) }
        fn query(&self, _: &Filter) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn count(&self, _: &Filter) -> Result<u64, crate::error::Error> { Ok(0) }
        fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn mark_shipped(&self, _: &[String]) -> Result<(), crate::error::Error> { Ok(()) }
        fn purge(&self, _: &str, _: bool) -> Result<u64, crate::error::Error> { Ok(0) }
        fn max_monotonic_seq(&self) -> Result<u64, crate::error::Error> { Ok(0) }
    }

    /// A slot flush counts but whose row never gets queued, as when enqueue
    /// is refused at stop: flush must return once the drain thread is gone.
    #[test]
    fn flush_returns_once_the_drain_thread_has_exited() {
        let d = Drainer::new(Box::new(OkStore), DrainerConfig {
            capacity: 4,
            retry_initial: Duration::from_millis(5),
            retry_max: Duration::from_millis(5),
            retry_jitter: false,
            max_attempts: 3,
        });
        d.stop(Duration::from_secs(2));
        d.inner.slots.acquire();
        let start = Instant::now();
        assert!(d.flush(Duration::from_secs(30)));
        assert!(start.elapsed() < Duration::from_secs(5), "flush waited for its timeout");
    }

    /// A zero capacity takes the default instead of blocking every enqueue.
    #[test]
    fn zero_capacity_takes_the_default() {
        let d = Drainer::new(Box::new(OkStore), DrainerConfig {
            capacity: 0,
            retry_initial: Duration::from_millis(5),
            retry_max: Duration::from_millis(5),
            retry_jitter: false,
            max_attempts: 3,
        });
        assert_eq!(d.stats().capacity, DrainerConfig::default().capacity);
        let (tx, rx) = std::sync::mpsc::channel();
        let d2 = d.clone();
        thread::spawn(move || {
            let _ = tx.send(d2.enqueue(Row { id: "r-1".into(), ..Row::default() }));
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true), "enqueue blocked");
        assert!(d.flush(Duration::from_secs(5)));
        d.stop(Duration::from_secs(2));
    }

    struct TypedFailStore(Arc<std::sync::atomic::AtomicUsize>);

    impl Store for TypedFailStore {
        fn insert(&self, _: &Row) -> Result<(), crate::error::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(crate::error::Error::Store("PgError".into()))
        }
        fn ping(&self) -> Result<(), crate::error::Error> { Ok(()) }
        fn query(&self, _: &Filter) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn count(&self, _: &Filter) -> Result<u64, crate::error::Error> { Ok(0) }
        fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn mark_shipped(&self, _: &[String]) -> Result<(), crate::error::Error> { Ok(()) }
        fn purge(&self, _: &str, _: bool) -> Result<u64, crate::error::Error> { Ok(0) }
        fn max_monotonic_seq(&self) -> Result<u64, crate::error::Error> { Ok(0) }
    }

    /// What the drainer records for an error: its type, never a message
    /// that names a row or node.
    #[test]
    fn errors_are_recorded_by_type() {
        assert_eq!(error_text(&Error::Store("PgError".into())), "PgError");
        assert_eq!(error_text(&Error::Store("row evt-1: not inserted and not stored".into())), "Store");
        assert_eq!(error_text(&Error::Store("node 'n-1': next monotonic_seq -1 is negative".into())), "Store");
        assert_eq!(error_text(&Error::Store(String::new())), "Store");
        assert_eq!(error_text(&Error::Store("42P01".into())), "Store");
        assert_eq!(error_text(&Error::RowRejected("row evt-1: differs".into())), "RowRejected");
        assert_eq!(error_text(&Error::RowRejected("AuditStoreRejected".into())), "AuditStoreRejected");
        assert_eq!(error_text(&Error::RowRejected("_Rejected2".into())), "_Rejected2");
        assert_eq!(error_text(&Error::RowRejected("2Rejected".into())), "RowRejected");
        assert_eq!(error_text(&Error::RowRejected("value too long".into())), "RowRejected");
        assert_eq!(error_text(&Error::RowRejected(String::new())), "RowRejected");
        assert_eq!(error_text(&Error::SeqClash("row evt-1: seq 3".into())), "SeqClash");
        assert_eq!(error_text(&Error::CallbackFailed(-2)), "insert callback returned non-zero rc=-2");
    }

    struct RejectingStore(Arc<std::sync::atomic::AtomicUsize>);

    impl Store for RejectingStore {
        fn insert(&self, row: &Row) -> Result<(), crate::error::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if row.id == "bad" {
                return Err(crate::error::Error::RowRejected("DataError".into()));
            }
            Ok(())
        }
        fn ping(&self) -> Result<(), crate::error::Error> { Ok(()) }
        fn query(&self, _: &Filter) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn count(&self, _: &Filter) -> Result<u64, crate::error::Error> { Ok(0) }
        fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn mark_shipped(&self, _: &[String]) -> Result<(), crate::error::Error> { Ok(()) }
        fn purge(&self, _: &str, _: bool) -> Result<u64, crate::error::Error> { Ok(0) }
        fn max_monotonic_seq(&self) -> Result<u64, crate::error::Error> { Ok(0) }
    }

    /// A row the store rejects is dead-lettered after one attempt, and the
    /// rows behind it are stored.
    #[test]
    fn rejected_row_is_dead_lettered_at_once() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let d = Drainer::new(Box::new(RejectingStore(attempts.clone())), DrainerConfig {
            capacity: 4,
            retry_initial: Duration::from_secs(60),
            retry_max: Duration::from_secs(60),
            retry_jitter: false,
            max_attempts: 50,
        });
        assert!(d.enqueue(Row { id: "bad".into(), ..Row::default() }));
        assert!(d.enqueue(Row { id: "good".into(), ..Row::default() }));
        assert!(d.flush(Duration::from_secs(5)), "the queue did not drain");
        let stats = d.stats();
        assert_eq!(stats.dead_lettered_total, 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "one attempt per row");
        d.stop(Duration::from_secs(2));
    }

    #[test]
    fn sqlstate_classes_that_reject_a_row() {
        for code in ["22021", "23505", "54000"] {
            assert!(sqlstate_rejects_row(code), "{code}");
        }
        for code in ["08006", "40001", "42501", "42P01", "53300", "57P01", "", "2"] {
            assert!(!sqlstate_rejects_row(code), "{code}");
        }
    }

    /// A `Store` error is retried and reported by the type it carries.
    #[test]
    fn store_error_is_retried_and_reported_by_type() {
        let events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sink = events.clone();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let d = Drainer::with_sys_log(Box::new(TypedFailStore(attempts.clone())), DrainerConfig {
            capacity: 4,
            retry_initial: Duration::from_millis(5),
            retry_max: Duration::from_millis(5),
            retry_jitter: false,
            max_attempts: 50,
        }, Some(Arc::new(move |line: &str| {
            sink.lock().unwrap().push(serde_json::from_str(line).unwrap());
        })));
        assert!(d.enqueue(Row { id: "r-1".into(), ..Row::default() }));
        let deadline = Instant::now() + Duration::from_secs(5);
        while attempts.load(Ordering::SeqCst) < 3 {
            assert!(Instant::now() < deadline, "row was not retried");
            thread::sleep(Duration::from_millis(5));
        }
        let stats = d.stats();
        assert_eq!(stats.last_error.as_deref(), Some("PgError"));
        assert_eq!(stats.dead_lettered_total, 0);
        d.stop(Duration::from_secs(2));

        let events = events.lock().unwrap();
        let find = |name: &str| events.iter().find(|e| e["event"] == name).cloned();
        assert_eq!(find("audit_drain_failed").unwrap()["error"], "PgError");
        assert!(find("audit_drain_dead_letter").is_none());
        assert_eq!(find("audit_drain_lost_at_stop").unwrap()["error_type"], "PgError");
    }

    struct ErrStore(fn() -> crate::error::Error, Arc<std::sync::atomic::AtomicUsize>);

    impl Store for ErrStore {
        fn insert(&self, _: &Row) -> Result<(), crate::error::Error> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Err((self.0)())
        }
        fn ping(&self) -> Result<(), crate::error::Error> { Ok(()) }
        fn query(&self, _: &Filter) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn count(&self, _: &Filter) -> Result<u64, crate::error::Error> { Ok(0) }
        fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn mark_shipped(&self, _: &[String]) -> Result<(), crate::error::Error> { Ok(()) }
        fn purge(&self, _: &str, _: bool) -> Result<u64, crate::error::Error> { Ok(0) }
        fn max_monotonic_seq(&self) -> Result<u64, crate::error::Error> { Ok(0) }
    }

    /// Fails the first `fails` inserts, then succeeds.
    struct FailFirstStore(usize, Arc<std::sync::atomic::AtomicUsize>);

    impl Store for FailFirstStore {
        fn insert(&self, _: &Row) -> Result<(), crate::error::Error> {
            if self.1.fetch_add(1, Ordering::SeqCst) < self.0 {
                Err(crate::error::Error::Store("PgError".into()))
            } else {
                Ok(())
            }
        }
        fn ping(&self) -> Result<(), crate::error::Error> { Ok(()) }
        fn query(&self, _: &Filter) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn count(&self, _: &Filter) -> Result<u64, crate::error::Error> { Ok(0) }
        fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, crate::error::Error> { Ok(vec![]) }
        fn mark_shipped(&self, _: &[String]) -> Result<(), crate::error::Error> { Ok(()) }
        fn purge(&self, _: &str, _: bool) -> Result<u64, crate::error::Error> { Ok(0) }
        fn max_monotonic_seq(&self) -> Result<u64, crate::error::Error> { Ok(0) }
    }

    /// Drains `ids` through `store` with `max_attempts` and returns the
    /// `audit_drain_*` events in order. Queue high-water events are left out.
    fn drain_events(store: Box<dyn Store>, max_attempts: usize, ids: &[&str]) -> Vec<String> {
        let events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sink = events.clone();
        let d = Drainer::with_sys_log(store, DrainerConfig {
            capacity: 4,
            retry_initial: Duration::from_millis(5),
            retry_max: Duration::from_millis(5),
            retry_jitter: false,
            max_attempts,
        }, Some(Arc::new(move |line: &str| {
            sink.lock().unwrap().push(serde_json::from_str(line).unwrap());
        })));
        for id in ids {
            assert!(d.enqueue(Row { id: (*id).into(), ..Row::default() }));
        }
        assert!(d.flush(Duration::from_secs(5)), "the queue did not drain");
        assert_eq!(d.stats().last_error, None, "the last row was stored");
        d.stop(Duration::from_secs(2));
        let names = events.lock().unwrap().iter()
            .map(|e| e["event"].as_str().unwrap_or_default().to_owned())
            .filter(|n| n.starts_with("audit_drain_"))
            .collect();
        names
    }

    fn fail_first(n: usize) -> Box<dyn Store> {
        Box::new(FailFirstStore(n, Arc::new(std::sync::atomic::AtomicUsize::new(0))))
    }

    /// A row stored straight after a dead letter reports
    /// `audit_drain_recovered`: it succeeds after failures (spec §4).
    #[test]
    fn recovery_is_reported_right_after_a_dead_letter() {
        assert_eq!(
            drain_events(fail_first(2), 2, &["a", "b"]),
            ["audit_drain_failed", "audit_drain_dead_letter", "audit_drain_recovered"],
        );
    }

    /// The row after a dead letter reports its own first failure, as
    /// `retry_count` goes from 0 to 1 again, and recovery once it is stored.
    #[test]
    fn row_after_a_dead_letter_reports_its_own_failure() {
        assert_eq!(
            drain_events(fail_first(3), 2, &["a", "b"]),
            ["audit_drain_failed", "audit_drain_dead_letter", "audit_drain_failed", "audit_drain_recovered"],
        );
    }

    /// A row rejected on its first attempt is no failure burst: the next
    /// stored row reports no recovery.
    #[test]
    fn rejected_row_then_success_reports_no_recovery() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        assert_eq!(
            drain_events(Box::new(RejectingStore(attempts)), 50, &["bad", "good"]),
            ["audit_drain_dead_letter"],
        );
    }

    /// `error` and `last_error` hold the error's type; a callback's code
    /// is kept.
    #[test]
    fn failures_are_recorded_by_type() {
        let cases: [(fn() -> crate::error::Error, &str); 2] = [
            (|| crate::error::Error::InvalidTimestamp("acct-12345 2026-13-01".into()), "InvalidTimestamp"),
            (|| crate::error::Error::CallbackFailed(7), "insert callback returned non-zero rc=7"),
        ];
        for (make, want) in cases {
            let events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let sink = events.clone();
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let d = Drainer::with_sys_log(Box::new(ErrStore(make, attempts.clone())), DrainerConfig {
                capacity: 4,
                retry_initial: Duration::from_millis(5),
                retry_max: Duration::from_millis(5),
                retry_jitter: false,
                max_attempts: 2,
            }, Some(Arc::new(move |line: &str| {
                sink.lock().unwrap().push(serde_json::from_str(line).unwrap());
            })));
            assert!(d.enqueue(Row { id: "r-1".into(), ..Row::default() }));
            let deadline = Instant::now() + Duration::from_secs(5);
            while d.stats().dead_lettered_total == 0 {
                assert!(Instant::now() < deadline, "row was not dead-lettered");
                thread::sleep(Duration::from_millis(5));
            }
            d.stop(Duration::from_secs(2));
            let events = events.lock().unwrap();
            let find = |name: &str| events.iter().find(|e| e["event"] == name).cloned().unwrap();
            assert_eq!(find("audit_drain_failed")["error"], want);
            assert_eq!(find("audit_drain_dead_letter")["last_error"], want);
        }
    }

    /// A row the Rust SDK's store rejects reaches the drainer as
    /// `RowRejected("AuditStoreRejected")`, and is dead-lettered under that
    /// name; a rejection carrying a message is recorded as `RowRejected`.
    #[test]
    fn rejected_row_is_recorded_by_the_type_it_carries() {
        let cases: [(fn() -> crate::error::Error, &str); 2] = [
            (|| crate::error::Error::RowRejected("AuditStoreRejected".into()), "AuditStoreRejected"),
            (|| crate::error::Error::RowRejected("row r-1: differs".into()), "RowRejected"),
        ];
        for (make, want) in cases {
            let events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let sink = events.clone();
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let d = Drainer::with_sys_log(Box::new(ErrStore(make, attempts.clone())), DrainerConfig {
                capacity: 4,
                retry_initial: Duration::from_secs(60),
                retry_max: Duration::from_secs(60),
                retry_jitter: false,
                max_attempts: 50,
            }, Some(Arc::new(move |line: &str| {
                sink.lock().unwrap().push(serde_json::from_str(line).unwrap());
            })));
            assert!(d.enqueue(Row { id: "r-1".into(), ..Row::default() }));
            assert!(d.flush(Duration::from_secs(5)), "the queue did not drain");
            d.stop(Duration::from_secs(2));
            assert_eq!(attempts.load(Ordering::SeqCst), 1, "one attempt");
            let events = events.lock().unwrap();
            let dead = events.iter().find(|e| e["event"] == "audit_drain_dead_letter").cloned().unwrap();
            assert_eq!(dead["last_error"], want);
        }
    }

}
