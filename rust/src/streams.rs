//! The api and sys streams (spec persistent-streams.md): each keeps its
//! recent rows in memory and, with a stream store attached, writes every
//! row through to it.
//!
//! A row is pushed to the ring at once and queued for the store; one thread
//! per stream writes the queue in order. A failed or dropped write keeps the
//! stdout line, marks the stream degraded for good, and is reported on
//! stderr by error type only, rate-limited during an outage.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

pub use fasten_core::store::stream::{StreamFilter, StreamRow};

use crate::Error;

/// The sentinel `request_id` kinds (spec §7).
pub const SENTINEL_KINDS: [&str; 5] = ["boot", "sched", "bg", "lib", "orphan"];

/// A sentinel request id such as `orphan-svc-ab12cd34ef56`, for rows
/// written outside a request (spec §7). `kind` is one of
/// [`SENTINEL_KINDS`]; an empty `service_id` is written as `svc`.
pub fn mint_sentinel(kind: &str, service_id: &str) -> Result<String, Error> {
    if !SENTINEL_KINDS.contains(&kind) {
        return Err(Error::InvalidConfig(format!(
            "unknown sentinel kind {kind:?}; expected one of {}",
            SENTINEL_KINDS.join(", ")
        )));
    }
    let svc = if service_id.is_empty() { "svc" } else { service_id };
    Ok(format!("{kind}-{svc}-{}", crate::mint_id()))
}

/// Whether `request_id` starts with a sentinel prefix such as `boot-`.
pub fn is_sentinel(request_id: &str) -> bool {
    SENTINEL_KINDS.iter().any(|k| request_id.strip_prefix(k).is_some_and(|rest| rest.starts_with('-')))
}

/// A durable store behind the api or sys stream: the same table layout in
/// every SDK (spec §2), so one SDK reads what another wrote.
///
/// [`crate::SqliteStreamStore`] and [`crate::PostgresStreamStore`]
/// implement it. Reads return rows newest first; every filter is an exact
/// match.
pub trait StreamStore: Send + Sync {
    /// Store one row. Called from the stream's writer thread, one row at a
    /// time in push order. Must not be run again after a lost connection,
    /// since the first attempt may have committed.
    fn insert(&self, row: &StreamRow) -> Result<(), Error>;

    /// Up to `limit` rows matching `filter`, newest first; 0 means no
    /// limit.
    fn query(&self, filter: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error>;

    /// How many rows match `filter`, with no limit.
    fn count_matching(&self, filter: &StreamFilter) -> Result<u64, Error>;

    /// How many rows the table holds.
    fn count(&self) -> Result<u64, Error> {
        self.count_matching(&StreamFilter::default())
    }

    /// Case-insensitive substring search of the stored JSON within
    /// `[since, until]`, newest first (spec §9), at most `limit` rows (0
    /// for all). `%`, `_` and `\` in `q` match literally.
    fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Result<Vec<StreamRow>, Error>;

    /// Delete rows with a timestamp before `before`; rows without one are
    /// kept (spec §10). Returns how many were deleted.
    fn purge(&self, before: DateTime<Utc>) -> Result<u64, Error>;

    /// Record a write that failed and was dropped. Any at all makes the
    /// stream `store-degraded` (spec §6.1).
    fn note_write_failure(&self) {}

    /// Whether a write to this store has failed and been dropped.
    fn degraded(&self) -> bool {
        false
    }
}

/// Rows kept in memory per stream.
pub(crate) const RING_SIZE: usize = 2000;

/// Rows waiting on one store at most; past that a row is dropped and
/// counted as a failed write.
pub(crate) const MAX_PENDING: usize = 10_000;

/// During an outage stderr gets the first failure, then one line with the
/// count at most this often.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// The newest rows of one stream, newest first.
pub(crate) struct Ring {
    max: usize,
    rows: Mutex<VecDeque<StreamRow>>,
}

impl Ring {
    pub(crate) fn new(max: usize) -> Self {
        Self { max, rows: Mutex::new(VecDeque::new()) }
    }

    fn push(&self, row: StreamRow) {
        if self.max == 0 {
            return;
        }
        let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        rows.push_front(row);
        rows.truncate(self.max);
    }

    pub(crate) fn len(&self) -> usize {
        self.rows.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn query(&self, filter: &StreamFilter, limit: usize) -> Vec<StreamRow> {
        let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        rows.iter().filter(|r| filter.matches(r)).take(limit).cloned().collect()
    }

    fn count(&self, filter: &StreamFilter) -> u64 {
        let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        rows.iter().filter(|r| filter.matches(r)).count() as u64
    }
}

#[derive(Default)]
struct Queue {
    rows: VecDeque<StreamRow>,
    in_flight: bool,
    stop: bool,
}

struct Writer {
    queue: Mutex<Queue>,
    work: Condvar,
    idle: Condvar,
}

impl Writer {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Failures since the last stderr line, and when that line was written.
#[derive(Default)]
struct Outage {
    unreported: u64,
    reported_at: Option<Instant>,
}

/// One stream: its ring and, when attached, its store and writer thread.
pub(crate) struct Stream {
    name: &'static str,
    ring: Ring,
    store: Option<Arc<dyn StreamStore>>,
    writer: Arc<Writer>,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Whether the writer thread started. Without it rows are not queued.
    has_writer: bool,
    write_failures: Arc<AtomicU64>,
    outage: Arc<Mutex<Outage>>,
}

impl Stream {
    pub(crate) fn new(name: &'static str, store: Option<Arc<dyn StreamStore>>) -> Self {
        let mut s = Self {
            name,
            ring: Ring::new(RING_SIZE),
            store,
            writer: Arc::new(Writer { queue: Mutex::new(Queue::default()), work: Condvar::new(), idle: Condvar::new() }),
            thread: Mutex::new(None),
            has_writer: false,
            write_failures: Arc::new(AtomicU64::new(0)),
            outage: Arc::new(Mutex::new(Outage::default())),
        };
        if let Some(store) = s.store.clone() {
            let ctx = WriterCtx {
                label: s.label(),
                writer: Arc::clone(&s.writer),
                store,
                failures: Arc::clone(&s.write_failures),
                outage: Arc::clone(&s.outage),
            };
            match std::thread::Builder::new().name(format!("fasten-{name}-persist")).spawn(move || ctx.run()) {
                Ok(handle) => {
                    *s.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
                    s.has_writer = true;
                }
                Err(e) => stderr_line(&format!("fasten: {} persist writer not started: {:?}", s.label(), e.kind())),
            }
        }
        s
    }

    /// "syslog" or "api", as the other SDKs name the stream on stderr.
    fn label(&self) -> &'static str {
        if self.name == "sys" { "syslog" } else { "api" }
    }

    pub(crate) fn ring_len(&self) -> usize {
        self.ring.len()
    }

    /// Keep `row` in the ring and queue it for the store.
    pub(crate) fn push(&self, row: StreamRow) {
        let Some(store) = &self.store else {
            self.ring.push(row);
            return;
        };
        self.ring.push(row.clone());
        if !self.has_writer {
            failed(self.label(), "NoWriter", store.as_ref(), &self.write_failures, &self.outage);
            return;
        }
        let mut q = self.writer.lock();
        if q.stop {
            // A push racing a re-init that retired this stream. The store
            // may serve the next streams, so only this stream counts it.
            drop(q);
            self.write_failures.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if q.rows.len() + usize::from(q.in_flight) >= MAX_PENDING {
            drop(q);
            failed(self.label(), "QueueFull", store.as_ref(), &self.write_failures, &self.outage);
            return;
        }
        q.rows.push_back(row);
        self.writer.work.notify_one();
    }

    /// Wait until every queued row has been written, or `deadline` passes.
    /// True when nothing is left.
    pub(crate) fn flush(&self, deadline: Instant) -> bool {
        if self.store.is_none() || !self.has_writer {
            return true;
        }
        let mut q = self.writer.lock();
        loop {
            if q.rows.is_empty() && !q.in_flight {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            q = self.writer.idle.wait_timeout(q, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// Flush within `deadline`, then stop the writer. Rows still queued are
    /// written by the thread on its own; it is not waited for past the
    /// deadline.
    pub(crate) fn close(&self, deadline: Instant) -> bool {
        let flushed = self.flush(deadline);
        self.writer.lock().stop = true;
        self.writer.work.notify_all();
        let handle = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            while !h.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
        flushed
    }

    /// Rows queued or being written.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        let q = self.writer.lock();
        q.rows.len() + usize::from(q.in_flight)
    }

    /// `ring`, `store` or `store-degraded` (spec §6).
    pub(crate) fn source(&self) -> &'static str {
        match &self.store {
            None => "ring",
            Some(s) if s.degraded() || self.write_failures.load(Ordering::Relaxed) > 0 => "store-degraded",
            Some(_) => "store",
        }
    }

    pub(crate) fn query(&self, filter: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        match &self.store {
            Some(s) => s.query(filter, limit),
            None => Ok(self.ring.query(filter, if limit == 0 { usize::MAX } else { limit as usize })),
        }
    }

    pub(crate) fn count_matching(&self, filter: &StreamFilter) -> Result<u64, Error> {
        match &self.store {
            Some(s) => s.count_matching(filter),
            None => Ok(self.ring.count(filter)),
        }
    }

    /// Search covers stored history only: `None` without a store.
    pub(crate) fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Option<Result<Vec<StreamRow>, Error>> {
        self.store.as_ref().map(|s| s.search(q, since, until, limit))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.writer.lock().stop = true;
        self.writer.work.notify_all();
    }
}

struct WriterCtx {
    label: &'static str,
    writer: Arc<Writer>,
    store: Arc<dyn StreamStore>,
    failures: Arc<AtomicU64>,
    outage: Arc<Mutex<Outage>>,
}

impl WriterCtx {
    fn run(self) {
        loop {
            let row = {
                let mut q = self.writer.lock();
                loop {
                    if let Some(row) = q.rows.pop_front() {
                        q.in_flight = true;
                        break row;
                    }
                    if q.stop {
                        return;
                    }
                    q = self.writer.work.wait(q).unwrap_or_else(|e| e.into_inner());
                }
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.store.insert(&row)));
            match result {
                Ok(Ok(())) => stored(self.label, &self.outage),
                Ok(Err(e)) => failed(self.label, crate::retention::error_type(&e), self.store.as_ref(), &self.failures, &self.outage),
                Err(_) => failed(self.label, "Panic", self.store.as_ref(), &self.failures, &self.outage),
            }
            let mut q = self.writer.lock();
            q.in_flight = false;
            if q.rows.is_empty() {
                self.writer.idle.notify_all();
            }
        }
    }
}

/// A write succeeded: failures not yet reported get their line now.
fn stored(label: &str, outage: &Mutex<Outage>) {
    let mut o = outage.lock().unwrap_or_else(|e| e.into_inner());
    if o.reported_at.is_none() {
        return;
    }
    if o.unreported > 0 {
        stderr_line(&format!("fasten: {label} persist failed: {} more, then a write succeeded", o.unreported));
    }
    *o = Outage::default();
}

// The message is left out: a driver error can quote the row's values.
fn failed(label: &str, error_type: &str, store: &dyn StreamStore, failures: &AtomicU64, outage: &Mutex<Outage>) {
    failures.fetch_add(1, Ordering::Relaxed);
    store.note_write_failure();
    let now = Instant::now();
    let mut o = outage.lock().unwrap_or_else(|e| e.into_inner());
    let Some(at) = o.reported_at else {
        o.reported_at = Some(now);
        drop(o);
        stderr_line(&format!("fasten: {label} persist failed: {error_type}"));
        return;
    };
    o.unreported += 1;
    if now.duration_since(at) >= REPORT_EVERY {
        let n = o.unreported;
        o.unreported = 0;
        o.reported_at = Some(now);
        drop(o);
        stderr_line(&format!("fasten: {label} persist failed: {error_type} ({n} since the last report)"));
    }
}

fn stderr_line(line: &str) {
    #[cfg(test)]
    STREAM_STDERR.lock().unwrap_or_else(|e| e.into_inner()).push(line.to_string());
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

#[cfg(test)]
pub(crate) static STREAM_STDERR: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The api and sys streams of one engine configuration.
pub(crate) struct Streams {
    pub(crate) api: Stream,
    pub(crate) sys: Stream,
    service_id: String,
    boot_request_id: String,
    boot_over: AtomicBool,
}

impl Streams {
    pub(crate) fn new(
        service_id: &str,
        api_store: Option<Arc<dyn StreamStore>>,
        syslog_store: Option<Arc<dyn StreamStore>>,
    ) -> Self {
        Self {
            api: Stream::new("api", api_store),
            sys: Stream::new("sys", syslog_store),
            service_id: service_id.to_string(),
            boot_request_id: mint_sentinel("boot", service_id).unwrap_or_default(),
            boot_over: AtomicBool::new(false),
        }
    }

    /// Give `row` a request id when it has none (spec §7): the boot id until
    /// the first row with a real id, an orphan id after.
    pub(crate) fn stamp(&self, row: &mut StreamRow) {
        if let Some(rid) = row.get("request_id").and_then(serde_json::Value::as_str).filter(|s| !s.is_empty()) {
            if !is_sentinel(rid) {
                self.boot_over.store(true, Ordering::Relaxed);
            }
            return;
        }
        let rid = if self.boot_over.load(Ordering::Relaxed) {
            mint_sentinel("orphan", &self.service_id).unwrap_or_default()
        } else {
            self.boot_request_id.clone()
        };
        row.insert("request_id".into(), serde_json::Value::String(rid));
    }

    pub(crate) fn flush(&self, deadline: Instant) -> bool {
        let api = self.api.flush(deadline);
        self.sys.flush(deadline) && api
    }

    pub(crate) fn close(&self, deadline: Instant) -> bool {
        let api = self.api.close(deadline);
        self.sys.close(deadline) && api
    }

    pub(crate) fn get(&self, name: &str) -> &Stream {
        if name == "api" { &self.api } else { &self.sys }
    }
}

/// Background thread that purges one stream store every hour (spec §10).
pub(crate) struct StreamPurger {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl StreamPurger {
    pub(crate) fn start(
        stream: &'static str,
        store: Arc<dyn StreamStore>,
        retention: Duration,
        cfg: crate::Config,
        interval: Duration,
    ) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = Arc::clone(&stop);
        let retention = chrono::Duration::from_std(retention).unwrap_or(chrono::Duration::MAX);
        let report = cfg.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("fasten-retention-{stream}"))
            .spawn(move || loop {
                let before = Utc::now().checked_sub_signed(retention).unwrap_or(DateTime::<Utc>::MIN_UTC);
                if let Err(e) = store.purge(before) {
                    // Type only: a store error message can quote row values.
                    crate::engine::sys_line(Some(&cfg), "error", "retention_purge_failed", serde_json::json!({
                        "stream": format!("{stream}/age-purge"),
                        "error_type": crate::retention::error_type(&e),
                    }));
                }
                let (lock, cv) = &*flag;
                let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                let (guard, _) = cv.wait_timeout_while(guard, interval, |s| !*s).unwrap_or_else(|e| e.into_inner());
                if *guard {
                    return;
                }
            });
        let handle = match spawned {
            Ok(h) => Some(h),
            Err(e) => {
                crate::engine::sys_line(Some(&report), "error", "retention_purge_failed", serde_json::json!({
                    "stream": format!("{stream}/age-purge"),
                    "error_type": format!("{:?}", e.kind()),
                }));
                None
            }
        };
        Self { stop, handle }
    }

    pub(crate) fn stop(mut self) {
        self.signal();
        if let Some(h) = self.handle.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !h.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }

    fn signal(&self) {
        let (lock, cv) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
    }
}

impl Drop for StreamPurger {
    fn drop(&mut self) {
        self.signal();
    }
}

/// A stream store for `dsn`, in the forms of [`crate::parse_dsn`]: a
/// [`crate::PostgresStreamStore`] or a [`crate::SqliteStreamStore`], on
/// `default_table` (`api_log` or `syslog`) unless the DSN names one. Every
/// error is [`Error::InvalidConfig`] and names the scheme at most: a DSN
/// that does not parse, a scheme whose store feature is not built in, or a
/// store that cannot be opened.
pub fn stream_store_from_dsn(dsn: &str, default_table: &str) -> Result<Arc<dyn StreamStore>, Error> {
    open_stream_store("stream DSN", dsn, default_table)
}

/// [`stream_store_from_dsn`], with errors starting with `label`, such as
/// the variable the DSN came from.
pub(crate) fn open_stream_store(label: &str, dsn: &str, default_table: &str) -> Result<Arc<dyn StreamStore>, Error> {
    let parsed = crate::parse_dsn(dsn, default_table).map_err(|e| Error::InvalidConfig(format!("{label}: {e}")))?;
    crate::dsn::check_openable(label, &parsed)?;
    #[cfg(any(feature = "store-postgres", feature = "store-sqlite"))]
    let failed = |e: Error| crate::dsn::open_failed(label, &parsed, &e);
    match &parsed {
        #[cfg(feature = "store-postgres")]
        crate::Dsn::Postgres { url, table } => Ok(Arc::new(crate::PostgresStreamStore::new(url, table).map_err(failed)?)),
        #[cfg(feature = "store-sqlite")]
        crate::Dsn::Sqlite { path, table, wal } => {
            Ok(Arc::new(crate::SqliteStreamStore::open_with(path, table, *wal).map_err(failed)?))
        }
        #[allow(unreachable_patterns)]
        other => Err(crate::dsn::feature_missing(label, other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinels() {
        let id = mint_sentinel("orphan", "").unwrap();
        assert!(id.starts_with("orphan-svc-") && id.len() == "orphan-svc-".len() + 12, "{id}");
        assert!(is_sentinel(&id));
        assert!(!is_sentinel("bootstrap"));
        assert!(mint_sentinel("nope", "s").is_err());
    }

    // A push that races a re-init lands on the retired stream: it counts
    // there, and the store, which the next streams may use, is not marked.
    #[cfg(feature = "store-sqlite")]
    #[test]
    fn a_push_after_close_does_not_mark_the_store() {
        let store: Arc<dyn StreamStore> = Arc::new(crate::SqliteStreamStore::open(":memory:", "syslog").unwrap());
        let stream = Stream::new("sys", Some(store.clone()));
        assert!(stream.close(Instant::now() + Duration::from_secs(5)));
        stream.push(StreamRow::new());
        assert!(!store.degraded());
        assert_eq!(stream.source(), "store-degraded");
        assert_eq!(Stream::new("sys", Some(store)).source(), "store");
    }

    #[test]
    fn unsupported_scheme_is_refused_without_quoting_the_dsn() {
        let err = stream_store_from_dsn("mysql://user:secret@h/db", "syslog").err().unwrap().to_string();
        assert!(err.contains("'mysql'") && !err.contains("secret"), "{err}");
        let err = stream_store_from_dsn("sqlite://", "syslog").err().unwrap().to_string();
        assert!(err.contains("no path"), "{err}");
    }
}
