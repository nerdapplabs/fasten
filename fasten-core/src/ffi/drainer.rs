//! C ABI for the shared drainer (`fasten_drainer_*` symbols).
//!
//! The drainer attaches to an existing `FastenStoreHandle` and manages a
//! background OS thread with the full conformance-spec state machine.

use std::ffi::{c_void, CString};
use std::os::raw::{c_char, c_int};
use std::time::Duration;

use std::sync::Arc;

use crate::{
    drainer::{Drainer, DrainerConfig, SysLog},
    error::{Error, FastenErrorCode},
    row::Row,
    store::{Filter, Store},
};
use super::{FastenStoreHandle, guarded, result_to_rc};
use super::util::set_error;

fn slot(h: &FastenStoreHandle) -> std::sync::MutexGuard<'_, Option<Arc<Drainer>>> {
    h.drainer.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The installed drainer, kept alive for the caller even if it is closed.
fn current(h: &FastenStoreHandle) -> Option<Arc<Drainer>> {
    slot(h).clone()
}

fn retiring(h: &FastenStoreHandle) -> std::sync::MutexGuard<'_, Vec<Arc<Drainer>>> {
    h.retiring.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install `new` (or nothing) and return the old drainer, already on the
/// retiring list: both change under the slot lock, so flush finds the old
/// drainer in one list or the other. Pass the result to `retire`.
pub(super) fn swap(h: &FastenStoreHandle, new: Option<Arc<Drainer>>) -> Option<Arc<Drainer>> {
    let mut g = slot(h);
    let old = std::mem::replace(&mut *g, new);
    if let Some(o) = &old {
        retiring(h).push(Arc::clone(o));
    }
    old
}

/// Wait until every drainer taken off the handle has stopped, including
/// one another thread's install is still retiring.
pub(super) fn wait_retired(h: &FastenStoreHandle) {
    let mut r = retiring(h);
    while !r.is_empty() {
        r = h.retired.wait(r).unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

/// Flush (if `flush_for` is set) and stop a drainer `swap` took off the
/// handle. Until it returns, `fasten_drainer_flush` also waits for it.
/// Install reports rows the old drainer could not write.
pub(super) fn retire(h: &FastenStoreHandle, old: &Arc<Drainer>, flush_for: Option<Duration>) {
    let dead_before = old.stats().dead_lettered_total;
    let flushed = flush_for.is_none_or(|t| old.flush(t));
    old.stop(Duration::from_secs(2));
    // Enqueues still running may emit through the sys sink; the host may
    // release it once this returns.
    old.wait_calls();
    let dead = old.stats().dead_lettered_total - dead_before;
    if flush_for.is_some() && (!flushed || dead > 0) {
        old.sys_event("warn", "audit_drain_install_incomplete", &serde_json::json!({
            "flushed": flushed,
            "dead_lettered": dead,
        }));
    }
    // Notify under the lock: once it is released, close may free the handle.
    let mut r = retiring(h);
    r.retain(|d| !Arc::ptr_eq(d, old));
    h.retired.notify_all();
}

// Thin newtype so we can pass an Arc<dyn Store> as a Box<dyn Store>.
struct ArcStoreShim(Arc<dyn Store>);

impl Store for ArcStoreShim {
    fn insert(&self, row: &Row) -> Result<(), Error> { self.0.insert(row) }
    fn ping(&self) -> Result<(), Error> { self.0.ping() }
    fn query(&self, f: &Filter) -> Result<Vec<Row>, Error> { self.0.query(f) }
    fn count(&self, f: &Filter) -> Result<u64, Error> { self.0.count(f) }
    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error> { self.0.list_unshipped(limit) }
    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> { self.0.mark_shipped(ids) }
    fn purge(&self, before: &str, respect: bool) -> Result<u64, Error> { self.0.purge(before, respect) }
    fn max_monotonic_seq(&self) -> Result<u64, Error> { self.0.max_monotonic_seq() }
}

/// Add (or replace) a drainer on an existing store handle.
///
/// Must be called before any `fasten_drainer_enqueue` call. The drainer
/// uses the store already associated with `handle` to write rows.
///
/// `capacity`         — maximum queued + in-flight slots (default 100 when 0).
/// `retry_initial_ms` — first backoff window in ms (default 100 when 0).
/// `retry_max_ms`     — backoff ceiling in ms (default 60 000 when 0).
/// `retry_jitter`     — non-zero = apply ±20% uniform jitter.
/// `max_attempts`     — dead-letter threshold (default 50 when 0).
/// `out_err`          — set on error; may be NULL.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_install(
    handle: *mut FastenStoreHandle,
    capacity: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
    retry_jitter: c_int,
    max_attempts: u32,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    install(handle, capacity, retry_initial_ms, retry_max_ms, retry_jitter, max_attempts, None, out_err)
}

/// Receives each drainer sys event as a NUL-terminated JSON line.
pub type FastenSysLogFn = extern "C" fn(event_json: *const c_char, userdata: *mut c_void);

struct HostSysLog {
    f: FastenSysLogFn,
    userdata: *mut c_void,
}

// SAFETY: the host guarantees `f` and `userdata` may be used from any thread
// until fasten_drainer_close (or a replacing install) returns, and retire
// waits for every call that could still emit before those return.
unsafe impl Send for HostSysLog {}
unsafe impl Sync for HostSysLog {}

/// `fasten_drainer_install`, with sys events sent to `sys_log` instead of
/// stderr. `sys_log` may be NULL (stderr).
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_install_with_sys_log(
    handle: *mut FastenStoreHandle,
    capacity: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
    retry_jitter: c_int,
    max_attempts: u32,
    sys_log: Option<FastenSysLogFn>,
    userdata: *mut c_void,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let sink = sys_log.map(|f| {
        let host = HostSysLog { f, userdata };
        Arc::new(move |line: &str| {
            let host = &host; // capture the Send wrapper, not its raw pointer
            if let Ok(c) = CString::new(line) {
                (host.f)(c.as_ptr(), host.userdata);
            }
        }) as SysLog
    });
    install(handle, capacity, retry_initial_ms, retry_max_ms, retry_jitter, max_attempts, sink, out_err)
}

#[allow(clippy::too_many_arguments)]
unsafe fn install(
    handle: *mut FastenStoreHandle,
    capacity: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
    retry_jitter: c_int,
    max_attempts: u32,
    sys_log: Option<SysLog>,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(crate::error::Error::NullArg);
        }
        let cfg = DrainerConfig {
            capacity: if capacity == 0 { 100 } else { capacity as usize },
            retry_initial: Duration::from_millis(if retry_initial_ms == 0 { 100 } else { retry_initial_ms }),
            retry_max: Duration::from_millis(if retry_max_ms == 0 { 60_000 } else { retry_max_ms }),
            retry_jitter: retry_jitter != 0,
            max_attempts: if max_attempts == 0 { 50 } else { max_attempts as usize },
        };
        let h = &*handle;
        // Spec §10: build the new drainer, swap it in, then flush and stop
        // the old one outside the lock.
        let store_box = Box::new(ArcStoreShim(Arc::clone(&h.store)));
        let new = Drainer::with_sys_log(store_box, cfg, sys_log);
        if let Some(old) = swap(h, Some(new)) {
            retire(h, &old, Some(Duration::from_secs(5)));
        }
        Ok(())
    });
    result_to_rc(r, out_err)
}

/// Enqueue a row JSON for asynchronous insertion.
///
/// Blocks if the queue is full (back-pressure). Returns
/// `FASTEN_ERR_NULL_ARG` if no drainer is installed and
/// `FASTEN_ERR_DRAINER_STOPPED` if it is stopping and the row was not queued;
/// the caller should then store the row itself.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_enqueue(
    handle: *mut FastenStoreHandle,
    row_json: *const c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(crate::error::Error::NullArg);
        }
        let json = super::util::read_str(row_json).ok_or(crate::error::Error::NullArg)?;
        let row: crate::row::Row = serde_json::from_str(json)?;
        // Start the call under the drainer lock, so close can wait for it.
        let (d, _call) = {
            let g = slot(&*handle);
            let d = g.clone().ok_or(crate::error::Error::DrainerNotInstalled)?;
            let call = d.begin_call();
            (d, call)
        };
        if d.enqueue(row) { Ok(()) } else { Err(crate::error::Error::DrainerStopped) }
    });
    result_to_rc(r, out_err)
}

/// Block until all currently-queued rows have drained, or `timeout_ms` elapses.
///
/// `timeout_ms`       — 0 = no-timeout (practical ceiling: 30 days).
/// `out_fully_drained`— set to 1 if fully drained, 0 if timed out. May be NULL.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_flush(
    handle: *mut FastenStoreHandle,
    timeout_ms: u64,
    out_fully_drained: *mut c_int,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(crate::error::Error::NullArg);
        }
        let h = &*handle;
        let timeout = if timeout_ms == 0 {
            Duration::from_secs(30 * 24 * 3600) // 30-day practical ceiling
        } else {
            Duration::from_millis(timeout_ms)
        };
        let deadline = std::time::Instant::now() + timeout;
        // The installed drainer plus any being retired by install/close,
        // read under the slot lock so a swap can't hide one.
        let drainers: Vec<Arc<Drainer>> = {
            let g = slot(h);
            let mut v = retiring(h).clone();
            v.extend(g.clone());
            v
        };
        let drained = drainers.iter().all(|d| {
            d.flush(deadline.saturating_duration_since(std::time::Instant::now()))
        });
        Ok(drained)
    });
    match r {
        Ok(drained) => {
            if !out_fully_drained.is_null() {
                *out_fully_drained = if drained { 1 } else { 0 };
            }
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Return queue stats as a JSON string.
///
/// Returns an empty JSON object `{}` when no drainer is installed.
/// Free the result with `fasten_store_free_str`.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_stats_json(
    handle: *mut FastenStoreHandle,
    out_json: *mut *mut c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(crate::error::Error::NullArg);
        }
        let json = match current(&*handle) {
            None => "null".to_owned(),
            Some(d) => d.stats_json(),
        };
        Ok(json)
    });
    match r {
        Ok(json) => {
            set_error(out_json, &json);
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Shut down the drainer. Each queued row gets one more attempt; then close
/// waits for the drain thread, including a host callback in progress, and
/// for a drainer an install on another thread is still retiring.
/// Safe to call with NULL or when no drainer is installed.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_close(handle: *mut FastenStoreHandle) {
    if handle.is_null() {
        return;
    }
    let h = &*handle;
    if let Some(d) = swap(h, None) {
        retire(h, &d, None);
    }
    wait_retired(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{fasten_store_close, fasten_store_from_callback};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;

    extern "C" fn slow_ok(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        thread::sleep(Duration::from_millis(2));
        0
    }

    const ROW: &[u8] = b"{\"id\":\"r\",\"wire_version\":\"1\",\"origin_id\":\"r\",\
        \"monotonic_seq\":1,\"timestamp\":\"2026-01-01T00:00:00Z\",\"code\":\"T\",\
        \"action\":\"a\",\"severity\":\"info\",\"service_id\":\"s\",\"source_node_id\":\"n\",\
        \"actor\":\"u\",\"actor_kind\":\"user\",\"target\":\"t\",\"category\":\"c\",\
        \"domain\":\"d\",\"method\":\"sdk\",\"request_id\":\"q\",\"detail\":{}}\0";

    /// Other threads keep enqueuing while the drainer is closed; once it is
    /// closed, every one of them is refused.
    #[test]
    fn close_while_other_threads_enqueue() {
        for _ in 0..20 {
            let h = unsafe { fasten_store_from_callback(slow_ok, std::ptr::null_mut(), std::ptr::null_mut()) };
            let rc = unsafe { fasten_drainer_install(h, 2, 5, 5, 0, 3, std::ptr::null_mut()) };
            assert_eq!(rc, FastenErrorCode::Ok);
            let addr = h as usize;
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    thread::spawn(move || loop {
                        let rc = unsafe {
                            fasten_drainer_enqueue(addr as *mut FastenStoreHandle,
                                                   ROW.as_ptr().cast::<c_char>(),
                                                   std::ptr::null_mut())
                        };
                        if rc != FastenErrorCode::Ok {
                            return rc;
                        }
                    })
                })
                .collect();
            thread::sleep(Duration::from_millis(10));
            unsafe { fasten_drainer_close(h) };
            for w in workers {
                let rc = w.join().ok();
                assert!(matches!(rc, Some(FastenErrorCode::ErrDrainerStopped | FastenErrorCode::ErrNullArg)),
                        "unexpected rc {rc:?}");
            }
            unsafe { fasten_store_close(h) };
        }
    }

    static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn counted_slow(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        thread::sleep(Duration::from_millis(20));
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// A flush that runs while close is draining returns only once every
    /// queued row has been handled.
    #[test]
    fn flush_during_close_waits_for_queued_rows() {
        let h = unsafe { fasten_store_from_callback(counted_slow, std::ptr::null_mut(), std::ptr::null_mut()) };
        unsafe { fasten_drainer_install(h, 32, 5, 5, 0, 3, std::ptr::null_mut()) };
        for _ in 0..10 {
            unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        }
        let addr = h as usize;
        let closer = thread::spawn(move || unsafe { fasten_drainer_close(addr as *mut FastenStoreHandle) });
        thread::sleep(Duration::from_millis(5));
        let mut drained: c_int = 0;
        unsafe { fasten_drainer_flush(h, 5_000, std::ptr::addr_of_mut!(drained), std::ptr::null_mut()) };
        assert_eq!(drained, 1);
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 10);
        assert!(closer.join().is_ok());
        unsafe { fasten_store_close(h) };
    }

    static INSTALL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static INSTALL_STORED: AtomicBool = AtomicBool::new(false);

    extern "C" fn fails_twice(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        if INSTALL_CALLS.fetch_add(1, Ordering::SeqCst) < 2 {
            return 1;
        }
        INSTALL_STORED.store(true, Ordering::SeqCst);
        0
    }

    /// Re-install flushes the old drainer, so a row it is retrying is still
    /// stored rather than dead-lettered by the stop.
    #[test]
    fn install_flushes_the_old_drainer_before_stopping_it() {
        let h = unsafe { fasten_store_from_callback(fails_twice, std::ptr::null_mut(), std::ptr::null_mut()) };
        unsafe { fasten_drainer_install(h, 8, 20, 20, 0, 10, std::ptr::null_mut()) };
        unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        let start = std::time::Instant::now();
        while INSTALL_CALLS.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(5) {
            thread::yield_now();
        }
        let rc = unsafe { fasten_drainer_install(h, 8, 20, 20, 0, 10, std::ptr::null_mut()) };
        assert_eq!(rc, FastenErrorCode::Ok);
        assert!(INSTALL_STORED.load(Ordering::SeqCst), "row was not stored before the old drainer stopped");
        unsafe { fasten_store_close(h) };
    }

    static HANDLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn calls_back(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        thread::sleep(Duration::from_millis(20));
        let h = HANDLE.load(Ordering::SeqCst) as *mut FastenStoreHandle;
        let mut js: *mut c_char = std::ptr::null_mut();
        unsafe {
            fasten_drainer_stats_json(h, std::ptr::addr_of_mut!(js), std::ptr::null_mut());
            if !js.is_null() {
                crate::ffi::fasten_store_free_str(js);
            }
        }
        0
    }

    /// Two installs at once while the store callback calls back into the
    /// handle: neither install may wait on the other.
    #[test]
    fn concurrent_installs_with_a_callback_into_the_handle() {
        let h = unsafe { fasten_store_from_callback(calls_back, std::ptr::null_mut(), std::ptr::null_mut()) };
        HANDLE.store(h as usize, Ordering::SeqCst);
        unsafe { fasten_drainer_install(h, 8, 5, 5, 0, 3, std::ptr::null_mut()) };
        for _ in 0..5 {
            unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        }
        let addr = h as usize;
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let tx = tx.clone();
            thread::spawn(move || {
                let h = addr as *mut FastenStoreHandle;
                let rc = unsafe { fasten_drainer_install(h, 16, 5, 5, 0, 3, std::ptr::null_mut()) };
                for _ in 0..10 {
                    unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
                }
                tx.send(rc).ok();
            });
        }
        for _ in 0..2 {
            let rc = rx.recv_timeout(Duration::from_secs(10));
            assert!(matches!(rc, Ok(FastenErrorCode::Ok)), "install did not return Ok: {rc:?}");
        }
        unsafe { fasten_store_close(h) };
    }

    static SYS_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    extern "C" fn record_sys(json: *const c_char, _ud: *mut std::ffi::c_void) {
        let line = unsafe { std::ffi::CStr::from_ptr(json) }.to_string_lossy().into_owned();
        SYS_LINES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
    }

    extern "C" fn always_fails(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 { 1 }

    /// Sys events go to the host's callback, in order, and not to stderr.
    #[test]
    fn sys_events_reach_the_host_callback() {
        let h = unsafe { fasten_store_from_callback(always_fails, std::ptr::null_mut(), std::ptr::null_mut()) };
        let rc = unsafe {
            fasten_drainer_install_with_sys_log(h, 8, 1, 1, 0, 2, Some(record_sys),
                                                std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(rc, FastenErrorCode::Ok);
        unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        let mut drained: c_int = 0;
        unsafe { fasten_drainer_flush(h, 5_000, std::ptr::addr_of_mut!(drained), std::ptr::null_mut()) };
        unsafe { fasten_drainer_close(h) };
        let rc = unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        assert_eq!(rc, FastenErrorCode::ErrNullArg);
        unsafe { fasten_store_close(h) };
        let events: Vec<String> = SYS_LINES.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .map(|v| v["event"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(events, ["audit_drain_failed", "audit_drain_dead_letter"]);
    }

    static SINK_AFTER_CLOSE: AtomicBool = AtomicBool::new(false);
    static CLOSED: AtomicBool = AtomicBool::new(false);

    extern "C" fn slow_sink(json: *const c_char, _ud: *mut std::ffi::c_void) {
        let line = unsafe { std::ffi::CStr::from_ptr(json) }.to_string_lossy();
        if line.contains("audit_drain_abandoned") {
            thread::sleep(Duration::from_millis(300));
        }
        if CLOSED.load(Ordering::SeqCst) {
            SINK_AFTER_CLOSE.store(true, Ordering::SeqCst);
        }
    }

    /// An enqueue still running when close starts emits its abandoned event
    /// before close returns, so the host may then release its sink.
    #[test]
    fn close_waits_for_an_enqueue_still_emitting() {
        // The one slot is held by a row in a long backoff, so the second
        // enqueue waits; close wakes it and it emits abandoned (slowly).
        let h = unsafe { fasten_store_from_callback(always_fails, std::ptr::null_mut(), std::ptr::null_mut()) };
        unsafe {
            fasten_drainer_install_with_sys_log(h, 1, 10_000, 10_000, 0, 3, Some(slow_sink),
                                                std::ptr::null_mut(), std::ptr::null_mut());
            fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut());
        }
        let addr = h as usize;
        let blocked = thread::spawn(move || unsafe {
            fasten_drainer_enqueue(addr as *mut FastenStoreHandle, ROW.as_ptr().cast::<c_char>(),
                                   std::ptr::null_mut())
        });
        let start = std::time::Instant::now();
        while current(unsafe { &*h }).is_some_and(|d| d.calls_in_flight() == 0)
            && start.elapsed() < Duration::from_secs(5)
        {
            thread::yield_now();
        }
        unsafe { fasten_drainer_close(h) };
        CLOSED.store(true, Ordering::SeqCst);
        assert!(matches!(blocked.join(), Ok(FastenErrorCode::ErrDrainerStopped)));
        unsafe { fasten_store_close(h) };
        assert!(!SINK_AFTER_CLOSE.load(Ordering::SeqCst), "sys_log called after close returned");
    }

    static REJECT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REJECT_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    extern "C" fn rejects_first(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        if REJECT_CALLS.fetch_add(1, Ordering::SeqCst) == 0 { -1 } else { 0 }
    }

    extern "C" fn record_reject(json: *const c_char, _ud: *mut std::ffi::c_void) {
        let line = unsafe { std::ffi::CStr::from_ptr(json) }.to_string_lossy().into_owned();
        REJECT_LINES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(line);
    }

    /// A row the store rejects is dead-lettered on its first attempt, so the
    /// row behind it is not held up by a 10 s backoff.
    #[test]
    fn rejected_row_is_dead_lettered_without_retry() {
        let h = unsafe { fasten_store_from_callback(rejects_first, std::ptr::null_mut(), std::ptr::null_mut()) };
        unsafe {
            fasten_drainer_install_with_sys_log(h, 8, 10_000, 10_000, 0, 10, Some(record_reject),
                                                std::ptr::null_mut(), std::ptr::null_mut());
            fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut());
            fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut());
        }
        let mut drained: c_int = 0;
        unsafe { fasten_drainer_flush(h, 2_000, std::ptr::addr_of_mut!(drained), std::ptr::null_mut()) };
        assert_eq!(drained, 1);
        assert_eq!(REJECT_CALLS.load(Ordering::SeqCst), 2);
        unsafe { fasten_store_close(h) };
        let events: Vec<serde_json::Value> = REJECT_LINES.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["event"], "audit_drain_dead_letter");
        assert_eq!(events[0]["attempt_count"], 1);
    }

    static RETIRE_CALLS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn counted_100ms(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        thread::sleep(Duration::from_millis(100));
        RETIRE_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// close on one thread while an install on another is still flushing
    /// the old drainer: close returns only after that drainer has stopped.
    #[test]
    fn close_waits_for_a_drainer_another_install_is_retiring() {
        let h = unsafe { fasten_store_from_callback(counted_100ms, std::ptr::null_mut(), std::ptr::null_mut()) };
        unsafe { fasten_drainer_install(h, 8, 5, 5, 0, 3, std::ptr::null_mut()) };
        for _ in 0..3 {
            unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        }
        let addr = h as usize;
        let installer = thread::spawn(move || unsafe {
            fasten_drainer_install(addr as *mut FastenStoreHandle, 8, 5, 5, 0, 3, std::ptr::null_mut())
        });
        let start = std::time::Instant::now();
        while unsafe { &*h }.retiring.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty()
            && start.elapsed() < Duration::from_secs(5)
        {
            thread::yield_now();
        }
        unsafe { fasten_drainer_close(h) };
        assert_eq!(RETIRE_CALLS.load(Ordering::SeqCst), 3, "close returned before the old drainer stopped");
        assert!(matches!(installer.join(), Ok(FastenErrorCode::Ok)));
        unsafe { fasten_store_close(h) };
    }

    /// `fasten_store_close` while an install on another thread is retiring
    /// the old drainer: the handle is freed only after that install is done
    /// with it. The race window is small, so this rarely fails without the fix.
    #[test]
    fn store_close_while_another_install_is_retiring() {
        for _ in 0..50 {
            let h = unsafe { fasten_store_from_callback(slow_ok, std::ptr::null_mut(), std::ptr::null_mut()) };
            unsafe { fasten_drainer_install(h, 8, 5, 5, 0, 3, std::ptr::null_mut()) };
            unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
            let addr = h as usize;
            let installer = thread::spawn(move || unsafe {
                fasten_drainer_install(addr as *mut FastenStoreHandle, 8, 5, 5, 0, 3, std::ptr::null_mut())
            });
            let start = std::time::Instant::now();
            while unsafe { &*h }.retiring.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty()
                && start.elapsed() < Duration::from_secs(5)
            {
                thread::yield_now();
            }
            unsafe { fasten_store_close(h) };
            assert!(matches!(installer.join(), Ok(FastenErrorCode::Ok)));
        }
    }

    static SWAP_STORED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn counted_2ms(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 {
        thread::sleep(Duration::from_millis(2));
        SWAP_STORED.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// A flush that overlaps an install never reports the old drainer's
    /// queued rows as drained before they are stored.
    #[test]
    fn flush_during_install_sees_the_old_drainer() {
        for _ in 0..50 {
            SWAP_STORED.store(0, Ordering::SeqCst);
            let h = unsafe { fasten_store_from_callback(counted_2ms, std::ptr::null_mut(), std::ptr::null_mut()) };
            unsafe { fasten_drainer_install(h, 8, 5, 5, 0, 3, std::ptr::null_mut()) };
            for _ in 0..4 {
                unsafe { fasten_drainer_enqueue(h, ROW.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
            }
            let addr = h as usize;
            let installer = thread::spawn(move || unsafe {
                fasten_drainer_install(addr as *mut FastenStoreHandle, 8, 5, 5, 0, 3, std::ptr::null_mut())
            });
            loop {
                let mut drained: c_int = 0;
                unsafe { fasten_drainer_flush(h, 1, std::ptr::addr_of_mut!(drained), std::ptr::null_mut()) };
                let stored = SWAP_STORED.load(Ordering::SeqCst);
                if drained == 1 {
                    assert_eq!(stored, 4, "flush reported drained with {stored} of 4 rows stored");
                    break;
                }
            }
            assert!(installer.join().is_ok());
            unsafe { fasten_store_close(h) };
        }
    }

    /// The queue is not allocated up front, so a large capacity is fine.
    #[test]
    fn large_capacity_is_not_allocated_up_front() {
        let h = unsafe { fasten_store_from_callback(slow_ok, std::ptr::null_mut(), std::ptr::null_mut()) };
        let rc = unsafe { fasten_drainer_install(h, 1 << 40, 5, 5, 0, 3, std::ptr::null_mut()) };
        assert_eq!(rc, FastenErrorCode::Ok);
        unsafe { fasten_store_close(h) };
    }
}
