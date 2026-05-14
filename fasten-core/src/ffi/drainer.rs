//! C ABI for the shared drainer (`fasten_drainer_*` symbols).
//!
//! The drainer attaches to an existing `FastenStoreHandle` and manages a
//! background OS thread with the full conformance-spec state machine.

use std::os::raw::{c_char, c_int};
use std::time::Duration;

use std::sync::Arc;

use crate::{
    drainer::{Drainer, DrainerConfig},
    error::{Error, FastenErrorCode},
    row::Row,
    store::{Filter, Store},
};
use super::{FastenStoreHandle, guarded, result_to_rc};
use super::util::set_error;

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
        // We need to reconstruct the store reference for the drainer.
        // The handle owns a Box<dyn Store>; to share it with the drainer
        // we wrap it in an Arc via an indirection.
        let h = &mut *handle;
        // Stop existing drainer if any.
        if let Some(old) = h.drainer.take() {
            old.stop(Duration::from_secs(2));
        }
        // Clone the Arc so both the handle and the drainer share the store.
        let store = Arc::clone(&h.store);
        // Drainer::new takes Box<dyn Store>; wrap the Arc in a newtype shim.
        let store_box = Box::new(ArcStoreShim(store));
        h.drainer = Some(Drainer::new(store_box, cfg));
        Ok(())
    });
    result_to_rc(r, out_err)
}

/// Enqueue a row JSON for asynchronous insertion.
///
/// Blocks if the queue is full (back-pressure). Returns
/// `FASTEN_ERR_DRAINER_STOPPED` if no drainer is installed or if it
/// has been shut down.
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
        let h = &*handle;
        match &h.drainer {
            None => Err(crate::error::Error::DrainerNotInstalled),
            Some(d) => {
                d.enqueue(row);
                Ok(())
            }
        }
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
        let drained = match &h.drainer {
            None => true, // no drainer = raise mode = trivially drained
            Some(d) => {
                let timeout = if timeout_ms == 0 {
                    Duration::from_secs(30 * 24 * 3600) // 30-day practical ceiling
                } else {
                    Duration::from_millis(timeout_ms)
                };
                d.flush(timeout)
            }
        };
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
        let h = &*handle;
        let json = match &h.drainer {
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

/// Shut down the drainer: stop the background thread (best-effort drain,
/// 2-second timeout). Safe to call with NULL or when no drainer is installed.
#[no_mangle]
pub unsafe extern "C" fn fasten_drainer_close(handle: *mut FastenStoreHandle) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    if let Some(d) = h.drainer.take() {
        d.stop(Duration::from_secs(2));
    }
}
