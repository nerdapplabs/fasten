//! C ABI exports.
//!
//! Every `extern "C"` function in this module:
//!   1. validates all pointer arguments before dereferencing them,
//!   2. wraps the body in `std::panic::catch_unwind` so a Rust panic can never
//!      unwind across the FFI boundary (which is undefined behaviour), and
//!   3. maps errors to a typed `FastenErrorCode` + a caller-owned `*mut c_char`
//!      error string freed via `fasten_store_free_str`.
//!
//! No Rust panics, no use-after-free, no double-free when the C caller follows
//! the documented ownership rules in `include/fasten_core.h`.

mod util;
pub(crate) mod catalog;
pub(crate) mod drainer;
pub(crate) mod redact;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic;
use std::sync::Arc;

use crate::{
    drainer::Drainer,
    error::{Error, FastenErrorCode},
    row::Row,
    store::{Filter, Store},
};
use util::{read_str, set_error};

// ── Shared helper ─────────────────────────────────────────────────────────────
// Re-exported so the redact and catalog submodules can use it without
// duplicating the catch_unwind boilerplate.

/// Run `f`; catch any Rust panic; return `Ok(R)` or `Err((code, message))`.
pub(crate) fn guarded<F, R>(f: F) -> Result<R, (FastenErrorCode, String)>
where
    F: FnOnce() -> Result<R, Error>,
{
    match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => {
            let code = FastenErrorCode::from(&e);
            Err((code, e.to_string()))
        }
        Err(_) => Err((
            FastenErrorCode::ErrUnknown,
            "fasten-core: internal panic".into(),
        )),
    }
}

// ── Opaque handle ─────────────────────────────────────────────────────────────

/// Heap-allocated, type-erased store + optional drainer. C sees only `FastenStore*`.
pub struct FastenStoreHandle {
    store: Arc<dyn Store>,
    drainer: Option<Arc<Drainer>>,
}

/// Write the error string and return the error code.
///
/// # Safety
/// `out_err` must be null or point to a writable `*mut c_char` slot.
unsafe fn result_to_rc(
    result: Result<(), (FastenErrorCode, String)>,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    match result {
        Ok(()) => FastenErrorCode::Ok,
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

// ── Exported symbols ──────────────────────────────────────────────────────────

/// Open a store and return an opaque handle.
///
/// `backend`  — `"sqlite"` or `"postgres"`.
/// `connstr`  — filesystem path (sqlite) or connection DSN (postgres).
/// `table`    — table name, optionally schema-qualified (`"schema.table"`).
/// `out_err`  — set to a heap-allocated error string on failure (free with
///              `fasten_store_free_str`); may be NULL if the caller ignores
///              error detail.
///
/// Returns a non-null handle on success, NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_open(
    backend: *const c_char,
    connstr: *const c_char,
    table: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut FastenStoreHandle {
    let result = guarded(|| {
        let backend = read_str(backend).ok_or(Error::NullArg)?;
        let connstr = read_str(connstr).ok_or(Error::NullArg)?;
        let table = read_str(table).ok_or(Error::NullArg)?;

        let store: Arc<dyn Store> = match backend {
            #[cfg(feature = "sqlite")]
            "sqlite" => Arc::new(crate::store::sqlite::SqliteStore::open(
                connstr, table, true,
            )?),

            #[cfg(feature = "postgres")]
            "postgres" => Arc::new(crate::store::postgres::PostgresStore::connect(
                connstr, table,
            )?),

            other => return Err(Error::UnknownBackend(other.to_owned())),
        };

        Ok(Box::into_raw(Box::new(FastenStoreHandle { store, drainer: None })))
    });

    match result {
        Ok(ptr) => ptr,
        Err((_code, msg)) => {
            set_error(out_err, &msg);
            std::ptr::null_mut()
        }
    }
}

/// Insert a JSON-encoded audit row.
///
/// `monotonic_seq` 0 means the store allocates the next seq for the node.
///
/// `handle`   — handle returned by `fasten_store_open`; must be non-null.
/// `row_json` — UTF-8 JSON object matching the fasten wire schema.
/// `out_err`  — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_insert(
    handle: *mut FastenStoreHandle,
    row_json: *const c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let json_str = read_str(row_json).ok_or(Error::NullArg)?;
        let row: Row = serde_json::from_str(json_str)?;
        // SAFETY: handle is non-null and was allocated by fasten_store_open;
        // no other thread drops it while we hold this shared reference.
        (*handle).store.insert(&row)?;
        Ok(())
    });
    result_to_rc(r, out_err)
}

/// Verify the backend is reachable (lightweight `SELECT 1`).
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_ping(
    handle: *mut FastenStoreHandle,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        (*handle).store.ping()?;
        Ok(())
    });
    result_to_rc(r, out_err)
}

/// Query rows matching an optional JSON filter object.
///
/// `filter_json` — nullable; when NULL all rows are returned.
///                 JSON object with optional fields: `request_id`, `code`,
///                 `domain`, `source_node_id`, `since`, `until`, `limit`,
///                 `offset`.
/// `out_rows_json` — on success, set to a heap-allocated UTF-8 JSON array of
///                   row objects.  Free with `fasten_store_free_str`.
///                   May be NULL if the caller doesn't need the rows.
/// `out_err`     — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_query(
    handle: *mut FastenStoreHandle,
    filter_json: *const c_char,
    out_rows_json: *mut *mut c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let filter: Filter = match read_str(filter_json) {
            Some(json) => serde_json::from_str(json)?,
            None => Filter::default(),
        };
        (*handle).store.query(&filter)
    });
    match r {
        Ok(rows) => {
            let json = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
            set_error(out_rows_json, &json);
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Count rows matching an optional JSON filter object.
///
/// `filter_json` — nullable; when NULL counts all rows.
/// `out_count`   — set to the row count on success; must be non-null.
/// `out_err`     — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_count(
    handle: *mut FastenStoreHandle,
    filter_json: *const c_char,
    out_count: *mut u64,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let filter: Filter = match read_str(filter_json) {
            Some(json) => serde_json::from_str(json)?,
            None => Filter::default(),
        };
        (*handle).store.count(&filter)
    });
    match r {
        Ok(n) => {
            if !out_count.is_null() {
                *out_count = n;
            }
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// List unshipped rows (those with `shipped_at IS NULL`).
///
/// `limit`         — maximum rows to return; 0 = all unshipped rows.
/// `out_rows_json` — on success, set to a heap-allocated UTF-8 JSON array.
///                   Free with `fasten_store_free_str`.
/// `out_err`       — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_list_unshipped(
    handle: *mut FastenStoreHandle,
    limit: u32,
    out_rows_json: *mut *mut c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        (*handle).store.list_unshipped(limit)
    });
    match r {
        Ok(rows) => {
            let json = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
            set_error(out_rows_json, &json);
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Mark rows as shipped by setting `shipped_at` to the current UTC time.
///
/// `ids_json` — UTF-8 JSON array of ID strings, e.g. `["id1","id2"]`.
///              IDs that do not exist are silently ignored.
/// `out_err`  — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_mark_shipped(
    handle: *mut FastenStoreHandle,
    ids_json: *const c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let json_str = read_str(ids_json).ok_or(Error::NullArg)?;
        let ids: Vec<String> = serde_json::from_str(json_str)?;
        (*handle).store.mark_shipped(&ids)?;
        Ok(())
    });
    result_to_rc(r, out_err)
}

/// Delete rows whose `timestamp` is before `before_iso8601`.
///
/// `before_iso8601`    — ISO-8601 UTC upper bound; rows strictly older are
///                       deleted.
/// `respect_unshipped` — non-zero: skip rows with `shipped_at IS NULL`.
/// `out_deleted`       — set to the count of deleted rows; may be NULL.
/// `out_err`           — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_purge(
    handle: *mut FastenStoreHandle,
    before_iso8601: *const c_char,
    respect_unshipped: c_int,
    out_deleted: *mut u64,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let before = read_str(before_iso8601).ok_or(Error::NullArg)?;
        (*handle).store.purge(before, respect_unshipped != 0)
    });
    match r {
        Ok(n) => {
            if !out_deleted.is_null() {
                *out_deleted = n;
            }
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Return the maximum `monotonic_seq` across all stored rows, or 0 if empty.
/// Table-wide, not per node; do not use it to allocate a seq.
///
/// `out_seq` — set to the maximum sequence number on success; must be non-null.
/// `out_err` — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_max_monotonic_seq(
    handle: *mut FastenStoreHandle,
    out_seq: *mut u64,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        (*handle).store.max_monotonic_seq()
    });
    match r {
        Ok(seq) => {
            if !out_seq.is_null() {
                *out_seq = seq;
            }
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// List rows a PII retention horizon would redact (spec §7.1).
///
/// `before_iso8601` — rows with `timestamp` strictly older are candidates.
/// `codes_json`     — UTF-8 JSON array of codes, e.g. `["USER_LOGIN"]`.
/// `out_json`       — on success, a JSON array of
///                    `{"id": ..., "monotonic_seq": ...}` ordered by
///                    `monotonic_seq`. Free with `fasten_store_free_str`.
/// `out_skipped`    — on success, the number of matching sealed rows left
///                    out of `out_json`. May be NULL.
/// `out_err`        — set on error; may be NULL.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_list_redaction_candidates(
    handle: *mut FastenStoreHandle,
    before_iso8601: *const c_char,
    codes_json: *const c_char,
    out_json: *mut *mut c_char,
    out_skipped: *mut u64,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let before = read_str(before_iso8601).ok_or(Error::NullArg)?;
        let codes: Vec<String> = serde_json::from_str(read_str(codes_json).ok_or(Error::NullArg)?)?;
        let found = (*handle).store.list_redaction_candidates(before, &codes)?;
        let out: Vec<_> = found
            .rows
            .into_iter()
            .map(|(id, seq)| serde_json::json!({"id": id, "monotonic_seq": seq}))
            .collect();
        Ok((serde_json::to_string(&out)?, found.skipped))
    });
    match r {
        Ok((json, skipped)) => {
            set_error(out_json, &json);
            if !out_skipped.is_null() {
                *out_skipped = skipped;
            }
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Set `detail` to JSON `null` on the rows in `ids_json` (spec §7.1).
///
/// `ids_json`     — UTF-8 JSON array of ids. Idempotent; sealed rows are
///                  left alone.
/// `out_ids_json` — on success, the JSON array of ids passed in. Free with
///                  `fasten_store_free_str`. May be NULL.
/// `out_err`      — set on error; may be NULL.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_redact_rows(
    handle: *mut FastenStoreHandle,
    ids_json: *const c_char,
    out_ids_json: *mut *mut c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        let ids: Vec<String> = serde_json::from_str(read_str(ids_json).ok_or(Error::NullArg)?)?;
        let done = (*handle).store.redact_rows(&ids)?;
        Ok(serde_json::to_string(&done)?)
    });
    match r {
        Ok(json) => {
            set_error(out_ids_json, &json);
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

// ── Callback-backed store ──────────────────────────────────────────────────

/// C callback: `fn(row_json, userdata) -> 0=ok, nonzero=error`.
pub type CInsertFn = unsafe extern "C" fn(*const c_char, *mut std::ffi::c_void) -> i32;

struct SendRawPtr(*mut std::ffi::c_void);
unsafe impl Send for SendRawPtr {}
unsafe impl Sync for SendRawPtr {}

struct CallbackStore { fn_ptr: CInsertFn, ud: SendRawPtr }

impl Store for CallbackStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        let json = serde_json::to_string(row)?;
        let cs = CString::new(json).map_err(|_| Error::NullArg)?;
        let rc = unsafe { (self.fn_ptr)(cs.as_ptr(), self.ud.0) };
        if rc != 0 { Err(Error::CallbackFailed(rc)) }
        else { Ok(()) }
    }
    fn ping(&self) -> Result<(), Error> { Ok(()) }
    fn query(&self, _: &Filter) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn count(&self, _: &Filter) -> Result<u64, Error> { Ok(0) }
    fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), Error> { Ok(()) }
    fn purge(&self, _: &str, _: bool) -> Result<u64, Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, Error> { Ok(0) }
    // Redaction keeps the trait defaults (Unsupported): the callback can
    // only insert.
}

/// Create a store handle backed by an insert callback.
///
/// `fn_ptr` is invoked by the drainer's background thread for each row.
/// `userdata` is passed through unchanged; the caller must keep it valid
/// while the handle is alive.  Always returns a non-null handle.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_from_callback(
    fn_ptr: CInsertFn,
    userdata: *mut std::ffi::c_void,
    _out_err: *mut *mut c_char,
) -> *mut FastenStoreHandle {
    let store: Arc<dyn Store> = Arc::new(CallbackStore { fn_ptr, ud: SendRawPtr(userdata) });
    Box::into_raw(Box::new(FastenStoreHandle { store, drainer: None }))
}

/// Close the store (and any attached drainer) and release all resources.
///
/// Safe to call with NULL.  After this call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_close(handle: *mut FastenStoreHandle) {
    if !handle.is_null() {
        // Stop drainer first so its background thread exits cleanly before
        // the store Arc's ref-count drops to zero.
        let h = &mut *handle;
        if let Some(d) = h.drainer.take() {
            d.stop(std::time::Duration::from_secs(2));
        }
        drop(Box::from_raw(handle));
    }
}

/// Free an error string (or JSON output string) returned by this library.
///
/// Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_free_str(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: s was allocated in set_error via CString::into_raw.
        drop(CString::from_raw(s));
    }
}

/// Return a NUL-terminated version string (e.g. `"0.1.0"`).
///
/// The returned pointer is valid for the lifetime of the process.
#[no_mangle]
pub extern "C" fn fasten_store_version() -> *const c_char {
    static VERSION: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(env!("CARGO_PKG_VERSION")).expect("version is NUL-free")
        })
        .as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::Row;
    use crate::store::Store;

    /// Regression for issue #36 — Bug 2: when a host-language insert
    /// callback returns non-zero, CallbackStore must report
    /// `CallbackFailed(rc)`, not `InvalidTableName("insert callback rc=N")`.
    /// The old wording ran an SQL-identifier validation regex against
    /// what was actually a free-form error message, masking the real
    /// host-side exception (compounded with Bug 1 — see python's
    /// _insert_cb test for the round-trip half).
    #[test]
    fn callback_store_failure_reports_callback_failed_variant() {
        // Returns a non-zero rc to simulate a host-side callback that
        // caught its own exception and surfaced an error code.
        extern "C" fn failing_cb(
            _json: *const c_char,
            _ud: *mut std::ffi::c_void,
        ) -> i32 {
            7  // arbitrary non-zero
        }
        let store = CallbackStore {
            fn_ptr: failing_cb,
            ud: SendRawPtr(std::ptr::null_mut()),
        };
        let row = Row::default();
        let err = store.insert(&row).expect_err("non-zero rc must error");
        assert!(
            matches!(err, Error::CallbackFailed(7)),
            "expected CallbackFailed(7); got {err:?} \
             (formatted: {err})",
        );
        // And the human-readable form is what an adopter actually sees
        // in their `audit_drain_failed` log line — no "table name" noise.
        assert_eq!(err.to_string(), "insert callback returned non-zero rc=7");
    }

    #[test]
    fn callback_store_success_returns_ok() {
        extern "C" fn ok_cb(
            _json: *const c_char,
            _ud: *mut std::ffi::c_void,
        ) -> i32 {
            0
        }
        let store = CallbackStore {
            fn_ptr: ok_cb,
            ud: SendRawPtr(std::ptr::null_mut()),
        };
        assert!(store.insert(&Row::default()).is_ok());
    }

    unsafe fn take(p: *mut c_char) -> String {
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_owned();
        fasten_store_free_str(p);
        s
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn redaction_exports_round_trip_json() {
        let cs = |s: &str| CString::new(s).unwrap();
        unsafe {
            let mut err: *mut c_char = std::ptr::null_mut();
            let h = fasten_store_open(
                cs("sqlite").as_ptr(), cs(":memory:").as_ptr(), cs("audit_log").as_ptr(), &mut err,
            );
            assert!(!h.is_null());
            let row = serde_json::json!({
                "wire_version": "1", "id": "evt-1", "origin_id": "evt-1", "monotonic_seq": 0,
                "timestamp": "2020-01-01T00:00:00.000000Z", "code": "USER_LOGIN",
                "action": "a", "severity": "info", "service_id": "s", "source_node_id": "n",
                "actor": "u", "actor_kind": "user", "target": "t", "category": "c",
                "domain": "d", "method": "sdk", "request_id": "r", "detail": {"email": "x"},
            });
            let rc = fasten_store_insert(h, cs(&row.to_string()).as_ptr(), &mut err);
            assert_eq!(rc, FastenErrorCode::Ok);

            let mut out: *mut c_char = std::ptr::null_mut();
            let mut skipped: u64 = 99;
            let rc = fasten_store_list_redaction_candidates(
                h, cs("2021-01-01T00:00:00Z").as_ptr(), cs(r#"["USER_LOGIN"]"#).as_ptr(),
                &mut out, &mut skipped, &mut err,
            );
            assert_eq!(rc, FastenErrorCode::Ok);
            assert_eq!(take(out), r#"[{"id":"evt-1","monotonic_seq":1}]"#);
            assert_eq!(skipped, 0);

            // out_skipped may be NULL.
            let rc = fasten_store_list_redaction_candidates(
                h, cs("2021-01-01T00:00:00Z").as_ptr(), cs(r#"["USER_LOGIN"]"#).as_ptr(),
                &mut out, std::ptr::null_mut(), &mut err,
            );
            assert_eq!(rc, FastenErrorCode::Ok);
            take(out);

            let rc = fasten_store_redact_rows(h, cs(r#"["evt-1"]"#).as_ptr(), &mut out, &mut err);
            assert_eq!(rc, FastenErrorCode::Ok);
            assert_eq!(take(out), r#"["evt-1"]"#);
            fasten_store_close(h);
        }
    }

    #[test]
    fn callback_store_has_no_redaction() {
        extern "C" fn ok_cb(_json: *const c_char, _ud: *mut std::ffi::c_void) -> i32 { 0 }
        let store = CallbackStore { fn_ptr: ok_cb, ud: SendRawPtr(std::ptr::null_mut()) };
        assert!(matches!(store.redact_rows(&["x".into()]), Err(Error::Unsupported(_))));
    }
}
