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
//! the documented ownership rules in `include/fasten_store_core.h`.

mod util;
pub(crate) mod catalog;
pub(crate) mod redact;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic;

use crate::{
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
            "fasten-store-core: internal panic".into(),
        )),
    }
}

// ── Opaque handle ─────────────────────────────────────────────────────────────

/// Heap-allocated, type-erased store. C sees only `FastenStore*`.
pub struct FastenStoreHandle {
    store: Box<dyn Store>,
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

        let store: Box<dyn Store> = match backend {
            #[cfg(feature = "sqlite")]
            "sqlite" => Box::new(crate::store::sqlite::SqliteStore::open(
                connstr, table, true,
            )?),

            #[cfg(feature = "postgres")]
            "postgres" => Box::new(crate::store::postgres::PostgresStore::connect(
                connstr, table,
            )?),

            other => return Err(Error::UnknownBackend(other.to_owned())),
        };

        Ok(Box::into_raw(Box::new(FastenStoreHandle { store })))
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

/// Close the store and release all resources.
///
/// Safe to call with NULL.  After this call the handle is invalid.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_close(handle: *mut FastenStoreHandle) {
    if !handle.is_null() {
        // SAFETY: handle was allocated in fasten_store_open via Box::into_raw;
        // ownership is transferred back here and dropped at end of scope.
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
