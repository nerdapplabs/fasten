//! C ABI exports.
//!
//! Every `extern "C"` function in this module:
//!   1. validates all pointer arguments before dereferencing them,
//!   2. wraps the body in `std::panic::catch_unwind` so a Rust panic can never
//!      unwind across the FFI boundary (which is undefined behaviour), and
//!   3. maps errors to a caller-owned `*mut c_char` error string freed via
//!      `fasten_store_free_str`.
//!
//! No Rust panics, no use-after-free, no double-free when the C caller follows
//! the documented ownership rules in `include/fasten_store_core.h`.

mod util;

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic;

use crate::{error::Error, row::Row, store::Store};
use util::{read_str, set_error};

// ── Opaque handle ─────────────────────────────────────────────────────────────

/// Heap-allocated, type-erased store. C sees only `FastenStore*`.
pub struct FastenStoreHandle {
    store: Box<dyn Store>,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Run `f`; catch any Rust panic; map the result to `Ok(R)` / `Err(String)`.
fn guarded<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce() -> Result<R, Error>,
{
    match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("fasten-store-core: internal panic".into()),
    }
}

/// Convert a guarded result to a C return code; write the error string.
///
/// # Safety
/// `out_err` must be null or point to a writable `*mut c_char` slot.
unsafe fn result_to_rc(
    result: Result<(), String>,
    out_err: *mut *mut c_char,
) -> c_int {
    match result {
        Ok(()) => 0,
        Err(msg) => {
            set_error(out_err, &msg);
            1
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
        Err(msg) => {
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
/// Returns 0 on success, 1 on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_insert(
    handle: *mut FastenStoreHandle,
    row_json: *const c_char,
    out_err: *mut *mut c_char,
) -> c_int {
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
/// Returns 0 on success, 1 on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_store_ping(
    handle: *mut FastenStoreHandle,
    out_err: *mut *mut c_char,
) -> c_int {
    let r = guarded(|| {
        if handle.is_null() {
            return Err(Error::NullArg);
        }
        (*handle).store.ping()?;
        Ok(())
    });
    result_to_rc(r, out_err)
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

/// Free an error string returned by this library.
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
