//! C ABI — code catalog functions.

use std::collections::HashMap;
use std::os::raw::c_char;

use super::util::{read_str, set_error, write_to_buf, write_err_to_buf};
use super::guarded;
use crate::{
    catalog::{Meta, GLOBAL_REGISTRY},
    error::{Error, FastenErrorCode},
};

/// Register a batch of audit codes for a domain.
///
/// `domain`     — UTF-8 domain string, e.g. `"user"` or `"billing"`.
/// `codes_json` — UTF-8 JSON object mapping code keys to Meta objects:
///   ```json
///   {
///     "USER_CREATED": {
///       "domain": "user", "category": "auth", "action": "create",
///       "severity": "info", "description": "...", "emitter": "auth-svc"
///     }
///   }
///   ```
///   All fields except `id`, `retention_class`, `high_volume`, `pii_in_detail`,
///   `declared_unused`, and `detail_passthrough_keys` are required.
/// `out_err`    — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_register_codes(
    domain:     *const c_char,
    codes_json: *const c_char,
    out_err:    *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let domain_str = read_str(domain).ok_or(Error::NullArg)?;
        let json_str   = read_str(codes_json).ok_or(Error::NullArg)?;
        let codes: HashMap<String, Meta> = serde_json::from_str(json_str)?;
        GLOBAL_REGISTRY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register(domain_str, codes)?;
        Ok(())
    });
    match r {
        Ok(()) => FastenErrorCode::Ok,
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

/// Look up a single code in the global registry.
///
/// `code`      — UTF-8 code key, e.g. `"USER_CREATED"`.
/// `out_json`  — set to a heap-allocated UTF-8 JSON object (Meta) on success.
///               Returns an empty JSON object `{}` when the code is not found.
///               Free with `fasten_store_free_str`. May be NULL.
/// `out_err`   — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_meta_of(
    code:     *const c_char,
    out_json: *mut *mut c_char,
    out_err:  *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let code_str = read_str(code).ok_or(Error::NullArg)?;
        let reg = GLOBAL_REGISTRY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let json = match reg.meta_of(code_str) {
            Some(meta) => serde_json::to_string(meta)?,
            None => "{}".to_owned(),
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

/// Dump the registry as `id,domain,severity` CSV (sorted, one code per line).
///
/// `out_csv` — set to a heap-allocated UTF-8 string.
///             Free with `fasten_store_free_str`. May be NULL.
/// `out_err` — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_registry_dump(
    out_csv: *mut *mut c_char,
    out_err: *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let reg = GLOBAL_REGISTRY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(reg.dump())
    });
    match r {
        Ok(csv) => {
            set_error(out_csv, &csv);
            FastenErrorCode::Ok
        }
        Err((code, msg)) => {
            set_error(out_err, &msg);
            code
        }
    }
}

// ── Buffer-based variants (no heap allocation) ────────────────────────────────

/// Buffer-based variant of `fasten_register_codes`.
///
/// Writes NUL-terminated error message to `out_err_buf` on failure.
/// Returns `FASTEN_OK` (0) on success, positive `FastenErrorCode` on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_register_codes_buf(
    domain:      *const c_char,
    codes_json:  *const c_char,
    out_err_buf: *mut u8,
    err_buf_len: u32,
) -> i32 {
    let r = guarded(|| {
        let domain_str = read_str(domain).ok_or(Error::NullArg)?;
        let json_str   = read_str(codes_json).ok_or(Error::NullArg)?;
        let codes: HashMap<String, Meta> = serde_json::from_str(json_str)?;
        GLOBAL_REGISTRY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register(domain_str, codes)?;
        Ok(())
    });
    match r {
        Ok(())        => 0,
        // Return positive error code (same convention as fasten_register_codes).
        // write_err_to_buf returns negative; negate to get positive.
        Err((c, msg)) => -write_err_to_buf(out_err_buf, err_buf_len as usize, &msg, c),
    }
}

/// Buffer-based variant of `fasten_meta_of`.
///
/// Writes NUL-terminated UTF-8 JSON Meta to `out_buf` on success.
/// Returns bytes written (exclusive of NUL) on success, 0 if the code is not
/// found, or `-(FastenErrorCode as i32)` on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_meta_of_buf(
    code:        *const c_char,
    out_buf:     *mut u8,
    buf_len:     u32,
    out_err_buf: *mut u8,
    err_buf_len: u32,
) -> i32 {
    let r = guarded(|| {
        let code_str = read_str(code).ok_or(Error::NullArg)?;
        let reg = GLOBAL_REGISTRY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(match reg.meta_of(code_str) {
            Some(meta) => Some(serde_json::to_string(meta)?),
            None => None,
        })
    });
    match r {
        Ok(Some(json)) => write_to_buf(out_buf, buf_len as usize, &json),
        Ok(None)       => {
            if !out_buf.is_null() && buf_len > 0 {
                *out_buf = 0;
            }
            0
        }
        Err((c, msg))  => write_err_to_buf(out_err_buf, err_buf_len as usize, &msg, c),
    }
}

/// Clear the global registry (intended for test teardown and re-init).
#[no_mangle]
pub extern "C" fn fasten_registry_clear() {
    GLOBAL_REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}
