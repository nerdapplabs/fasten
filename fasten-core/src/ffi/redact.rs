//! C ABI: redaction functions.

use std::os::raw::c_char;

use serde::Deserialize;

use super::util::{read_opt, read_req, set_error, write_to_buf, write_err_to_buf};
use super::guarded;
use crate::{
    error::FastenErrorCode,
    redact::Redactor,
};

/// Redact a JSON value using the global default key-pattern + value-shape rules.
///
/// `in_json`:    UTF-8 JSON string (object, array, or scalar).
/// `out_json`:   set to a heap-allocated UTF-8 JSON string on success.
///               Free with `fasten_store_free_str`. May be NULL if unneeded.
/// `out_err`:    set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact(
    in_json:  *const c_char,
    out_json: *mut *mut c_char,
    out_err:  *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let input = read_req(in_json)?;
        crate::redact::REDACTOR.redact_json(input)
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

/// Buffer-based variant of `fasten_redact`.
///
/// Writes NUL-terminated UTF-8 redacted JSON to `out_buf` on success.
/// Writes NUL-terminated error message to `out_err_buf` on failure.
///
/// Returns bytes written (exclusive of NUL) on success.
/// Returns `-(FastenErrorCode as i32)` on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact_buf(
    in_json:     *const c_char,
    out_buf:     *mut u8,
    buf_len:     u32,
    out_err_buf: *mut u8,
    err_buf_len: u32,
) -> i32 {
    let r = guarded(|| {
        let input = read_req(in_json)?;
        crate::redact::REDACTOR.redact_json(input)
    });
    match r {
        Ok(json)       => write_to_buf(out_buf, buf_len as usize, &json),
        Err((c, msg))  => write_err_to_buf(out_err_buf, err_buf_len as usize, &msg, c),
    }
}

/// Buffer-based variant of `fasten_redact_full`.
///
/// `extra_keys_json`:            JSON array of key strings (e.g. `"[]"`), never NULL.
/// `replacement`:                replacement token; empty string means the default `"***"`.
/// `extra_value_patterns_json`:  JSON array of pattern objects (e.g. `"[]"`), never NULL.
///
/// Returns bytes written (exclusive of NUL) on success.
/// Returns `-(FastenErrorCode as i32)` on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact_full_buf(
    in_json:                   *const c_char,
    extra_keys_json:           *const c_char,
    replacement:               *const c_char,
    extra_value_patterns_json: *const c_char,
    out_buf:                   *mut u8,
    buf_len:                   u32,
    out_err_buf:               *mut u8,
    err_buf_len:               u32,
) -> i32 {
    let r = guarded(|| {
        let input = read_req(in_json)?;

        let extra_keys: Vec<String> = match read_opt(extra_keys_json)? {
            Some(json) if !json.is_empty() => serde_json::from_str(json)?,
            _ => vec![],
        };
        let key_refs: Vec<&str> = extra_keys.iter().map(String::as_str).collect();

        // A replacement that isn't UTF-8 is treated as unset (the default
        // "***"), as the Rust SDK does, rather than failing every redaction.
        let repl = read_opt(replacement).ok().flatten().unwrap_or("");

        let extra_vp: Vec<ExtraValuePattern> = match read_opt(extra_value_patterns_json)? {
            Some(json) if !json.is_empty() => serde_json::from_str(json)?,
            _ => vec![],
        };
        let vp_refs: Vec<(&str, &str)> = extra_vp
            .iter()
            .map(|p| (p.pattern.as_str(), p.replacement.as_str()))
            .collect();

        let redactor = Redactor::new(&key_refs, repl, &vp_refs);
        redactor.redact_json(input)
    });
    match r {
        Ok(json)      => write_to_buf(out_buf, buf_len as usize, &json),
        Err((c, msg)) => write_err_to_buf(out_err_buf, err_buf_len as usize, &msg, c),
    }
}

/// JSON shape for an extra value-shape pattern passed to `fasten_redact_full`.
#[derive(Deserialize)]
struct ExtraValuePattern {
    pattern:     String,
    replacement: String,
}

/// Redact a JSON value with fully-custom key patterns, replacement token, and
/// extra value-shape patterns.
///
/// `in_json`:                    UTF-8 JSON string.
/// `extra_keys_json`:            nullable: JSON array of plain key strings.
///                               NULL = no extra key patterns.
/// `replacement`:                nullable: replacement token for key-pattern hits.
///                               NULL = use default `"***"`.
/// `extra_value_patterns_json`:  nullable: JSON array of objects:
///                               `[{"pattern":"<regex>","replacement":"***X***"},...]`
///                               Appended after built-in value patterns. NULL = none.
/// `out_json`:                   set to heap-allocated redacted JSON on success.
///                               Free with `fasten_store_free_str`. May be NULL.
/// `out_err`:                    set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact_full(
    in_json:                    *const c_char,
    extra_keys_json:            *const c_char,
    replacement:                *const c_char,
    extra_value_patterns_json:  *const c_char,
    out_json:                   *mut *mut c_char,
    out_err:                    *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let input = read_req(in_json)?;

        let extra_keys: Vec<String> = match read_opt(extra_keys_json)? {
            Some(json) => serde_json::from_str(json)?,
            None => vec![],
        };
        let key_refs: Vec<&str> = extra_keys.iter().map(String::as_str).collect();

        // A replacement that isn't UTF-8 is treated as unset (the default
        // "***"), as the Rust SDK does, rather than failing every redaction.
        let repl = read_opt(replacement).ok().flatten().unwrap_or("");

        let extra_vp: Vec<ExtraValuePattern> = match read_opt(extra_value_patterns_json)? {
            Some(json) => serde_json::from_str(json)?,
            None => vec![],
        };
        let vp_refs: Vec<(&str, &str)> = extra_vp
            .iter()
            .map(|p| (p.pattern.as_str(), p.replacement.as_str()))
            .collect();

        let redactor = Redactor::new(&key_refs, repl, &vp_refs);
        redactor.redact_json(input)
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

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr;

    use super::*;

    /// A replacement that isn't UTF-8 is treated as unset: the default
    /// "***", not a failed redaction.
    #[test]
    fn replacement_not_utf8_is_the_default() {
        let input = CString::new(r#"{"password":"p","ok":"v"}"#).unwrap();
        let repl = CString::new(vec![b'[', 0xFF, b']']).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe {
            fasten_redact_full(input.as_ptr(), ptr::null(), repl.as_ptr(), ptr::null(), &mut out, ptr::null_mut())
        };
        assert_eq!(code, FastenErrorCode::Ok);
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
        unsafe { super::super::fasten_store_free_str(out) };
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["password"], "***");
        assert_eq!(v["ok"], "v");
    }
}
