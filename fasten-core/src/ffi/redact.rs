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

/// Options for `fasten_redact_opts`. Every field is optional.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RedactOptions {
    extra_keys:           Vec<String>,
    replacement:          String,
    extra_value_patterns: Vec<ExtraValuePattern>,
    check_numbers:        bool,
}

fn redact_with_options(input: &str, options_json: Option<&str>) -> Result<String, crate::error::Error> {
    let opts: RedactOptions = match options_json {
        Some(json) if !json.is_empty() => serde_json::from_str(json)?,
        _ => RedactOptions::default(),
    };
    let key_refs: Vec<&str> = opts.extra_keys.iter().map(String::as_str).collect();
    let vp_refs: Vec<(&str, &str)> = opts
        .extra_value_patterns
        .iter()
        .map(|p| (p.pattern.as_str(), p.replacement.as_str()))
        .collect();
    Redactor::new(&key_refs, &opts.replacement, &vp_refs)
        .with_check_numbers(opts.check_numbers)
        .redact_json(input)
}

/// Redact a JSON value with options given as one JSON object:
/// `{"extra_keys":[...],"replacement":"...","extra_value_patterns":[...],
/// "check_numbers":true}`. Every field is optional; the defaults are those
/// of `fasten_redact`. `check_numbers` turns on the card rule for numbers
/// with no fractional part.
///
/// `in_json`:      UTF-8 JSON string.
/// `options_json`: nullable: the options object. NULL = defaults.
/// `out_json`:     set to heap-allocated redacted JSON on success.
///                 Free with `fasten_store_free_str`. May be NULL.
/// `out_err`:      set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact_opts(
    in_json:      *const c_char,
    options_json: *const c_char,
    out_json:     *mut *mut c_char,
    out_err:      *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| redact_with_options(read_req(in_json)?, read_opt(options_json)?));
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

/// Buffer-based variant of `fasten_redact_opts`.
///
/// Returns bytes written (exclusive of NUL) on success.
/// Returns `-(FastenErrorCode as i32)` on error.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact_opts_buf(
    in_json:      *const c_char,
    options_json: *const c_char,
    out_buf:      *mut u8,
    buf_len:      u32,
    out_err_buf:  *mut u8,
    err_buf_len:  u32,
) -> i32 {
    let r = guarded(|| redact_with_options(read_req(in_json)?, read_opt(options_json)?));
    match r {
        Ok(json)      => write_to_buf(out_buf, buf_len as usize, &json),
        Err((c, msg)) => write_err_to_buf(out_err_buf, err_buf_len as usize, &msg, c),
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

    fn redact_opts(input: &str, options: Option<&str>) -> (FastenErrorCode, String) {
        let input = CString::new(input).unwrap();
        let options = options.map(|o| CString::new(o).unwrap());
        let mut out: *mut c_char = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        let code = unsafe {
            fasten_redact_opts(
                input.as_ptr(),
                options.as_ref().map_or(ptr::null(), |o| o.as_ptr()),
                &mut out,
                &mut err,
            )
        };
        let p = if out.is_null() { err } else { out };
        let text = if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned() };
        if !p.is_null() {
            unsafe { super::super::fasten_store_free_str(p) };
        }
        (code, text)
    }

    #[test]
    fn opts_check_numbers() {
        let input = r#"{"card":4111111111111111,"token":"x"}"#;
        let (code, out) = redact_opts(input, None);
        assert_eq!(code, FastenErrorCode::Ok);
        assert_eq!(out, r#"{"card":4111111111111111,"token":"***"}"#);
        let (_, out) = redact_opts(input, Some(r#"{"check_numbers":true,"replacement":"[gone]"}"#));
        assert_eq!(out, r#"{"card":"***CC***","token":"[gone]"}"#);
        let (code, _) = redact_opts(input, Some(r#"{"check_number":true}"#));
        assert_ne!(code, FastenErrorCode::Ok);
    }
}
