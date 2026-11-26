//! C ABI: redaction functions.

use std::os::raw::c_char;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;

use super::util::{read_opt, read_req, set_error, write_to_buf, write_err_to_buf};
use super::guarded;
use crate::{
    error::{Error, FastenErrorCode},
    redact::Redactor,
};

/// Extra keys, replacement, and value patterns as `(pattern, replacement)`.
type RedactorArgs = (Vec<String>, String, Vec<(String, String)>);

/// The last custom redactor built, with the arguments it was built from.
/// Hosts pass the same config on every emit, so this skips recompiling the
/// patterns each call.
static LAST_REDACTOR: Mutex<Option<(RedactorArgs, Arc<Redactor>)>> = Mutex::new(None);

fn custom_redactor(
    extra_keys: Vec<String>,
    replacement: &str,
    extra_vp: Vec<ExtraValuePattern>,
) -> Result<Arc<Redactor>, Error> {
    let args: RedactorArgs = (
        extra_keys,
        replacement.to_owned(),
        extra_vp.into_iter().map(|p| (p.pattern, p.replacement)).collect(),
    );
    let mut last = LAST_REDACTOR.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((built_from, r)) = last.as_ref() {
        if *built_from == args {
            return Ok(r.clone());
        }
    }
    let key_refs: Vec<&str> = args.0.iter().map(String::as_str).collect();
    let vp_refs: Vec<(&str, &str)> = args.2.iter().map(|(p, r)| (p.as_str(), r.as_str())).collect();
    let r = Arc::new(Redactor::new(&key_refs, &args.1).with_value_patterns(&vp_refs)?);
    *last = Some((args, r.clone()));
    Ok(r)
}

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

        // A replacement that isn't UTF-8 is treated as unset (the default
        // "***"), as the Rust SDK does, rather than failing every redaction.
        let repl = read_opt(replacement).ok().flatten().unwrap_or("");

        let extra_vp: Vec<ExtraValuePattern> = match read_opt(extra_value_patterns_json)? {
            Some(json) if !json.is_empty() => serde_json::from_str(json)?,
            _ => vec![],
        };

        custom_redactor(extra_keys, repl, extra_vp)?.redact_json(input)
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

        // A replacement that isn't UTF-8 is treated as unset (the default
        // "***"), as the Rust SDK does, rather than failing every redaction.
        let repl = read_opt(replacement).ok().flatten().unwrap_or("");

        let extra_vp: Vec<ExtraValuePattern> = match read_opt(extra_value_patterns_json)? {
            Some(json) => serde_json::from_str(json)?,
            None => vec![],
        };

        custom_redactor(extra_keys, repl, extra_vp)?.redact_json(input)
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
    Redactor::new(&key_refs, &opts.replacement)
        .with_value_patterns(&vp_refs)?
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

    /// A bad value pattern from the host is an `ErrBadJson` naming the
    /// pattern, not an internal panic; the next good call still works.
    #[test]
    fn invalid_value_pattern_is_bad_json() {
        let input = CString::new(r#"{"ref":"custom_ABCDEFGH"}"#).unwrap();
        let bad = CString::new(r#"[{"pattern":"([","replacement":"X"}]"#).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        let code = unsafe {
            fasten_redact_full(input.as_ptr(), ptr::null(), ptr::null(), bad.as_ptr(), &mut out, &mut err)
        };
        assert_eq!(code, FastenErrorCode::ErrBadJson);
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
        unsafe { super::super::fasten_store_free_str(err) };
        assert!(msg.contains("([") && msg.contains("does not compile"), "{msg}");

        let good = CString::new(r#"[{"pattern":"custom_[A-Z]{8}","replacement":"***C***"}]"#).unwrap();
        for _ in 0..2 {
            let mut out: *mut c_char = ptr::null_mut();
            let code = unsafe {
                fasten_redact_full(input.as_ptr(), ptr::null(), ptr::null(), good.as_ptr(), &mut out, ptr::null_mut())
            };
            assert_eq!(code, FastenErrorCode::Ok);
            let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
            unsafe { super::super::fasten_store_free_str(out) };
            assert_eq!(serde_json::from_str::<serde_json::Value>(&json).unwrap()["ref"], "***C***");
        }
    }

    /// `fasten_redact_full` with the given arguments; panics unless it succeeds.
    fn redact_full(input: &str, keys: &str, repl: &str, patterns: &str) -> serde_json::Value {
        let (input, keys) = (CString::new(input).unwrap(), CString::new(keys).unwrap());
        let (repl, patterns) = (CString::new(repl).unwrap(), CString::new(patterns).unwrap());
        let mut out: *mut c_char = ptr::null_mut();
        let code = unsafe {
            fasten_redact_full(input.as_ptr(), keys.as_ptr(), repl.as_ptr(), patterns.as_ptr(), &mut out, ptr::null_mut())
        };
        assert_eq!(code, FastenErrorCode::Ok);
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
        unsafe { super::super::fasten_store_free_str(out) };
        serde_json::from_str(&json).unwrap()
    }

    /// The reused redactor is rebuilt whenever any argument changes: a
    /// stale one would apply the wrong keys or replacement.
    #[test]
    fn reused_redactor_follows_every_argument() {
        let input = r#"{"field_a":"x","field_b":"y"}"#;
        let out = redact_full(input, r#"["field_a"]"#, "[A]", "[]");
        assert_eq!((out["field_a"].as_str(), out["field_b"].as_str()), (Some("[A]"), Some("y")));
        let out = redact_full(input, r#"["field_a"]"#, "[B]", "[]");
        assert_eq!(out["field_a"], "[B]");
        let out = redact_full(input, r#"["field_b"]"#, "[B]", "[]");
        assert_eq!((out["field_a"].as_str(), out["field_b"].as_str()), (Some("x"), Some("[B]")));
    }

    /// The buffer variant reports a bad pattern the same way.
    #[test]
    fn buf_variant_reports_a_bad_pattern() {
        let input = CString::new(r#"{"k":"v"}"#).unwrap();
        let empty = CString::new("[]").unwrap();
        let repl = CString::new("").unwrap();
        let bad = CString::new(r#"[{"pattern":"([","replacement":"X"}]"#).unwrap();
        let mut out = [0u8; 256];
        let mut err = [0u8; 256];
        let rc = unsafe {
            fasten_redact_full_buf(
                input.as_ptr(), empty.as_ptr(), repl.as_ptr(), bad.as_ptr(),
                out.as_mut_ptr(), 256, err.as_mut_ptr(), 256,
            )
        };
        assert_eq!(rc, -(FastenErrorCode::ErrBadJson as i32));
        let msg = CStr::from_bytes_until_nul(&err).unwrap().to_str().unwrap();
        assert!(msg.contains("([") && msg.contains("does not compile"), "{msg}");
    }
}
