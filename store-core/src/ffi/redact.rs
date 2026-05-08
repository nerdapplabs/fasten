//! C ABI — redaction functions.

use std::os::raw::c_char;

use serde::Deserialize;

use super::util::{read_str, set_error};
use super::guarded;
use crate::{
    error::{Error, FastenErrorCode},
    redact::Redactor,
};

/// Redact a JSON value using the global default key-pattern + value-shape rules.
///
/// `in_json`   — UTF-8 JSON string (object, array, or scalar).
/// `out_json`  — set to a heap-allocated UTF-8 JSON string on success.
///               Free with `fasten_store_free_str`. May be NULL if unneeded.
/// `out_err`   — set on error; may be NULL.
///
/// Returns `FASTEN_OK` (0) on success, an error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn fasten_redact(
    in_json:  *const c_char,
    out_json: *mut *mut c_char,
    out_err:  *mut *mut c_char,
) -> FastenErrorCode {
    let r = guarded(|| {
        let input = read_str(in_json).ok_or(Error::NullArg)?;
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

// ── Custom-pattern redaction ──────────────────────────────────────────────────

/// JSON shape for an extra value-shape pattern passed to `fasten_redact_full`.
#[derive(Deserialize)]
struct ExtraValuePattern {
    pattern:     String,
    replacement: String,
}

/// Redact a JSON value with fully-custom key patterns, replacement token, and
/// extra value-shape patterns.
///
/// `in_json`                   — UTF-8 JSON string.
/// `extra_keys_json`           — nullable: JSON array of plain key strings.
///                               NULL = no extra key patterns.
/// `replacement`               — nullable: replacement token for key-pattern hits.
///                               NULL = use default `"***"`.
/// `extra_value_patterns_json` — nullable: JSON array of objects:
///                               `[{"pattern":"<regex>","replacement":"***X***"},...]`
///                               Appended after built-in value patterns. NULL = none.
/// `out_json`                  — set to heap-allocated redacted JSON on success.
///                               Free with `fasten_store_free_str`. May be NULL.
/// `out_err`                   — set on error; may be NULL.
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
        let input = read_str(in_json).ok_or(Error::NullArg)?;

        let extra_keys: Vec<String> = match read_str(extra_keys_json) {
            Some(json) => serde_json::from_str(json)?,
            None => vec![],
        };
        let key_refs: Vec<&str> = extra_keys.iter().map(String::as_str).collect();

        let repl = read_str(replacement).unwrap_or("");

        let extra_vp: Vec<ExtraValuePattern> = match read_str(extra_value_patterns_json) {
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
