use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Convert a raw C string pointer to a Rust `&str`.
///
/// # Safety
/// `ptr` must either be null (in which case `None` is returned) or point to a
/// valid, NUL-terminated, UTF-8-encoded C string that remains valid for the
/// duration of the returned reference.
pub(crate) unsafe fn read_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is valid and NUL-terminated.
    CStr::from_ptr(ptr).to_str().ok()
}

/// Write an error message into the caller-provided `*out_err` slot.
///
/// The resulting string is heap-allocated.  The C caller must free it with
/// `fasten_store_free_str`.  If `out_err` is null the message is silently
/// discarded — callers that don't care about error text may pass NULL.
///
/// # Safety
/// `out_err`, if non-null, must point to a writable `*mut c_char` slot.
pub(crate) unsafe fn set_error(out_err: *mut *mut c_char, msg: &str) {
    if out_err.is_null() {
        return;
    }
    // Replace interior NUL bytes so the string stays valid as a C string.
    let safe_msg = msg.replace('\0', "\\0");
    match CString::new(safe_msg) {
        Ok(cs) => *out_err = cs.into_raw(),
        Err(_) => {
            // Fallback: a generic message that is guaranteed NUL-free.
            if let Ok(cs) = CString::new("fasten-store-core: error (non-UTF-8 detail)") {
                *out_err = cs.into_raw();
            }
        }
    }
}
