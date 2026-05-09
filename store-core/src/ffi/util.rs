use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::error::FastenErrorCode;

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

// ── Buffer-based output helpers (no heap allocation, for FFI callers like Node.js) ──

/// Write `s` into a caller-provided `[u8; buf_len]` buffer (NUL-terminated).
///
/// Returns bytes written (exclusive of NUL) on success.
/// Returns `-(ErrUnknown as i32)` if `buf` is null, `buf_len` is 0, or the
/// buffer is too small; writes a truncated NUL-terminated string in that case.
///
/// # Safety
/// `buf`, if non-null, must point to at least `buf_len` writable bytes.
pub(crate) unsafe fn write_to_buf(buf: *mut u8, buf_len: usize, s: &str) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return -(FastenErrorCode::ErrUnknown as i32);
    }
    let bytes = s.as_bytes();
    if bytes.len() + 1 > buf_len {
        // Truncate to fit — caller can detect via return value vs buf_len.
        let n = buf_len - 1;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        *buf.add(n) = 0;
        return -(FastenErrorCode::ErrUnknown as i32);
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    *buf.add(bytes.len()) = 0;
    bytes.len() as i32
}

/// Write an error message into `buf` (NUL-terminated, truncated to fit) and
/// return `-(code as i32)`.
///
/// # Safety
/// `buf`, if non-null, must point to at least `buf_len` writable bytes.
pub(crate) unsafe fn write_err_to_buf(
    buf:     *mut u8,
    buf_len: usize,
    msg:     &str,
    code:    FastenErrorCode,
) -> i32 {
    if !buf.is_null() && buf_len > 0 {
        let bytes = msg.as_bytes();
        let n = bytes.len().min(buf_len - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        *buf.add(n) = 0;
    }
    -(code as i32)
}
