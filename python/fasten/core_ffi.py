"""
ctypes binding to libfasten_core — the shared Rust engine.

Loads the compiled .so / .dylib / .dll and exposes thin Python wrappers around:
  - fasten_redact / fasten_redact_full  — secret redaction
  - fasten_register_codes               — code catalog registration
  - fasten_meta_of                      — single-code lookup
  - fasten_registry_dump                — sorted CSV dump
  - fasten_registry_clear               — clear global registry (tests)
  - fasten_store_free_str               — free library-allocated strings

Library location (tried in order):
  1. FASTEN_CORE_LIB env var — explicit path for CI / custom installs.
  2. Adjacent to this file — when the .so is bundled in the wheel.
  3. ctypes.util.find_library("fasten_core") — system-installed.
  4. Development path relative to this file:
       ../../fasten-core/target/release/libfasten_core.{so,dylib}
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

# ── Library loading ───────────────────────────────────────────────────────────

def _find_lib() -> str:
    # 1. Explicit override
    if (env := os.environ.get("FASTEN_CORE_LIB")):
        return env

    # 2. Bundled alongside this file (wheel layout)
    here = Path(__file__).parent
    suffix = ".dylib" if sys.platform == "darwin" else ".dll" if sys.platform == "win32" else ".so"
    bundled = here / f"libfasten_core{suffix}"
    if bundled.exists():
        return str(bundled)

    # 3. System linker path
    if (found := ctypes.util.find_library("fasten_core")):
        return found

    # 4. Development path (monorepo: python/fasten/ → fasten-core/target/release/)
    dev = here.parent.parent / "fasten-core" / "target" / "release" / f"libfasten_core{suffix}"
    if dev.exists():
        return str(dev)

    raise OSError(
        "libfasten_core not found. "
        "Build it with `cargo build --release --features all` in fasten-core/, "
        "then set FASTEN_CORE_LIB=/path/to/libfasten_core.so."
    )


def _configure(lib: ctypes.CDLL) -> None:
    c_char_p = ctypes.c_char_p
    c_int    = ctypes.c_int

    lib.fasten_redact.restype  = c_int
    lib.fasten_redact.argtypes = [c_char_p, ctypes.POINTER(c_char_p), ctypes.POINTER(c_char_p)]

    lib.fasten_redact_full.restype  = c_int
    lib.fasten_redact_full.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p,
        ctypes.POINTER(c_char_p), ctypes.POINTER(c_char_p),
    ]

    lib.fasten_register_codes.restype  = c_int
    lib.fasten_register_codes.argtypes = [c_char_p, c_char_p, ctypes.POINTER(c_char_p)]

    lib.fasten_meta_of.restype  = c_int
    lib.fasten_meta_of.argtypes = [c_char_p, ctypes.POINTER(c_char_p), ctypes.POINTER(c_char_p)]

    lib.fasten_registry_dump.restype  = c_int
    lib.fasten_registry_dump.argtypes = [ctypes.POINTER(c_char_p), ctypes.POINTER(c_char_p)]

    lib.fasten_registry_clear.restype  = None
    lib.fasten_registry_clear.argtypes = []

    lib.fasten_store_free_str.restype  = None
    lib.fasten_store_free_str.argtypes = [c_char_p]


_lib: Optional[ctypes.CDLL] = None


def get_lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = ctypes.CDLL(_find_lib())
        _configure(_lib)
    return _lib


# ── Low-level call helpers ────────────────────────────────────────────────────

_FASTEN_OK = 0


def _call_out_str(fn: Any, *args: Any) -> str:
    """Call an FFI function that writes one output string.

    Interprets the last two argtypes as `*out_str, *out_err`.
    Returns the output string on success; raises `RuntimeError` on error.
    """
    lib  = get_lib()
    out  = ctypes.c_char_p(None)
    err  = ctypes.c_char_p(None)
    rc   = fn(*args, ctypes.byref(out), ctypes.byref(err))
    if rc != _FASTEN_OK:
        msg = err.value.decode("utf-8", errors="replace") if err.value else f"fasten error code {rc}"
        if err.value:
            lib.fasten_store_free_str(err)
        raise _rc_to_error(rc, msg)
    result = out.value.decode("utf-8") if out.value else ""
    if out.value:
        lib.fasten_store_free_str(out)
    return result


def _call_no_out(fn: Any, *args: Any) -> None:
    """Call an FFI function that returns only an error code + *out_err."""
    lib = get_lib()
    err = ctypes.c_char_p(None)
    rc  = fn(*args, ctypes.byref(err))
    if rc != _FASTEN_OK:
        msg = err.value.decode("utf-8", errors="replace") if err.value else f"fasten error code {rc}"
        if err.value:
            lib.fasten_store_free_str(err)
        raise _rc_to_error(rc, msg)


# Error code mapping (mirrors FastenErrorCode in error.rs)
_CATALOG_CODES = {6, 7, 8, 9}


def _rc_to_error(rc: int, msg: str) -> Exception:
    from .codes import AuditCatalogError
    if rc in _CATALOG_CODES:
        return AuditCatalogError(msg)
    return RuntimeError(msg)


# ── Public helpers ────────────────────────────────────────────────────────────

def redact_json(in_json: str) -> str:
    """Redact a JSON string using global default patterns."""
    lib = get_lib()
    return _call_out_str(lib.fasten_redact, in_json.encode())


def redact_json_full(
    in_json: str,
    extra_keys: Optional[list[str]] = None,
    replacement: Optional[str] = None,
    extra_value_patterns: Optional[list[tuple[str, str]]] = None,
) -> str:
    """Redact with custom key patterns, replacement, and value-shape patterns."""
    lib    = get_lib()
    ek_j   = json.dumps(extra_keys).encode() if extra_keys else None
    repl_b = replacement.encode() if replacement else None
    evp_j  = (
        json.dumps([{"pattern": p, "replacement": r} for (p, r) in extra_value_patterns]).encode()
        if extra_value_patterns else None
    )
    return _call_out_str(lib.fasten_redact_full, in_json.encode(), ek_j, repl_b, evp_j)


def register_codes(domain: str, codes_json: str) -> None:
    """Validate + register codes (JSON dict) into the global Rust registry."""
    lib = get_lib()
    _call_no_out(lib.fasten_register_codes, domain.encode(), codes_json.encode())


def meta_of_json(code: str) -> str:
    """Return the Meta JSON for `code`, or `"{}"` if not registered."""
    lib = get_lib()
    return _call_out_str(lib.fasten_meta_of, code.encode())


def registry_dump() -> str:
    """Return sorted `id,domain,severity` CSV (one line per code)."""
    lib = get_lib()
    return _call_out_str(lib.fasten_registry_dump)


def registry_clear() -> None:
    """Clear the global Rust registry (for tests / re-init)."""
    get_lib().fasten_registry_clear()


# ── Drainer C ABI ─────────────────────────────────────────────────────────────

# Callback type: fn(row_json: bytes, userdata: c_void_p) -> c_int32
InsertCallbackFn = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_char_p, ctypes.c_void_p)


def _configure_drainer(lib: ctypes.CDLL) -> None:
    vp = ctypes.c_void_p

    lib.fasten_store_from_callback.restype  = vp
    lib.fasten_store_from_callback.argtypes = [InsertCallbackFn, vp, ctypes.POINTER(ctypes.c_char_p)]

    lib.fasten_drainer_install.restype  = ctypes.c_int32
    lib.fasten_drainer_install.argtypes = [
        vp,                   # store handle
        ctypes.c_uint64,      # capacity
        ctypes.c_uint64,      # retry_initial_ms
        ctypes.c_uint64,      # retry_max_ms
        ctypes.c_int,         # retry_jitter
        ctypes.c_uint32,      # max_attempts
        ctypes.POINTER(ctypes.c_char_p),  # out_err
    ]

    lib.fasten_drainer_enqueue.restype  = ctypes.c_int32
    lib.fasten_drainer_enqueue.argtypes = [vp, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]

    lib.fasten_drainer_flush.restype  = ctypes.c_int32
    lib.fasten_drainer_flush.argtypes = [
        vp, ctypes.c_uint64, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_char_p),
    ]

    lib.fasten_drainer_stats_json.restype  = ctypes.c_int32
    lib.fasten_drainer_stats_json.argtypes = [vp, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]

    lib.fasten_drainer_close.restype  = None
    lib.fasten_drainer_close.argtypes = [vp]

    lib.fasten_store_close.restype  = None
    lib.fasten_store_close.argtypes = [vp]


# Lazily configure drainer bindings the first time they're needed.
_drainer_configured = False


def _ensure_drainer(lib: ctypes.CDLL) -> None:
    global _drainer_configured
    if not _drainer_configured:
        _configure_drainer(lib)
        _drainer_configured = True


def store_from_callback(cb: InsertCallbackFn) -> ctypes.c_void_p:
    """Create a FastenStore* backed by a Python insert callback."""
    lib = get_lib()
    _ensure_drainer(lib)
    err = ctypes.c_char_p(None)
    ptr = lib.fasten_store_from_callback(cb, None, ctypes.byref(err))
    if ptr is None:
        msg = err.value.decode("utf-8", errors="replace") if err.value else "unknown"
        raise RuntimeError(f"fasten_store_from_callback: {msg}")
    return ptr


def drainer_install(
    handle: ctypes.c_void_p,
    capacity: int,
    retry_initial_ms: int,
    retry_max_ms: int,
    retry_jitter: bool,
    max_attempts: int,
) -> None:
    lib = get_lib()
    _ensure_drainer(lib)
    err = ctypes.c_char_p(None)
    rc  = lib.fasten_drainer_install(
        handle, capacity, retry_initial_ms, retry_max_ms,
        int(retry_jitter), max_attempts, ctypes.byref(err),
    )
    if rc != 0:
        msg = err.value.decode("utf-8", errors="replace") if err.value else f"rc={rc}"
        raise RuntimeError(f"fasten_drainer_install: {msg}")


def drainer_enqueue(handle: ctypes.c_void_p, row_json: str) -> None:
    lib = get_lib()
    err = ctypes.c_char_p(None)
    rc  = lib.fasten_drainer_enqueue(handle, row_json.encode("utf-8"), ctypes.byref(err))
    if rc != 0:
        msg = err.value.decode("utf-8", errors="replace") if err.value else f"rc={rc}"
        if err.value:
            lib.fasten_store_free_str(err)
        raise RuntimeError(f"fasten_drainer_enqueue: {msg}")
    if err.value:
        lib.fasten_store_free_str(err)


def drainer_flush(handle: ctypes.c_void_p, timeout_ms: int) -> bool:
    lib = get_lib()
    drained = ctypes.c_int(0)
    err     = ctypes.c_char_p(None)
    lib.fasten_drainer_flush(handle, timeout_ms, ctypes.byref(drained), ctypes.byref(err))
    if err.value:
        lib.fasten_store_free_str(err)
    return bool(drained.value)


def drainer_stats_json(handle: ctypes.c_void_p) -> Optional[str]:
    lib  = get_lib()
    out  = ctypes.c_char_p(None)
    err  = ctypes.c_char_p(None)
    rc   = lib.fasten_drainer_stats_json(handle, ctypes.byref(out), ctypes.byref(err))
    if err.value:
        lib.fasten_store_free_str(err)
    if rc != 0 or out.value is None:
        return None
    result = out.value.decode("utf-8")
    lib.fasten_store_free_str(out)
    return result


def drainer_close(handle: ctypes.c_void_p) -> None:
    get_lib().fasten_drainer_close(handle)


def store_close(handle: ctypes.c_void_p) -> None:
    get_lib().fasten_store_close(handle)
