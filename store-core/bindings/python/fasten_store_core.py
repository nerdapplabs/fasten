"""
fasten_store_core — Python binding for libfasten_store_core.

Uses cffi (ABI mode) so no compilation step is needed; the shared library
is loaded at import time. cffi is a pure-Python package available on all
CPython / PyPy versions ≥ 3.8.

Install:  pip install cffi
Build lib: cd fasten/store-core && cargo build --release --features all

Usage:
    from fasten_store_core import FastenStore
    store = FastenStore.open("sqlite", "audit.db", "audit_log")
    store.insert(row_dict)   # row_dict matches the fasten JSON wire schema
    store.ping()
    store.close()
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import cffi

# ── Library location ──────────────────────────────────────────────────────────

def _lib_name() -> str:
    system = platform.system()
    if system == "Darwin":
        return "libfasten_store_core.dylib"
    if system == "Windows":
        return "fasten_store_core.dll"
    return "libfasten_store_core.so"


def _find_lib() -> str:
    """Search standard locations; raise ImportError if not found."""
    # 1. Explicit override from env
    env = os.environ.get("FASTEN_STORE_CORE_LIB")
    if env:
        return env

    # 2. Alongside this file (pip-installed wheel layout)
    candidates = [
        Path(__file__).parent / _lib_name(),
        # 3. Cargo release build (dev / CI)
        Path(__file__).parents[3] / "target" / "release" / _lib_name(),
        Path(__file__).parents[3] / "target" / "debug" / _lib_name(),
    ]
    for p in candidates:
        if p.exists():
            return str(p)

    raise ImportError(
        f"Cannot find {_lib_name()}. "
        "Set FASTEN_STORE_CORE_LIB to the full path, or build with "
        "`cargo build --release --features all` inside fasten/store-core/."
    )


# ── FFI declarations ──────────────────────────────────────────────────────────

_ffi = cffi.FFI()
_ffi.cdef("""
    typedef struct FastenStore FastenStore;

    FastenStore* fasten_store_open(
        const char* backend,
        const char* connstr,
        const char* table,
        char**      out_err
    );
    int  fasten_store_insert(FastenStore* store, const char* row_json, char** out_err);
    int  fasten_store_ping  (FastenStore* store, char** out_err);
    void fasten_store_close (FastenStore* store);
    void fasten_store_free_str(char* s);
    const char* fasten_store_version(void);
""")

_lib = _ffi.dlopen(_find_lib())


# ── Helper: read + free an error string ──────────────────────────────────────

def _take_error(out_err_p) -> str:
    """Read the error string from *out_err_p and free it."""
    raw = out_err_p[0]
    if raw == _ffi.NULL:
        return "(no detail)"
    msg = _ffi.string(raw).decode("utf-8", errors="replace")
    _lib.fasten_store_free_str(raw)
    out_err_p[0] = _ffi.NULL
    return msg


# ── Public API ────────────────────────────────────────────────────────────────

class FastenStoreError(RuntimeError):
    """Raised when the store backend returns an error."""


class FastenStore:
    """Thread-safe audit store.  Use as a context manager or call close()."""

    def __init__(self, _handle) -> None:
        self._handle = _handle

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def open(
        cls,
        backend: str,
        connstr: str,
        table: str = "audit_log",
    ) -> "FastenStore":
        """Open an audit store.

        Parameters
        ----------
        backend : ``"sqlite"`` or ``"postgres"``
        connstr : SQLite path / ``:memory:`` or PostgreSQL DSN
        table   : plain or schema-qualified table name
        """
        out_err_p = _ffi.new("char*[1]", [_ffi.NULL])
        handle = _lib.fasten_store_open(
            backend.encode(),
            connstr.encode(),
            table.encode(),
            out_err_p,
        )
        if handle == _ffi.NULL:
            raise FastenStoreError(_take_error(out_err_p))
        return cls(handle)

    # ── Write path ────────────────────────────────────────────────────────────

    def insert(self, row: dict[str, Any]) -> None:
        """Insert one audit row (dict matching the fasten wire schema)."""
        row_json = json.dumps(row, separators=(",", ":")).encode()
        out_err_p = _ffi.new("char*[1]", [_ffi.NULL])
        rc = _lib.fasten_store_insert(self._handle, row_json, out_err_p)
        if rc != 0:
            raise FastenStoreError(_take_error(out_err_p))

    def insert_json(self, row_json: str) -> None:
        """Insert from a pre-serialised JSON string."""
        out_err_p = _ffi.new("char*[1]", [_ffi.NULL])
        rc = _lib.fasten_store_insert(
            self._handle, row_json.encode(), out_err_p
        )
        if rc != 0:
            raise FastenStoreError(_take_error(out_err_p))

    # ── Health ────────────────────────────────────────────────────────────────

    def ping(self) -> None:
        """Raise FastenStoreError if the backend is unreachable."""
        out_err_p = _ffi.new("char*[1]", [_ffi.NULL])
        rc = _lib.fasten_store_ping(self._handle, out_err_p)
        if rc != 0:
            raise FastenStoreError(_take_error(out_err_p))

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release all resources. The store is unusable after this call."""
        if self._handle != _ffi.NULL:
            _lib.fasten_store_close(self._handle)
            self._handle = _ffi.NULL

    def __enter__(self) -> "FastenStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    # ── Metadata ──────────────────────────────────────────────────────────────

    @staticmethod
    def version() -> str:
        """Return the library version string."""
        return _ffi.string(_lib.fasten_store_version()).decode()
