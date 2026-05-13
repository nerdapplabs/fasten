/**
 * fasten_store_core — Node.js binding for libfasten_store_core.
 *
 * Uses ffi-napi (maintained fork of node-ffi, supports Node 16+).
 *
 *   npm install ffi-napi ref-napi
 *
 * Build lib:  cd fasten/store-core && cargo build --release --features all
 *
 * Usage:
 *   import { FastenStore } from './fasten_store_core.mjs';
 *   const store = FastenStore.open('sqlite', ':memory:');
 *   store.insert({ id: 'evt-001', ... });
 *   store.ping();
 *   store.close();
 */

import { createRequire } from 'module';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import os from 'os';

const require = createRequire(import.meta.url);
const ffi     = require('ffi-napi');
const ref     = require('ref-napi');

// ── Library location ─────────────────────────────────────────────────────────

function libName() {
  switch (os.platform()) {
    case 'darwin':  return 'libfasten_store_core.dylib';
    case 'win32':   return 'fasten_store_core.dll';
    default:        return 'libfasten_store_core.so';
  }
}

function findLib() {
  const env = process.env.FASTEN_STORE_CORE_LIB;
  if (env) return env;

  const dir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(dir, libName()),
    resolve(dir, '..', '..', '..', 'target', 'release', libName()),
    resolve(dir, '..', '..', '..', 'target', 'debug',   libName()),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  throw new Error(
    `Cannot find ${libName()}. Set FASTEN_STORE_CORE_LIB or ` +
    `run: cargo build --release --features all`
  );
}

// ── FFI bindings ─────────────────────────────────────────────────────────────

const VoidPtr   = ref.refType(ref.types.void);
const StringPtr = ref.refType('string');

const lib = ffi.Library(findLib(), {
  fasten_store_open:     [VoidPtr,   ['string', 'string', 'string', StringPtr]],
  fasten_store_insert:   ['int',     [VoidPtr,  'string', StringPtr]],
  fasten_store_ping:     ['int',     [VoidPtr,  StringPtr]],
  fasten_store_close:    ['void',    [VoidPtr]],
  fasten_store_free_str: ['void',    ['pointer']],
  fasten_store_version:  ['string',  []],
});

// ── Helper ───────────────────────────────────────────────────────────────────

function takeError(outErrBuf) {
  const ptr = outErrBuf.deref();
  if (ptr.isNull()) return '(no detail)';
  const msg = ptr.readCString();
  lib.fasten_store_free_str(ptr);
  return msg;
}

// ── Public API ────────────────────────────────────────────────────────────────

export class FastenStoreError extends Error {
  constructor(msg) { super(msg); this.name = 'FastenStoreError'; }
}

export class FastenStore {
  constructor(_handle) { this._handle = _handle; }

  /**
   * Open an audit store.
   * @param {'sqlite'|'postgres'} backend
   * @param {string} connstr  SQLite path / ':memory:' or PostgreSQL DSN
   * @param {string} [table='audit_log']
   */
  static open(backend, connstr, table = 'audit_log') {
    const outErr = ref.alloc(StringPtr, ref.NULL);
    const handle = lib.fasten_store_open(backend, connstr, table, outErr);
    if (handle.isNull()) {
      throw new FastenStoreError(takeError(outErr));
    }
    return new FastenStore(handle);
  }

  /** Insert one audit row (plain JS object or pre-serialised JSON string). */
  insert(row) {
    const json    = typeof row === 'string' ? row : JSON.stringify(row);
    const outErr  = ref.alloc(StringPtr, ref.NULL);
    const rc      = lib.fasten_store_insert(this._handle, json, outErr);
    if (rc !== 0) throw new FastenStoreError(takeError(outErr));
  }

  /** Throw FastenStoreError if the backend is unreachable. */
  ping() {
    const outErr = ref.alloc(StringPtr, ref.NULL);
    const rc = lib.fasten_store_ping(this._handle, outErr);
    if (rc !== 0) throw new FastenStoreError(takeError(outErr));
  }

  /** Release all resources. The store is unusable after this call. */
  close() {
    if (this._handle && !this._handle.isNull()) {
      lib.fasten_store_close(this._handle);
      this._handle = ref.NULL;
    }
  }

  /** Library version string. */
  static version() { return lib.fasten_store_version(); }

  // Support `using store = FastenStore.open(...)` (TC39 explicit resource mgmt)
  [Symbol.dispose]() { this.close(); }
}
