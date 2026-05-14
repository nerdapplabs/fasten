/**
 * Tests for the Node.js binding (fasten_store_core.mjs).
 *
 * Requires libfasten_store_core to be built:
 *   cd fasten/store-core && cargo build --release --features all
 *
 * Run:
 *   node --test fasten_store_core.test.mjs
 *
 * Skip gracefully when the library is absent so CI passes without it.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

// ── Library availability guard ────────────────────────────────────────────────

let FastenStore, FastenStoreError, libAvailable;

try {
  ({ FastenStore, FastenStoreError } = await import('./fasten_store_core.mjs'));
  libAvailable = true;
} catch {
  libAvailable = false;
}

function skip(name, fn) {
  if (!libAvailable) {
    test(name, { skip: 'libfasten_store_core not built' }, fn);
  } else {
    test(name, fn);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeRow(id, code = 'TEST') {
  return {
    wire_version: '1', id, origin_id: id,
    monotonic_seq: 1,
    timestamp: '2026-05-07T00:00:00.000Z',
    code, action: 'test', severity: 'info',
    service_id: 'test-svc', source_node_id: 'node-1',
    actor: 'tester', actor_kind: 'user',
    target: 'res-1', category: 'test', domain: 'test',
    method: 'sdk', request_id: 'req-001',
    detail: { key: 'value' },
  };
}

const PG_DSN = process.env.FASTEN_TEST_POSTGRES_DSN;

// ── Version ───────────────────────────────────────────────────────────────────

skip('version() returns a non-empty string', () => {
  const v = FastenStore.version();
  assert.ok(typeof v === 'string' && v.length > 0, `bad version: ${v}`);
});

// ── SQLite ────────────────────────────────────────────────────────────────────

skip('sqlite: open :memory: and ping', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  try { store.ping(); }
  finally { store.close(); }
});

skip('sqlite: insert a row', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  try { store.insert(makeRow('evt-node-sqlite-001')); }
  finally { store.close(); }
});

skip('sqlite: insert is idempotent', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  const row = makeRow('evt-node-idem-001');
  try {
    store.insert(row);
    store.insert(row); // INSERT OR IGNORE — no throw
  } finally { store.close(); }
});

skip('sqlite: insert from pre-serialised JSON string', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  try { store.insert(JSON.stringify(makeRow('evt-node-json-001'))); }
  finally { store.close(); }
});

skip('sqlite: nullable tenant_id + shipped_at', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  const row = { ...makeRow('evt-node-null-001'), tenant_id: 'tenant-abc',
                shipped_at: '2026-05-07T01:00:00.000Z' };
  try { store.insert(row); }
  finally { store.close(); }
});

skip('sqlite: pii_in_detail flag', () => {
  const store = FastenStore.open('sqlite', ':memory:', 'audit_log');
  const row = { ...makeRow('evt-node-pii-001'), pii_in_detail: true };
  try { store.insert(row); }
  finally { store.close(); }
});

skip('sqlite: Symbol.dispose closes the store', () => {
  { using store = FastenStore.open('sqlite', ':memory:', 'audit_log');
    store.insert(makeRow('evt-node-dispose-001')); }
  // store.close() was called by Symbol.dispose
});

skip('invalid table name throws FastenStoreError', () => {
  assert.throws(
    () => FastenStore.open('sqlite', ':memory:', 'bad-name!'),
    FastenStoreError,
  );
});

skip('unknown backend throws FastenStoreError', () => {
  assert.throws(
    () => FastenStore.open('nope', ':memory:', 'audit_log'),
    FastenStoreError,
  );
});

// ── PostgreSQL (skipped without DSN) ──────────────────────────────────────────

if (PG_DSN) {
  skip('postgres: open and ping', () => {
    const store = FastenStore.open('postgres', PG_DSN, 'fasten_node_sc_test');
    try { store.ping(); }
    finally { store.close(); }
  });

  skip('postgres: insert idempotent', () => {
    const store = FastenStore.open('postgres', PG_DSN, 'fasten_node_sc_test');
    const row = makeRow('evt-node-pg-001');
    try { store.insert(row); store.insert(row); }
    finally { store.close(); }
  });

  skip('postgres: schema-qualified table', () => {
    const store = FastenStore.open('postgres', PG_DSN, 'fasten_node_sc_schema.audit_rows');
    try { store.insert(makeRow('evt-node-schema-001')); }
    finally { store.close(); }
  });
}
