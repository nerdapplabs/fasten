/**
 * Integration tests for PostgresStore.
 *
 * Set FASTEN_TEST_POSTGRES_DSN to run against a real Postgres instance:
 *
 *   FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test \
 *     node --test test/store_postgres.test.mjs
 *
 * All tests are skipped when the env-var is absent.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PostgresStore } from '../src/store/postgres.js';

const DSN = process.env.FASTEN_TEST_POSTGRES_DSN;
const skip = !DSN;

// One unique table for the entire test run — dropped in `after`.
const TABLE = `t_${randomUUID().replace(/-/g, '').slice(0, 12)}`;

let store = skip ? null : new PostgresStore(DSN, { table: TABLE });

// ── Helpers ────────────────────────────────────────────────────────────────

function _id() {
    return `evt-${randomUUID().replace(/-/g, '').slice(0, 20)}`;
}

let _seq = 0;
function makeRow(overrides = {}) {
    _seq++;
    return {
        id: _id(),
        origin_id: _id(),
        monotonic_seq: _seq,
        timestamp: new Date().toISOString(),
        code: 'USER_CREATED',
        action: 'create',
        severity: 'info',
        service_id: 'svc',
        source_node_id: 'node-1',
        tenant_id: null,
        actor: 'system',
        actor_kind: 'service',
        target: 'u-1',
        category: 'account',
        domain: 'user',
        method: 'sdk',
        request_id: randomUUID().replace(/-/g, '').slice(0, 12),
        detail: { email: 'a@b.com' },
        pii_in_detail: false,
        shipped_at: null,
        ...overrides,
    };
}

// ── Cleanup ────────────────────────────────────────────────────────────────

after(async () => {
    if (skip || !store) return;
    // Drop the shared table then close the pool.
    // Use a fresh pool because store._pool may be ended by close().
    const { default: pg } = await import('pg');
    const { Pool } = pg;
    const cleanup = new Pool({ connectionString: DSN });
    await cleanup.query(`DROP TABLE IF EXISTS ${TABLE}`);
    await cleanup.end();
    await store.close();
});

// ── Tests ──────────────────────────────────────────────────────────────────

// 1. insert + query by requestId
test('insert and query by requestId', { skip }, async () => {
    const rid = randomUUID().replace(/-/g, '').slice(0, 12);
    const row = makeRow({ request_id: rid });
    await store.insert(row);
    const results = await store.query({ requestId: rid });
    assert.equal(results.length, 1);
    assert.equal(results[0].id, row.id);
    assert.equal(results[0].code, 'USER_CREATED');
});

// 2. insert idempotent (ON CONFLICT DO NOTHING)
test('insert is idempotent — ON CONFLICT DO NOTHING', { skip }, async () => {
    const row = makeRow();
    await store.insert(row);
    await store.insert(row);
    const n = await store.count({ requestId: row.request_id });
    assert.equal(n, 1);
});

// 3. listUnshipped
test('listUnshipped returns rows with no shipped_at', { skip }, async () => {
    const row = makeRow();
    await store.insert(row);
    const unshipped = await store.listUnshipped(100);
    const ids = unshipped.map((r) => r.id);
    assert.ok(ids.includes(row.id), `expected ${row.id} in unshipped list`);
    for (const r of unshipped) {
        assert.equal(r.shippedAt, null, `row ${r.id} should have shippedAt=null`);
    }
});

// 4. markShipped removes from unshipped
test('markShipped removes row from listUnshipped', { skip }, async () => {
    const row = makeRow();
    await store.insert(row);

    // Confirm it starts unshipped.
    const before = await store.listUnshipped(500);
    assert.ok(before.some((r) => r.id === row.id));

    await store.markShipped([row.id]);

    const after = await store.listUnshipped(500);
    assert.ok(!after.some((r) => r.id === row.id),
        `${row.id} should no longer be in unshipped list`);

    // shipped_at should now be set.
    const [back] = await store.query({ requestId: row.request_id });
    assert.ok(back.shippedAt !== null, 'shippedAt should be set after markShipped');
});

// 5. purge respects unshipped
test('purge respects unshipped rows', { skip }, async () => {
    // Insert a row with an old timestamp but leave it unshipped.
    const oldTs = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    const row = makeRow({ timestamp: oldTs });
    await store.insert(row);

    const before = await store.count({ requestId: row.request_id });
    assert.equal(before, 1);

    const deleted = await store.purge({ before: new Date().toISOString(), respectUnshipped: true });
    // Row is unshipped so it must NOT be deleted.
    assert.equal(deleted, 0, 'unshipped rows must not be purged');

    const after = await store.count({ requestId: row.request_id });
    assert.equal(after, 1);
});

// 6. purge shipped
test('purge deletes shipped rows older than cutoff', { skip }, async () => {
    const oldTs = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    const row = makeRow({ timestamp: oldTs });
    await store.insert(row);
    await store.markShipped([row.id]);

    const deleted = await store.purge({ before: new Date().toISOString(), respectUnshipped: true });
    assert.ok(deleted >= 1, `expected at least 1 deleted row; got ${deleted}`);

    const remaining = await store.count({ requestId: row.request_id });
    assert.equal(remaining, 0);
});

// 7. count filtered
test('count filtered by code', { skip }, async () => {
    const rid = randomUUID().replace(/-/g, '').slice(0, 12);
    await store.insert(makeRow({ code: 'USER_CREATED', request_id: rid }));
    await store.insert(makeRow({ code: 'USER_CREATED', request_id: rid }));
    await store.insert(makeRow({ code: 'USER_DELETED', request_id: rid }));

    const total = await store.count({ requestId: rid });
    assert.equal(total, 3);

    const created = await store.count({ requestId: rid, code: 'USER_CREATED' });
    assert.equal(created, 2);

    const deleted = await store.count({ requestId: rid, code: 'USER_DELETED' });
    assert.equal(deleted, 1);
});

// 8. round-trip detail JSON
test('round-trip detail JSON', { skip }, async () => {
    const detail = { nested: { k: [1, 2, 3] }, flag: true, n: null };
    const row = makeRow({ detail });
    await store.insert(row);
    const [back] = await store.query({ requestId: row.request_id });
    assert.deepEqual(back.detail, detail);
});

// 9. piiInDetail round-trips
test('piiInDetail round-trips as boolean', { skip }, async () => {
    const row = makeRow({ pii_in_detail: true });
    await store.insert(row);
    const [back] = await store.query({ requestId: row.request_id });
    assert.equal(back.piiInDetail, true);
});

// 10. schema-qualified table
test('schema-qualified table (fasten.<TABLE>)', { skip }, async () => {
    const schemaTable = `fasten.${TABLE}_sq`;
    const schemaStore = new PostgresStore(DSN, { table: schemaTable });

    try {
        const row = makeRow();
        await schemaStore.insert(row);

        const count = await schemaStore.count();
        assert.equal(count, 1);

        const [back] = await schemaStore.query({ requestId: row.request_id });
        assert.equal(back.id, row.id);
    } finally {
        // Cleanup: drop table + schema.
        const { default: pg } = await import('pg');
        const { Pool } = pg;
        const cleanup = new Pool({ connectionString: DSN });
        await cleanup.query(`DROP TABLE IF EXISTS ${schemaTable}`);
        await cleanup.query('DROP SCHEMA IF EXISTS fasten CASCADE');
        await cleanup.end();
        await schemaStore.close();
    }
});
