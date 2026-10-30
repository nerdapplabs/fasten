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
import { Engine, register as registerCodes } from '../src/index.js';

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
        timestamp: new Date().toISOString().replace(/Z$/, '000Z'),
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

function _daysAgo(n) {
    return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString().replace(/Z$/, '000Z');
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
    const oldTs = _daysAgo(31);
    const row = makeRow({ timestamp: oldTs });
    await store.insert(row);

    const before = await store.count({ requestId: row.request_id });
    assert.equal(before, 1);

    // Cutoff 30 days back: only this test's old row is before it, not the
    // shipped rows other tests leave in the shared table.
    const deleted = await store.purge({ before: _daysAgo(30), respectUnshipped: true });
    // Row is unshipped so it must NOT be deleted.
    assert.equal(deleted, 0, 'unshipped rows must not be purged');

    const after = await store.count({ requestId: row.request_id });
    assert.equal(after, 1);
});

// 6. purge shipped
test('purge deletes shipped rows older than cutoff', { skip }, async () => {
    const oldTs = _daysAgo(31);
    const row = makeRow({ timestamp: oldTs });
    await store.insert(row);
    await store.markShipped([row.id]);

    const deleted = await store.purge({ before: _daysAgo(30), respectUnshipped: true });
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

// ── #137: seq allocation, tenant filter, tables made by Python and Go ──────

const CANONICAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

async function _seqsOf(s, node) {
    const rows = await s.query({ sourceNodeId: node, limit: 100 });
    return rows.map(r => r.monotonicSeq).sort((a, b) => a - b);
}

test('a row with seq 0 gets the node\'s next seq', { skip }, async () => {
    const node = `alloc-${randomUUID().slice(0, 8)}`;
    for (let i = 0; i < 3; i++) {
        await store.insert(makeRow({ monotonic_seq: 0, source_node_id: node }));
    }
    assert.deepEqual(await _seqsOf(store, node), [1, 2, 3]);
});

test('concurrent inserts on one node get distinct seqs', { skip }, async () => {
    const node = `conc-${randomUUID().slice(0, 8)}`;
    await Promise.all(Array.from({ length: 10 }, () =>
        store.insert(makeRow({ monotonic_seq: 0, source_node_id: node }))));
    assert.deepEqual(await _seqsOf(store, node), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
});

test('query and count filter by tenantId', { skip }, async () => {
    const rid = randomUUID().replace(/-/g, '').slice(0, 12);
    await store.insert(makeRow({ request_id: rid, tenant_id: 'tenant-a' }));
    await store.insert(makeRow({ request_id: rid, tenant_id: 'tenant-b' }));
    const rows = await store.query({ requestId: rid, tenantId: 'tenant-a' });
    assert.deepEqual(rows.map(r => r.tenantId), ['tenant-a']);
    assert.equal(await store.count({ requestId: rid, tenantId: 'tenant-a' }), 1);
});

test('markShipped writes a canonical timestamp', { skip }, async () => {
    const row = makeRow();
    await store.insert(row);
    await store.markShipped([row.id]);
    const [got] = await store.query({ requestId: row.request_id });
    assert.match(got.shippedAt, CANONICAL);
});

// Shapes of the tables the Python and Go stores create.
const PY_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL,
    timestamp TEXT NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
    severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
    tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
    target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
    method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL,
    shipped_at TEXT, prev_hash TEXT NOT NULL DEFAULT 'genesis',
    hash TEXT NOT NULL DEFAULT '', canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt TEXT, detail_commitment TEXT)`;
const GO_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
    severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
    tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
    target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
    method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL,
    pii_in_detail SMALLINT NOT NULL DEFAULT 0, shipped_at TIMESTAMPTZ,
    wire_version TEXT NOT NULL DEFAULT '1', hash TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '', canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt TEXT NOT NULL DEFAULT '', detail_commitment TEXT NOT NULL DEFAULT '');
    CREATE UNIQUE INDEX uq_${t}_node_seq ON ${t}(source_node_id, monotonic_seq)`;

for (const [name, ddl] of [['Python', PY_DDL], ['Go', GO_DDL]]) {
    test(`writes into a table the ${name} store created`, { skip }, async () => {
        const { default: pg } = await import('pg');
        const admin = new pg.Pool({ connectionString: DSN });
        const t = `t_${name.toLowerCase()}_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
        const s = new PostgresStore(DSN, { table: t });
        try {
            await admin.query(ddl(t));
            const node = 'node-shared';
            const first = makeRow({ monotonic_seq: 0, source_node_id: node, pii_in_detail: true });
            await s.insert(first);
            await s.insert(makeRow({ monotonic_seq: 0, source_node_id: node }));
            assert.deepEqual(await _seqsOf(s, node), [1, 2]);

            const raw = await admin.query(
                `SELECT prev_hash, hash FROM ${t} WHERE id = $1`, [first.id]);
            assert.deepEqual(raw.rows[0], { prev_hash: '', hash: '' });

            await s.markShipped([first.id]);
            const [got] = await s.query({ requestId: first.request_id });
            assert.match(got.timestamp, CANONICAL);
            assert.match(got.shippedAt, CANONICAL);
            assert.equal(got.piiInDetail, true);
        } finally {
            await s.close().catch(() => {});
            await admin.query(`DROP TABLE IF EXISTS ${t}`);
            await admin.end();
        }
    });
}

// The Python store reads SELECT * by position, and the Go store scans
// detail_salt / detail_commitment into strings, so a table the JS store
// creates must have Python's column order and no NULLs in those two.
test('a table the JS store creates can be read by Python and Go', { skip }, async () => {
    const { default: pg } = await import('pg');
    const admin = new pg.Pool({ connectionString: DSN });
    try {
        const row = makeRow({ monotonic_seq: 0 });
        await store.insert(row);
        const cols = await admin.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_name = $1 ORDER BY ordinal_position`, [TABLE]);
        assert.deepEqual(cols.rows.map(r => r.column_name), [
            'id', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action',
            'severity', 'service_id', 'source_node_id', 'tenant_id', 'actor',
            'actor_kind', 'target', 'category', 'domain', 'method', 'request_id',
            'detail', 'shipped_at', 'prev_hash', 'hash', 'canonical_form_id',
            'detail_salt', 'detail_commitment', 'pii_in_detail',
        ]);
        const raw = await admin.query(
            `SELECT detail_salt, detail_commitment FROM ${TABLE} WHERE id = $1`, [row.id]);
        assert.deepEqual(raw.rows[0], { detail_salt: '', detail_commitment: '' });
    } finally {
        await admin.end();
    }
});

// ── #124: two engines on one node (#92) and PII redaction (#90) ────────────

registerCodes('t124', {
    T124_EVENT: { domain: 't124', action: 'do', severity: 'info', retentionClass: 'long' },
    T124_PII: {
        domain: 't124', action: 'do', severity: 'info',
        piiInDetail: true, detailPassthroughKeys: ['email'],
    },
    T124_PLAIN: { domain: 't124', action: 'do', severity: 'info', retentionClass: 'long' },
});

async function _withTable(fn) {
    const { default: pg } = await import('pg');
    const admin = new pg.Pool({ connectionString: DSN });
    const t = `t124_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
    const stores = [];
    const mk = () => { const s = new PostgresStore(DSN, { table: t }); stores.push(s); return s; };
    try {
        await fn({ admin, t, mk });
    } finally {
        for (const s of stores) await s.close().catch(() => {});
        await admin.query(`DROP TABLE IF EXISTS ${t}`);
        await admin.end();
    }
}

test('two engines on one node get seqs 1..N with no chain fields (#92)', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const engines = [new Engine(), new Engine()];
        engines.forEach((e) => e.init({ serviceId: 'svc', nodeId: 'node-92', auditStore: mk() }));
        try {
            for (let i = 0; i < 20; i++) {
                engines[i % 2].emit({ code: 'T124_EVENT', target: `x-${i}` });
            }
            for (const e of engines) assert.equal(await e.flush(10_000), true);
            const r = await admin.query(
                `SELECT monotonic_seq, prev_hash, hash FROM ${t} WHERE source_node_id = 'node-92' ORDER BY monotonic_seq`);
            assert.deepEqual(r.rows.map((x) => Number(x.monotonic_seq)),
                Array.from({ length: 20 }, (_, i) => i + 1));
            for (const x of r.rows) assert.deepEqual([x.prev_hash, x.hash], ['', '']);
        } finally {
            engines.forEach((e) => e.resetForTests());
        }
    });
});

test('redactExpired clears old PII rows and records each one (#90)', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const e = new Engine();
        e.init({ serviceId: 'svc', nodeId: 'node-90', auditStore: s, auditStoreFailureStrategy: 'raise' });
        try {
            const old = _daysAgo(40);
            const pii = makeRow({ monotonic_seq: 0, source_node_id: 'node-90', code: 'T124_PII', timestamp: old, pii_in_detail: true, detail: { email: 'a@b.com' } });
            const plain = makeRow({ monotonic_seq: 0, source_node_id: 'node-90', code: 'T124_PLAIN', timestamp: old });
            const fresh = makeRow({ monotonic_seq: 0, source_node_id: 'node-90', code: 'T124_PII', pii_in_detail: true });
            for (const r of [pii, plain, fresh]) await s.insert(r);
            // A form-"1" row sealed by another SDK: its detail is hashed, so it stays.
            const sealed = makeRow({ monotonic_seq: 99, source_node_id: 'node-90', code: 'T124_PII', timestamp: old });
            await s.insert(sealed);
            await admin.query(`UPDATE ${t} SET hash = 'abc', prev_hash = 'genesis' WHERE id = $1`, [sealed.id]);

            const cutoff = new Date(Date.now() - 30 * 86_400_000);
            assert.deepEqual(await e.redactExpired({ before: cutoff }), [pii.id]);

            const byId = async (id) => (await admin.query(
                `SELECT detail, detail_salt, hash FROM ${t} WHERE id = $1`, [id])).rows[0];
            assert.deepEqual(await byId(pii.id), { detail: 'null', detail_salt: '', hash: '' });
            assert.equal(JSON.parse((await byId(plain.id)).detail).email, 'a@b.com');
            assert.notEqual((await byId(fresh.id)).detail, 'null');
            assert.notEqual((await byId(sealed.id)).detail, 'null');

            const rec = await admin.query(
                `SELECT target, detail, monotonic_seq FROM ${t} WHERE code = 'AUDIT_ROW_REDACTED'`);
            assert.equal(rec.rows.length, 1);
            assert.equal(rec.rows[0].target, pii.id);
            const [{ monotonic_seq: piiSeq }] = (await admin.query(
                `SELECT monotonic_seq FROM ${t} WHERE id = $1`, [pii.id])).rows;
            assert.deepEqual(JSON.parse(rec.rows[0].detail),
                { redacted_seq: Number(piiSeq), reason: 'retention', redacted_id: pii.id });
            assert.equal(await s.count(), 5);

            // Idempotent: nothing left to redact, no second record.
            assert.deepEqual(await e.redactExpired({ before: cutoff }), []);
            assert.equal(await s.count({ code: 'AUDIT_ROW_REDACTED' }), 1);
            assert.deepEqual(await s.redactRows({ ids: [pii.id, sealed.id] }), [pii.id]);
        } finally {
            e.resetForTests();
        }
    });
});

test('redactRows writes an empty salt on a table the Go store created', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        await admin.query(GO_DDL(t));
        const s = mk();
        const row = makeRow({ monotonic_seq: 0, code: 'T124_PII' });
        await s.insert(row);
        assert.deepEqual(await s.redactRows({ ids: [row.id] }), [row.id]);
        const r = await admin.query(`SELECT detail, detail_salt FROM ${t} WHERE id = $1`, [row.id]);
        assert.deepEqual(r.rows[0], { detail: 'null', detail_salt: '' });
    });
});

test('retentionPii runs the redaction on init', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const row = makeRow({ monotonic_seq: 0, code: 'T124_PII', timestamp: _daysAgo(40) });
        await s.insert(row);
        const e = new Engine();
        e.init({ serviceId: 'svc', nodeId: 'node-r', auditStore: s, retentionPii: '30d' });
        try {
            let detail;
            for (let i = 0; i < 100 && detail !== 'null'; i++) {
                await new Promise((r) => setTimeout(r, 50));
                detail = (await admin.query(`SELECT detail FROM ${t} WHERE id = $1`, [row.id])).rows[0].detail;
            }
            assert.equal(detail, 'null');
            assert.equal(await s.count({ code: 'AUDIT_ROW_REDACTED' }), 1);
        } finally {
            e.resetForTests();
        }
    });
});
