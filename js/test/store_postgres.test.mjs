/**
 * Integration tests for PostgresStore.
 *
 * Set FASTEN_TEST_POSTGRES_DSN to run against a real Postgres instance:
 *
 *   FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test \
 *     node --test test/store_postgres.test.mjs
 *
 * All tests are skipped when the env-var is absent, unless
 * FASTEN_REQUIRE_POSTGRES=1 says they must run.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PostgresStore } from '../src/store/postgres.js';
import {
    AuditOutcomeUnknownError, AuditRowRejectedError, AuditStoreError, ChainError, Engine,
    register as registerCodes, takeCheckpoints, verifyChain,
} from '../src/index.js';
import { canonicalJSON, detailCommitment, detailText, parseJson } from '../src/chain.js';

const DSN = process.env.FASTEN_TEST_POSTGRES_DSN;
const skip = !DSN;

test('Postgres is configured when it is required', () => {
    assert.ok(!skip || process.env.FASTEN_REQUIRE_POSTGRES !== '1',
        'FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set');
});

// One table for the whole run, dropped in `after`.
const TABLE = `t_${randomUUID().replace(/-/g, '').slice(0, 12)}`;

let store = skip ? null : new PostgresStore(DSN, { table: TABLE });

// Helpers

function _id() {
    return `evt-${randomUUID().replace(/-/g, '').slice(0, 20)}`;
}

let _seq = 0;
function makeRow(overrides = {}) {
    _seq++;
    const id = _id();
    return {
        id,
        origin_id: id,
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

// Cleanup

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

// Tests

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
test('insert ignores a duplicate id', { skip }, async () => {
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
        assert.equal(r.shipped_at, null, `row ${r.id} should have shipped_at=null`);
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
    assert.ok(back.shipped_at !== null, 'shipped_at should be set after markShipped');
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
    // Its own node: an older unshipped row on node-1 keeps the rows above it.
    const oldTs = _daysAgo(31);
    const row = makeRow({ timestamp: oldTs, source_node_id: `node-${randomUUID()}`, monotonic_seq: 1 });
    await store.insert(row);
    await store.markShipped([row.id]);

    const deleted = await store.purge({ before: _daysAgo(30), respectUnshipped: true });
    assert.ok(deleted >= 1, `expected at least 1 deleted row; got ${deleted}`);

    const remaining = await store.count({ requestId: row.request_id });
    assert.equal(remaining, 0);
});

// 6b. purge keeps a seq suffix per node (spec §2.3)
test('purge deletes only a seq prefix of each node', { skip }, async () => {
    // Seq 2 is newer than the cutoff and seq 3 older: a timestamp-only
    // delete takes 3 and keeps 2 and 4, and the chain breaks at 4.
    const node = `node-${randomUUID()}`;
    for (const [seq, days] of [[1, 40], [2, 20], [3, 35], [4, 10]]) {
        await store.insert(makeRow({ source_node_id: node, monotonic_seq: seq, timestamp: _daysAgo(days) }));
    }
    await store.purge({ before: _daysAgo(30), respectUnshipped: false });
    const left = await store.query({ sourceNodeId: node });
    assert.deepEqual(left.map((r) => r.monotonic_seq).sort((a, b) => a - b), [2, 3, 4]);
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

// 9. pii_in_detail round-trips
test('pii_in_detail round-trips as boolean', { skip }, async () => {
    const row = makeRow({ pii_in_detail: true });
    await store.insert(row);
    const [back] = await store.query({ requestId: row.request_id });
    assert.equal(back.pii_in_detail, true);
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
    return rows.map(r => r.monotonic_seq).sort((a, b) => a - b);
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
    const res = verifyChain(await store.chainRows(node));
    assert.ok(res.ok, res.reason);
    assert.equal(res.sealedRows, 10);
});

test('query and count filter by tenantId', { skip }, async () => {
    const rid = randomUUID().replace(/-/g, '').slice(0, 12);
    await store.insert(makeRow({ request_id: rid, tenant_id: 'tenant-a' }));
    await store.insert(makeRow({ request_id: rid, tenant_id: 'tenant-b' }));
    const rows = await store.query({ requestId: rid, tenantId: 'tenant-a' });
    assert.deepEqual(rows.map(r => r.tenant_id), ['tenant-a']);
    assert.equal(await store.count({ requestId: rid, tenantId: 'tenant-a' }), 1);
});

test('markShipped writes a canonical timestamp', { skip }, async () => {
    const row = makeRow();
    await store.insert(row);
    await store.markShipped([row.id]);
    const [got] = await store.query({ requestId: row.request_id });
    assert.match(got.shipped_at, CANONICAL);
});

const CHAIN_COLUMNS = ['id', 'wire_version', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action',
    'severity', 'service_id', 'source_node_id', 'tenant_id', 'actor', 'actor_kind', 'target', 'category',
    'domain', 'method', 'request_id', 'detail', 'shipped_at', 'canonical_form_id', 'prev_hash', 'hash',
    'detail_salt', 'detail_commitment', 'pii_in_detail'];

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
                `SELECT prev_hash, hash, canonical_form_id FROM ${t} WHERE id = $1`, [first.id]);
            assert.equal(raw.rows[0].prev_hash, 'genesis');
            assert.match(raw.rows[0].hash, /^[0-9a-f]{64}$/);
            assert.equal(raw.rows[0].canonical_form_id, '2');
            const res = verifyChain(await s.chainRows(node));
            assert.ok(res.ok, res.reason);
            assert.equal(res.sealedRows, 2);

            // Every column the store reads exists, added where the table lacked it.
            const cols = (await admin.query(
                'SELECT column_name FROM information_schema.columns WHERE table_name = $1', [t])).rows.map((r) => r.column_name);
            for (const c of CHAIN_COLUMNS) assert.ok(cols.includes(c), `${name} table lacks ${c}`);

            await s.markShipped([first.id]);
            const [got] = await s.query({ requestId: first.request_id });
            assert.match(got.timestamp, CANONICAL);
            assert.match(got.shipped_at, CANONICAL);
            assert.equal(got.pii_in_detail, true);
            // shipped_at is hashed as null, so marking a row shipped keeps the chain.
            assert.ok(verifyChain(await s.chainRows(node)).ok);
        } finally {
            await s.close().catch(() => {});
            await admin.query(`DROP TABLE IF EXISTS ${t}`);
            await admin.end();
        }
    });
}

// The Go store scans detail_salt / detail_commitment into strings, so a
// table the JS store creates must have no NULLs in those two; its columns
// are in the order of the Python and Rust stores' tables.
test('a table the JS store creates can be read by Python and Go', { skip }, async () => {
    const { default: pg } = await import('pg');
    const admin = new pg.Pool({ connectionString: DSN });
    try {
        const row = makeRow({ monotonic_seq: 0 });
        const sealed = await store.insert(row);
        const unsealed = makeRow({ source_node_id: `own-seq-${randomUUID()}` });
        await store.insert(unsealed);
        const cols = await admin.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_name = $1 ORDER BY ordinal_position`, [TABLE]);
        assert.deepEqual(cols.rows.map(r => r.column_name), [
            'id', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action',
            'severity', 'service_id', 'source_node_id', 'tenant_id', 'actor',
            'actor_kind', 'target', 'category', 'domain', 'method', 'request_id',
            'detail', 'shipped_at', 'prev_hash', 'hash', 'canonical_form_id',
            'detail_salt', 'detail_commitment', 'pii_in_detail', 'wire_version',
        ]);
        const raw = await admin.query(
            `SELECT detail_salt, detail_commitment FROM ${TABLE} WHERE id = $1`, [row.id]);
        assert.deepEqual(raw.rows[0], {
            detail_salt: sealed.detail_salt, detail_commitment: sealed.detail_commitment,
        });
        assert.match(sealed.detail_salt, /^[0-9a-f]{64}$/);
        const plain = await admin.query(
            `SELECT detail_salt, detail_commitment FROM ${TABLE} WHERE id = $1`, [unsealed.id]);
        assert.deepEqual(plain.rows[0], { detail_salt: '', detail_commitment: '' });
    } finally {
        await admin.end();
    }
});

// A Go-created table stores TIMESTAMPTZ with microseconds. Reading it back as
// a Date dropped the last three digits, so count({ until: row.timestamp })
// missed the row. The session's time zone must not shift it either.
test('TIMESTAMPTZ keeps its microseconds and reads back in UTC', { skip }, async () => {
    const { default: pg } = await import('pg');
    const admin = new pg.Pool({ connectionString: DSN });
    const t = `t_go_us_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
    const sep = DSN.includes('?') ? '&' : '?';
    const kolkata = `${DSN}${sep}options=${encodeURIComponent('-c TimeZone=Asia/Kolkata')}`;
    const s = new PostgresStore(kolkata, { table: t });
    try {
        await admin.query(GO_DDL(t));
        const ts = '2026-08-21T10:00:00.123456Z';
        const row = makeRow({ timestamp: ts });
        await s.insert(row);
        const [got] = await s.query({ requestId: row.request_id });
        assert.equal(got.timestamp, ts);
        assert.equal(await s.count({ requestId: row.request_id, until: got.timestamp }), 1);
    } finally {
        await s.close().catch(() => {});
        await admin.query(`DROP TABLE IF EXISTS ${t}`);
        await admin.end();
    }
});

test('the seq allocation has an index on (source_node_id, monotonic_seq)', { skip }, async () => {
    await store.insert(makeRow({ monotonic_seq: 0 }));
    const { default: pg } = await import('pg');
    const admin = new pg.Pool({ connectionString: DSN });
    try {
        const res = await admin.query(
            'SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2',
            [TABLE, `idx_${TABLE}_node_seq`]);
        assert.equal(res.rows.length, 1);
        assert.match(res.rows[0].indexdef, /\(source_node_id, monotonic_seq\)/);
        assert.doesNotMatch(res.rows[0].indexdef, /UNIQUE/);
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

test('two engines on one node get seqs 1..N in one chain (#92)', { skip }, async () => {
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
            const res = verifyChain(await mk().chainRows('node-92'));
            assert.ok(res.ok, res.reason);
            assert.equal(res.sealedRows, 20);
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
            await admin.query(`UPDATE ${t} SET hash = '${'c'.repeat(64)}', prev_hash = 'genesis' WHERE id = $1`, [sealed.id]);

            const cutoff = new Date(Date.now() - 30 * 86_400_000);
            assert.deepEqual(await e.redactExpired({ before: cutoff }), [pii.id]);

            const byId = async (id) => (await admin.query(
                `SELECT detail, detail_salt, hash FROM ${t} WHERE id = $1`, [id])).rows[0];
            const redacted = await byId(pii.id);
            assert.deepEqual([redacted.detail, redacted.detail_salt], ['null', '']);
            assert.match(redacted.hash, /^[0-9a-f]{64}$/);
            // The rows sealed here still verify with the detail gone.
            const mine = (await s.chainRows('node-90')).filter((r) => r.monotonic_seq <= 3);
            assert.ok(verifyChain(mine).ok);
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

// ── Sealing into the hash chain (spec §2.1) ────────────────────────────────

const VECTORS = new URL('../../', import.meta.url);
const loadVector = async (path) => {
    const { readFile } = await import('node:fs/promises');
    return parseJson(await readFile(new URL(path, VECTORS), 'utf8'));
};

test('a row with seq 0 is sealed, and the detail column holds the hashed text', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const detail = {
            whole: 75, half: 75.5, tiny: 1e-7, safe: Number.MAX_SAFE_INTEGER,
            exact: 123456789012345678901234567890n, text: 'café ✓ 日本', del: 'a\x7fb',
            nested: { list: [1, 2.5, { x: 0.0001 }], none: null, ok: true },
        };
        const first = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-seal', detail }));
        const second = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-seal' }));
        assert.equal(first.monotonic_seq, 1);
        assert.equal(first.prev_hash, 'genesis');
        assert.equal(second.prev_hash, first.hash);
        assert.equal(first.canonical_form_id, '2');
        assert.equal(first.detail, detail);

        const raw = (await admin.query(`SELECT detail, detail_commitment FROM ${t} WHERE id = $1`, [first.id])).rows[0];
        assert.equal(raw.detail, canonicalJSON(detail));
        assert.equal(raw.detail,
            '{"del":"a\\u007fb","exact":123456789012345678901234567890,"half":75.5,'
            + '"nested":{"list":[1,2.5,{"x":0.0001}],"none":null,"ok":true},"safe":9007199254740991,'
            + '"text":"caf\\u00e9 \\u2713 \\u65e5\\u672c","tiny":1e-07,"whole":75}');
        assert.equal(raw.detail_commitment, detailCommitment(first.detail_salt, parseJson(raw.detail)));

        const rows = await s.chainRows('n-seal');
        const res = verifyChain(rows);
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 2);
        assert.equal(rows[0].hash, first.hash);
        // query() keeps an integer past 2^53 as a BigInt.
        const [back] = await s.query({ requestId: first.request_id });
        assert.equal(back.detail.exact, 123456789012345678901234567890n);
    });
});

test('two stores on one node writing at once give one unbroken chain', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const a = mk();
        const b = mk();
        await Promise.all([a.init(), b.init()]);
        let go;
        const start = new Promise((r) => { go = r; });
        const PER = 25;
        const write = async (store, tag) => {
            await start;
            for (let i = 0; i < PER; i++) {
                await store.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-race', target: `${tag}-${i}` }));
            }
        };
        const both = [write(a, 'a'), write(b, 'b')];
        go();
        await Promise.all(both);
        const seqs = (await admin.query(
            `SELECT monotonic_seq FROM ${t} WHERE source_node_id = 'n-race' ORDER BY monotonic_seq`)).rows;
        assert.deepEqual(seqs.map((r) => Number(r.monotonic_seq)), Array.from({ length: 2 * PER }, (_, i) => i + 1));
        const res = verifyChain(await a.chainRows('n-race'));
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 2 * PER);
    });
});

test('a new store continues the chain from the stored tip', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const before = mk();
        await before.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
        const tip = await before.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
        await before.close();
        const after = mk();
        const next = await after.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
        assert.equal(next.monotonic_seq, 3);
        assert.equal(next.prev_hash, tip.hash);
        assert.ok(verifyChain(await after.chainRows('n-restart')).ok);
    });
});

test('a retried row returns the stored row; a different row under its id is rejected', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const row = makeRow({ monotonic_seq: 0, source_node_id: 'n-retry', detail: { n: 1.5 } });
        const first = await s.insert(row);
        const again = await s.insert(row);
        assert.deepEqual(
            [again.monotonic_seq, again.hash, again.prev_hash, again.detail_salt],
            [first.monotonic_seq, first.hash, first.prev_hash, first.detail_salt]);
        assert.equal(Number((await admin.query(`SELECT COUNT(*) FROM ${t}`)).rows[0].count), 1);

        for (const other of [{ target: 'u-2' }, { detail: { n: 2.5 } }, { code: 'USER_DELETED' }]) {
            await assert.rejects(s.insert({ ...row, ...other }), (err) =>
                err instanceof AuditRowRejectedError && /differs from the stored row/.test(err.message));
        }
        // A row with its own seq must match the stored seq and hash too.
        await assert.rejects(s.insert({ ...row, monotonic_seq: 5 }), AuditRowRejectedError);
        // Redacted since: the detail is not compared.
        await s.redactRows({ ids: [row.id] });
        assert.equal((await s.insert(row)).hash, first.hash);
    });
});

test('a seq-0 row needs origin_id === id', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        const row = makeRow({ monotonic_seq: 0, origin_id: 'evt-elsewhere' });
        await assert.rejects(s.insert(row), (err) =>
            err instanceof AuditRowRejectedError && /origin_id/.test(err.message));
        assert.equal(await s.count(), 0);
    });
});

// Inserts a sealed row by plain SQL, the way another SDK's store writes it.
async function _sqlInsert(admin, t, row, detail) {
    const cols = ['id', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action', 'severity',
        'service_id', 'source_node_id', 'tenant_id', 'actor', 'actor_kind', 'target', 'category',
        'domain', 'method', 'request_id', 'detail', 'prev_hash', 'hash', 'canonical_form_id',
        'detail_salt', 'detail_commitment'];
    const vals = cols.map((c) => {
        if (c === 'detail') return detail;
        if (c === 'monotonic_seq') return Number(row[c]);
        return row[c] ?? (c === 'detail_salt' || c === 'detail_commitment' ? '' : null);
    });
    await admin.query(
        `INSERT INTO ${t} (${cols.join(',')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(',')})`, vals);
}

for (const [name, ddl, path, pick] of [
    ['Go', GO_DDL, 'spec/go-sealed-form2.json', (v) => v],
    ['Python', PY_DDL, 'spec/checkpoint-vectors.json', (v) => v.cases[0].rows.filter((r) => r.source_node_id === 'node-1')],
]) {
    test(`appends to a ${name}-sealed chain inserted by SQL`, { skip }, async () => {
        await _withTable(async ({ admin, t, mk }) => {
            await admin.query(ddl(t));
            const rows = pick(await loadVector(path));
            assert.ok(rows.length >= 2);
            for (const r of rows) {
                // The detail as Python's json.dumps writes it: ", " and ": ".
                const text = detailText(r.detail).replaceAll(',"', ', "').replaceAll('":', '": ');
                await _sqlInsert(admin, t, r, text);
            }
            const s = mk();
            const node = rows[0].source_node_id;
            const next = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: node, detail: { after: 1.25 } }));
            assert.equal(next.monotonic_seq, rows.length + 1);
            assert.equal(next.prev_hash, rows.at(-1).hash);
            const back = await s.chainRows(node);
            const res = verifyChain(back);
            assert.ok(res.ok, res.reason);
            assert.equal(res.sealedRows, rows.length + 1);
            back.slice(0, rows.length).forEach((r, i) => assert.equal(r.hash, rows[i].hash));
        });
    });
}

test('insertSealed stores a row from elsewhere with its number tokens', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const [row] = await loadVector('spec/go-sealed-numbers.json');
        await s.insertSealed(row);
        await s.insertSealed(row);
        const back = await s.chainRows(row.source_node_id);
        assert.equal(back.length, 1);
        assert.ok(verifyChain(back).ok);
        const raw = (await admin.query(`SELECT detail FROM ${t} WHERE id = $1`, [row.id])).rows[0].detail;
        assert.equal(raw, detailText(row.detail));
        await assert.rejects(s.insertSealed({ ...row, hash: 'f'.repeat(64) }), AuditRowRejectedError);
        await assert.rejects(s.insertSealed({ ...row, id: 'evt-unsealed', hash: '' }), AuditRowRejectedError);

        // With detailText, the column holds that text byte for byte.
        const [py] = (await loadVector('go/xlang_form2.json')).map((c) => c.row);
        const text = '{"sku": "WIDGET", "qty": 3}';
        await s.insertSealed({ ...py, source_node_id: 'n-py' }, { detailText: text });
        assert.equal((await admin.query(`SELECT detail FROM ${t} WHERE id = $1`, [py.id])).rows[0].detail, text);
    });
});

test('chain tips give checkpoints that the stored chain verifies against', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        for (const node of ['n-a', 'n-b', 'n-b']) {
            await s.insert(makeRow({ monotonic_seq: 0, source_node_id: node }));
        }
        // An unsealed row above is not the tip.
        await s.insert(makeRow({ monotonic_seq: 9, source_node_id: 'n-c' }));
        const tips = await s.chainTips();
        assert.deepEqual(tips.map((x) => [x.source_node_id, x.monotonic_seq]), [['n-a', 1], ['n-b', 2]]);
        const checkpoints = await takeCheckpoints(s);
        const rows = await s.allChainRows();
        assert.ok(verifyChain(rows, { checkpoints }).ok);
        // Cut the tail of n-b: a whole-chain verify finds it.
        await admin.query(`DELETE FROM ${t} WHERE source_node_id = 'n-b' AND monotonic_seq = 2`);
        const res = verifyChain(await s.allChainRows(), { checkpoints });
        assert.equal(res.ok, false);
        assert.equal(res.reason, "node 'n-b': chain ends at seq 1 before checkpoint at seq 2");
        assert.ok(verifyChain(await s.chainRows('n-b'), { checkpoints, partial: true }).ok);
    });
});

test('an engine writes the sealed row to stdout after the insert, and the lines verify', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        for (const strategy of ['queue', 'raise']) {
            const node = `n-stdout-${strategy}`;
            const e = new Engine();
            const lines = [];
            const orig = process.stdout.write;
            // fasten's lines are taken; the test runner's own output goes through.
            process.stdout.write = (chunk, ...rest) => {
                if (typeof chunk !== 'string' || !chunk.startsWith('{"shape":')) return orig.call(process.stdout, chunk, ...rest);
                lines.push(chunk);
                rest.find((x) => typeof x === 'function')?.();
                return true;
            };
            try {
                e.init({ serviceId: 'svc', nodeId: node, auditStore: mk(), auditStoreFailureStrategy: strategy });
                const out = e.emit({ code: 'T124_EVENT', target: 'x', detail: { v: 75.5, big: 2n ** 64n } });
                const stored = strategy === 'raise' ? await out : out;
                if (strategy === 'queue') assert.equal(await e.flush(10_000), true);
                else assert.match(stored.hash, /^[0-9a-f]{64}$/);
            } finally {
                process.stdout.write = orig;
                await e.resetForTests();
            }
            const audit = lines.filter((l) => l.includes('"shape":"audit"'));
            assert.equal(audit.length, 2, strategy);
            const [unsealed, sealed] = audit.map((l) => parseJson(l));
            assert.equal(unsealed.hash, '');
            assert.match(sealed.hash, /^[0-9a-f]{64}$/);
            assert.equal(sealed.id, unsealed.id);
            assert.ok(audit[1].includes('"big":18446744073709551616'));
            const res = verifyChain(audit);
            assert.ok(res.ok, res.reason);
            assert.equal(res.sealedRows, 1);
        }
    });
});

// ── Failures, retries and the node lock ────────────────────────────────────

// Runs fn with fasten's lines captured: the audit lines on stdout, and the
// sys lines on stderr parsed.
async function _captured(fn) {
    const out = [];
    const err = [];
    const [ow, ew] = [process.stdout.write, process.stderr.write];
    const ours = (chunk) => typeof chunk === 'string' && chunk.startsWith('{"shape":');
    process.stdout.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ow.call(process.stdout, chunk, ...rest);
        out.push(...chunk.split('\n').filter(Boolean));
        rest.find((x) => typeof x === 'function')?.();
        return true;
    };
    process.stderr.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ew.call(process.stderr, chunk, ...rest);
        err.push(JSON.parse(chunk));
        return true;
    };
    try {
        await fn();
    } finally {
        process.stdout.write = ow;
        process.stderr.write = ew;
    }
    return { out: out.filter((l) => l.includes('"shape":"audit"')), err };
}

// Wraps the clients the store's pool hands out: on(sql, run) returns a
// promise to answer a query in place of run(), or undefined to let it
// through. `released` collects what each checkout was released with.
async function _hook(s, on) {
    await s._ensureReady();
    const pool = s._pool;
    const connect = pool.connect.bind(pool);
    const released = [];
    const wrap = (c) => {
        if (!c._fastenHooked) {
            c._fastenHooked = true;
            const query = c.query.bind(c);
            c.query = (sql, ...rest) => on(sql, () => query(sql, ...rest)) ?? query(sql, ...rest);
        }
        const release = c.release;
        c.release = (e) => {
            released.push(e);
            return release.call(c, e);
        };
        return c;
    };
    // pool.query() calls connect with a callback.
    pool.connect = (cb) => {
        const p = connect().then(wrap);
        if (!cb) return p;
        p.then((c) => cb(undefined, c, c.release), (e) => cb(e));
        return undefined;
    };
    return { released };
}

const LONE = `doc/${'\u{1f600}'.slice(0, 1)}`;

test('a row the store cannot seal is dead-lettered at once, and the next row is stored', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        for (const bad of [{ target: LONE }, { actor: 42 }]) {
            await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, ...bad })), AuditRowRejectedError);
        }
        const e = new Engine();
        const { err } = await _captured(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n-dead', auditStore: s, queueRetryInitialMs: 1, queueRetryJitter: false });
            // emit() refuses such a row itself, so it is queued directly.
            e._drainer.put(makeRow({ monotonic_seq: 0, source_node_id: 'n-dead', target: LONE }));
            e.emit({ code: 'T124_EVENT', target: 'next' });
            assert.equal(await e.flush(10_000), true);
            await e.resetForTests();
        });
        const dead = err.filter((l) => l.event === 'audit_drain_dead_letter');
        assert.equal(dead.length, 1);
        assert.equal(dead[0].attempt_count, 1);
        assert.match(dead[0].last_error, /^AuditRowRejectedError: /);
        assert.equal(err.filter((l) => l.event === 'audit_drain_failed').length, 0);
        const rows = await s.chainRows('n-dead');
        assert.deepEqual(rows.map((r) => [r.target, r.monotonic_seq]), [['next', 1]]);
        assert.equal(await s.count(), 1);
    });
});

test('a string detail is read as JSON text and must be an object', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const row = makeRow({
            monotonic_seq: 0, source_node_id: 'n-text',
            detail: '{"qty": 3, "price": 75.0, "tiny": 1e-7, "big": 123456789012345678901234567890}',
        });
        const stored = await s.insert(row);
        const raw = (await admin.query(`SELECT detail FROM ${t} WHERE id = $1`, [row.id])).rows[0].detail;
        assert.equal(raw, '{"big":123456789012345678901234567890,"price":75.0,"qty":3,"tiny":1e-07}');
        assert.ok(verifyChain(await s.chainRows('n-text')).ok);
        const [back] = await s.query({ requestId: row.request_id });
        assert.deepEqual(back.detail, { big: 123456789012345678901234567890n, price: 75, qty: 3, tiny: 1e-7 });
        assert.equal((await s.insert(row)).hash, stored.hash);
        for (const bad of ['[1]', 'null', '"x"', '7', 'not json', '{"a":']) {
            await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-text', detail: bad })),
                AuditRowRejectedError, bad);
        }
        assert.equal(await s.count(), 1);
    });
});

test('a retry returns the stored row, and its stdout line verifies', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        const e = new Engine();
        let first;
        const { out } = await _captured(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n-again', auditStore: s, auditStoreFailureStrategy: 'raise' });
            const row = makeRow({ monotonic_seq: 0, source_node_id: 'n-again', detail: { email: 'a@b.com', n: 1.5 } });
            first = await e._storeRow(s, row);
            await s.redactRows({ ids: [row.id] });
            const again = await e._storeRow(s, row);
            assert.deepEqual([again.detail, again.detail_salt, again.monotonic_seq, again.hash],
                [null, null, first.monotonic_seq, first.hash]);
            await e.resetForTests();
        });
        assert.equal(out.length, 2);
        const line = parseJson(out[1]);
        assert.deepEqual([line.detail, line.detail_salt, line.hash], [null, null, first.hash]);
        const res = verifyChain([out[1]]);
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 1);
    });
});

test('a seq-0 row gets a new salt even when it carries one', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        const stored = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-salt', detail_salt: 'ab'.repeat(32) }));
        assert.match(stored.detail_salt, /^[0-9a-f]{64}$/);
        assert.notEqual(stored.detail_salt, 'ab'.repeat(32));
        assert.ok(verifyChain(await s.chainRows('n-salt')).ok);
    });
});

test('after a failed COMMIT the row is read back once', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        let mode = null;
        const hook = await _hook(s, (sql, run) => {
            if (sql !== 'COMMIT' || !mode) return undefined;
            const landed = mode === 'landed';
            mode = null;
            const lost = new Error('Connection terminated unexpectedly');
            return landed ? run().then(() => { throw lost; }) : Promise.reject(lost);
        });
        const e = new Engine();
        const { out } = await _captured(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n-commit', auditStore: s, auditStoreFailureStrategy: 'raise' });
            // Stored, though COMMIT reported an error: emit() gets the row.
            mode = 'landed';
            const row = await e.emit({ code: 'T124_EVENT', target: 'landed' });
            assert.deepEqual([row.monotonic_seq, /^[0-9a-f]{64}$/.test(row.hash)], [1, true]);
            // Not stored: the COMMIT's error.
            mode = 'lost';
            await assert.rejects(e.emit({ code: 'T124_EVENT', target: 'lost' }),
                (err) => err instanceof AuditStoreError && /Connection terminated/.test(err.message)
                    && !(err.cause instanceof AuditOutcomeUnknownError));
            // The read fails too: the outcome is unknown.
            mode = 'lost';
            const query = s._pool.query;
            s._pool.query = async () => { throw new Error('read failed'); };
            try {
                await assert.rejects(e.emit({ code: 'T124_EVENT', target: 'unknown' }),
                    (err) => err.cause instanceof AuditOutcomeUnknownError && /is unknown/.test(err.message));
            } finally {
                s._pool.query = query;
            }
            await e.resetForTests();
        });
        // Each client whose COMMIT failed was discarded.
        assert.equal(hook.released.filter(Boolean).length, 3);
        assert.deepEqual((await s.chainRows('n-commit')).map((r) => r.target), ['landed']);
        // The stored row's sealed line was written; the others have only their first line.
        assert.equal(out.length, 4);
        assert.deepEqual(out.map((l) => parseJson(l)).filter((r) => r.hash).map((r) => r.target), ['landed']);
    });
});

test('a client whose ROLLBACK fails is discarded', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        await s._ensureReady();
        await admin.query(`ALTER TABLE ${t} ADD CONSTRAINT no_marker CHECK (target <> 'reject-me')`);
        const hook = await _hook(s, (sql) => (sql === 'ROLLBACK' ? Promise.reject(new Error('rollback failed')) : undefined));
        await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, target: 'reject-me' })), { code: '23514' });
        assert.equal(hook.released.length, 1);
        assert.match(hook.released[0]?.message ?? '', /rollback failed/);
    });
});

test('insertSealed throws when the row was neither inserted nor found', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        const [row] = await loadVector('spec/go-sealed-numbers.json');
        s._insertRow = async () => 0;
        await assert.rejects(s.insertSealed(row), /not inserted and not stored/);
    });
});

test('a row with its own seq is refused when another row holds that seq', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        // Python's table: its (node, seq) index is not unique.
        await admin.query(PY_DDL(t));
        const s = mk();
        const first = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-own' }));
        const held = (err) => err instanceof AuditRowRejectedError && /seq 1 on node "n-own" is held by row /.test(err.message);
        await assert.rejects(s.insert(makeRow({ monotonic_seq: 1, source_node_id: 'n-own' })), held);
        await assert.rejects(s.insertSealed({ ...first, id: 'evt-other', origin_id: 'evt-other' }), held);
        // The same row again is still a no-op.
        const own = makeRow({ monotonic_seq: 7, source_node_id: 'n-own' });
        await s.insert(own);
        await s.insert(own);
        await s.insertSealed(first);
        assert.equal(await s.count({ sourceNodeId: 'n-own' }), 2);
    });
});

test('an insert waits for the node lock every SDK takes', { skip }, async () => {
    await _withTable(async ({ admin, mk }) => {
        const s = mk();
        await s.init();
        const holder = await admin.connect();
        try {
            await holder.query('BEGIN');
            await holder.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', ['n-lock']);
            let done = 0;
            const pending = [1, 2, 3].map(() =>
                s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-lock' })).then((r) => { done++; return r; }));
            // Another node is not held up.
            assert.equal((await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-free' }))).monotonic_seq, 1);
            await new Promise((r) => setTimeout(r, 300));
            assert.equal(done, 0);
            await holder.query('COMMIT');
            const rows = await Promise.all(pending);
            assert.deepEqual(rows.map((r) => r.monotonic_seq).sort(), [1, 2, 3]);
            const res = verifyChain(await s.chainRows('n-lock'));
            assert.ok(res.ok, res.reason);
        } finally {
            holder.release();
        }
    });
});

test('an insert that fails after sealing takes no seq and writes no sealed line', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        await s.init();
        await admin.query(`ALTER TABLE ${t} ADD CONSTRAINT no_marker CHECK (target <> 'reject-me')`);
        const e = new Engine();
        let ok1;
        let ok2;
        const { out } = await _captured(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n-check', auditStore: s, auditStoreFailureStrategy: 'raise' });
            ok1 = await e.emit({ code: 'T124_EVENT', target: 'ok-1' });
            await assert.rejects(e.emit({ code: 'T124_EVENT', target: 'reject-me' }),
                (err) => err instanceof AuditStoreError && err.cause?.code === '23514');
            ok2 = await e.emit({ code: 'T124_EVENT', target: 'ok-2' });
            await e.resetForTests();
        });
        assert.deepEqual([ok1.monotonic_seq, ok2.monotonic_seq], [1, 2]);
        assert.equal(ok2.prev_hash, ok1.hash);
        const res = verifyChain(await s.chainRows('n-check'));
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 2);
        const rejected = out.map((l) => parseJson(l)).filter((r) => r.target === 'reject-me');
        assert.deepEqual(rejected.map((r) => r.hash), ['']);
    });
});

test('four stores waiting on the node lock at once write one unbroken chain', { skip }, async () => {
    await _withTable(async ({ admin, mk }) => {
        const stores = [mk(), mk(), mk(), mk()];
        await Promise.all(stores.map((x) => x.init()));
        const PER = 10;
        // Hold the node lock until every store has inserts waiting on it, so
        // the writers really overlap instead of taking turns by chance.
        const holder = await admin.connect();
        let pending;
        try {
            await holder.query('BEGIN');
            await holder.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', ['n-four']);
            pending = Promise.all(stores.map((x, w) => Promise.all(Array.from({ length: PER }, (_, i) =>
                x.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-four', target: `w${w}-${i}` }))))));
            const waiting = async () => (await admin.query(
                "SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted")).rows[0].n;
            const deadline = Date.now() + 10_000;
            while ((await waiting()) < stores.length) {
                assert.ok(Date.now() < deadline, 'the stores never queued on the node lock together');
                await new Promise((r) => setTimeout(r, 20));
            }
            await holder.query('COMMIT');
        } finally {
            holder.release();
        }
        await pending;
        const rows = await stores[0].chainRows('n-four');
        assert.deepEqual(rows.map((r) => r.monotonic_seq), Array.from({ length: 4 * PER }, (_, i) => i + 1));
        assert.deepEqual(new Set(rows.map((r) => r.target.split('-')[0])), new Set(['w0', 'w1', 'w2', 'w3']));
        const res = verifyChain(rows);
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 4 * PER);
    });
});

test('a seq-0 row after an unsealed row with its own seq takes the next seq and links to the sealed tip', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        const sealed = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-gap' }));
        await s.insert(makeRow({ monotonic_seq: 500, source_node_id: 'n-gap' }));
        const next = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-gap' }));
        assert.deepEqual([next.monotonic_seq, next.prev_hash], [501, sealed.hash]);
        // The unsealed row above the node's first sealed seq breaks verifyChain there.
        const res = verifyChain(await s.chainRows('n-gap'));
        assert.deepEqual([res.ok, res.firstBreakAt], [false, 500]);
        assert.match(res.reason, /no hash after the node's chain started/);
    });
});

test('a row changed in SQL breaks the chain at its seq, and an unreadable row is named', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        for (let i = 0; i < 4; i++) {
            await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-tamper', detail: { i } }));
        }
        assert.ok(verifyChain(await s.chainRows('n-tamper')).ok);
        const at = (seq) => `source_node_id = 'n-tamper' AND monotonic_seq = ${seq}`;
        await admin.query(`UPDATE ${t} SET target = 'elsewhere' WHERE ${at(3)}`);
        let res = verifyChain(await s.chainRows('n-tamper'));
        assert.equal(res.firstBreakAt, 3);
        assert.match(res.reason, /hash mismatch/);
        await admin.query(`UPDATE ${t} SET detail = '{"i":99}' WHERE ${at(2)}`);
        res = verifyChain(await s.chainRows('n-tamper'));
        assert.equal(res.firstBreakAt, 2);
        assert.match(res.reason, /detail does not match its commitment/);
        const { rows: [{ id }] } = await admin.query(`UPDATE ${t} SET detail = 'not json' WHERE ${at(1)} RETURNING id`);
        await assert.rejects(s.chainRows('n-tamper'), (err) => err instanceof ChainError && err.message.includes(`row ${id}: `));
    });
});

test('a __proto__ key, an unpaired surrogate and big integers go through emit, Postgres and verifyChain', { skip }, async () => {
    await _withTable(async ({ admin, t, mk }) => {
        const s = mk();
        const e = new Engine();
        const detail = JSON.parse('{"__proto__": {"x": 1}, "name": "\\udcff.txt"}');
        Object.assign(detail, { over: 2n ** 53n + 1n, neg: -(2n ** 64n), list: [2n ** 60n], password: 2n ** 70n });
        let row;
        const { out } = await _captured(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n-e2e', auditStore: s, auditStoreFailureStrategy: 'raise' });
            row = await e.emit({ code: 'T124_EVENT', target: 'x', detail });
            await e.resetForTests();
        });
        assert.deepEqual(Object.getOwnPropertyDescriptor(row.detail, '__proto__').value, { x: 1 });
        const want = '{"__proto__":{"x":1},"list":[1152921504606846976],"name":"\\udcff.txt",'
            + '"neg":-18446744073709551616,"over":9007199254740993,"password":"***"}';
        const raw = (await admin.query(`SELECT detail FROM ${t} WHERE id = $1`, [row.id])).rows[0].detail;
        assert.equal(raw, want);
        const res = verifyChain(await s.chainRows('n-e2e'));
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, 1);
        assert.equal(out.length, 2);
        assert.ok(out[1].endsWith(`"detail":${want}}`), out[1]);
        assert.ok(verifyChain(out).ok);
        const [back] = await s.query({ requestId: row.request_id });
        assert.deepEqual([back.detail.over, back.detail.neg, back.detail.list[0]], [2n ** 53n + 1n, -(2n ** 64n), 2n ** 60n]);
    });
});

test('query() rows are snake_case like Row, and verifyChain reads them', { skip }, async () => {
    await _withTable(async ({ mk }) => {
        const s = mk();
        for (let i = 0; i < 2; i++) await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-q', detail: { i, s: 'x' } }));
        const rows = await s.query({ sourceNodeId: 'n-q' });
        assert.deepEqual(Object.keys(rows[0]).sort(), [...CHAIN_COLUMNS].sort());
        assert.ok(verifyChain(rows).ok);
        assert.deepEqual((await s.listUnshipped(10)).map((r) => r.monotonic_seq), [1, 2]);
    });
});
