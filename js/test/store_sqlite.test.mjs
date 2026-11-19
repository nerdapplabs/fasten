/**
 * Tests for SqliteStore, on Node's built-in node:sqlite. They need nothing
 * else and always run.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import { SqliteStore } from '../src/store/sqlite.js';
import {
    AuditOutcomeUnknownError, AuditRowRejectedError, ChainError, Engine,
    register as registerCodes, takeCheckpoints, verifyChain,
} from '../src/index.js';
import { canonicalJSON, detailCommitment, detailText, parseJson } from '../src/chain.js';

const DIR = mkdtempSync(join(tmpdir(), 'fasten-sqlite-'));
after(() => rmSync(DIR, { recursive: true, force: true }));

const dbPath = () => join(DIR, `${randomUUID()}.db`);

const stores = [];
function open(path = dbPath(), opts = {}) {
    const s = new SqliteStore(path, opts);
    stores.push(s);
    return s;
}
after(async () => { for (const s of stores) await s.close(); });

let _seq = 0;
function makeRow(overrides = {}) {
    _seq++;
    const id = `evt-${randomUUID().replace(/-/g, '').slice(0, 20)}`;
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

const _daysAgo = (n) => new Date(Date.now() - n * 86_400_000).toISOString().replace(/Z$/, '000Z');
const CANONICAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const seqsOf = async (s, node) =>
    (await s.query({ sourceNodeId: node, limit: 1000 })).map((r) => r.monotonic_seq).sort((a, b) => a - b);
const sql = (path) => new DatabaseSync(path);

// Runs fn with fasten's own stdout and stderr lines dropped.
async function quiet(fn) {
    const [ow, ew] = [process.stdout.write, process.stderr.write];
    const drop = (orig, stream) => (chunk, ...rest) =>
        typeof chunk === 'string' && chunk.startsWith('{"shape":') ? true : orig.call(stream, chunk, ...rest);
    process.stdout.write = drop(ow, process.stdout);
    process.stderr.write = drop(ew, process.stderr);
    try {
        return await fn();
    } finally {
        process.stdout.write = ow;
        process.stderr.write = ew;
    }
}
const VECTORS = new URL('../../', import.meta.url);
const loadVector = (path) => parseJson(readFileSync(new URL(path, VECTORS), 'utf8'));

registerCodes('tsq', {
    TSQ_EVENT: { domain: 'tsq', action: 'do', severity: 'info', retentionClass: 'long' },
    TSQ_PII: { domain: 'tsq', action: 'do', severity: 'info', piiInDetail: true, detailPassthroughKeys: ['email'] },
    TSQ_PLAIN: { domain: 'tsq', action: 'do', severity: 'info', retentionClass: 'long' },
});

// ── Repository basics ──────────────────────────────────────────────────────

test('insert, query, count and the filters', async () => {
    const s = open();
    const rid = 'req-basics';
    await s.insert(makeRow({ request_id: rid, tenant_id: 'tenant-a' }));
    await s.insert(makeRow({ request_id: rid, tenant_id: 'tenant-b', code: 'USER_DELETED' }));
    assert.equal((await s.query({ requestId: rid })).length, 2);
    assert.equal(await s.count({ requestId: rid }), 2);
    assert.equal(await s.count({ requestId: rid, code: 'USER_DELETED' }), 1);
    assert.deepEqual((await s.query({ requestId: rid, tenantId: 'tenant-a' })).map((r) => r.tenant_id), ['tenant-a']);
    assert.equal((await s.query({ requestId: rid, limit: 1 })).length, 1);
});

test('a new database file is created owner-only', { skip: process.platform === 'win32' }, async () => {
    const path = dbPath();
    open(path);
    assert.equal(statSync(path).mode & 0o777, 0o600);
});

test('the table name must be a plain identifier', () => {
    assert.throws(() => new SqliteStore(':memory:', { table: 'x; DROP TABLE y' }), /not a valid SQL identifier/);
    assert.throws(() => new SqliteStore(':memory:', { table: 'main.audit' }), /not a valid SQL identifier/);
});

test('WAL and the busy timeout are on', async () => {
    const path = dbPath();
    const s = open(path);
    await s.init();
    assert.equal(s._db.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
    assert.equal(s._db.prepare('PRAGMA busy_timeout').get().timeout, 5000);
});

test('round-trip detail and pii_in_detail; query rows are snake_case like Row', async () => {
    const s = open();
    const detail = { nested: { k: [1, 2, 3] }, flag: true, n: null };
    const row = makeRow({ detail, pii_in_detail: true, monotonic_seq: 0 });
    await s.insert(row);
    const [back] = await s.query({ requestId: row.request_id });
    assert.deepEqual(back.detail, detail);
    assert.equal(back.pii_in_detail, true);
    assert.deepEqual(Object.keys(back).sort(), [
        'action', 'actor', 'actor_kind', 'canonical_form_id', 'category', 'code', 'detail',
        'detail_commitment', 'detail_salt', 'domain', 'hash', 'id', 'method', 'monotonic_seq',
        'origin_id', 'pii_in_detail', 'prev_hash', 'request_id', 'service_id', 'severity',
        'shipped_at', 'source_node_id', 'target', 'tenant_id', 'timestamp', 'wire_version']);
    assert.ok(verifyChain([back]).ok);
});

test('listUnshipped, markShipped and the originated-only scope', async () => {
    const s = open();
    const mine = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-ship' }));
    // A row from another node, as ingest stores it.
    await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-other' }));
    const replicated = makeRow({ monotonic_seq: 0, source_node_id: 'n-ship', origin_id: 'evt-elsewhere' });
    replicated.monotonic_seq = 9;
    await s.insert(replicated);
    assert.equal((await s.listUnshipped(100)).length, 3);
    const scoped = await s.listUnshipped(100, { serviceId: 'svc', sourceNodeId: 'n-ship' });
    assert.deepEqual(scoped.map((r) => r.id), [mine.id]);
    await s.markShipped([mine.id]);
    assert.deepEqual(await s.listUnshipped(100, { serviceId: 'svc', sourceNodeId: 'n-ship' }), []);
    const [got] = await s.query({ requestId: mine.request_id });
    assert.match(got.shipped_at, CANONICAL);
    // shipped_at is hashed as null, so marking a row shipped keeps the chain.
    assert.ok(verifyChain((await s.chainRows('n-ship')).filter((r) => r.id === mine.id)).ok);
});

test('listUnshipped with exact keeps detail numbers as they were hashed', async () => {
    const s = open();
    const row = makeRow({ monotonic_seq: 0, source_node_id: 'n-exact', detail: '{"price": 75.0, "big": 123456789012345678901234567890}' });
    await s.insert(row);
    const [plain] = await s.listUnshipped(10);
    assert.equal(plain.detail.price, 75);
    const [exact] = await s.listUnshipped(10, { exact: true });
    const line = JSON.stringify(exact);
    assert.ok(line.includes('"price":75.0'), line);
    assert.ok(verifyChain([line]).ok);
    assert.equal(verifyChain([JSON.stringify(plain, (k, v) => typeof v === 'bigint' ? JSON.rawJSON(String(v)) : v)]).ok, false);
});

test('purge respects unshipped rows and deletes only a seq prefix of each node', async () => {
    const s = open();
    const old = makeRow({ timestamp: _daysAgo(31), source_node_id: 'n-p1', monotonic_seq: 1 });
    await s.insert(old);
    assert.equal(await s.purge({ before: _daysAgo(30) }), 0);
    await s.markShipped([old.id]);
    assert.equal(await s.purge({ before: _daysAgo(30) }), 1);

    // Seq 2 is newer than the cutoff and seq 3 older: a timestamp-only
    // delete takes 3 and keeps 2 and 4.
    for (const [seq, days] of [[1, 40], [2, 20], [3, 35], [4, 10]]) {
        await s.insert(makeRow({ source_node_id: 'n-p2', monotonic_seq: seq, timestamp: _daysAgo(days) }));
    }
    assert.equal(await s.purge({ before: _daysAgo(30), respectUnshipped: false }), 1);
    assert.deepEqual(await seqsOf(s, 'n-p2'), [2, 3, 4]);
});

// ── Sealing (spec §2.1) ────────────────────────────────────────────────────

test('a row with seq 0 is sealed, and the detail column holds the hashed text', async () => {
    const path = dbPath();
    const s = open(path);
    const detail = {
        whole: 75, half: 75.5, tiny: 1e-7, safe: Number.MAX_SAFE_INTEGER,
        exact: 123456789012345678901234567890n, text: 'café ✓ 日本', del: 'a\x7fb',
        nested: { list: [1, 2.5, { x: 0.0001 }], none: null, ok: true },
    };
    const first = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-seal', detail }));
    const second = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-seal' }));
    assert.deepEqual([first.monotonic_seq, first.prev_hash, second.prev_hash, first.canonical_form_id],
        [1, 'genesis', first.hash, '2']);
    assert.equal(first.detail, detail);
    const raw = sql(path).prepare('SELECT detail, detail_commitment FROM audit_log WHERE id = ?').get(first.id);
    assert.equal(raw.detail, canonicalJSON(detail));
    assert.equal(raw.detail,
        '{"del":"a\\u007fb","exact":123456789012345678901234567890,"half":75.5,'
        + '"nested":{"list":[1,2.5,{"x":0.0001}],"none":null,"ok":true},"safe":9007199254740991,'
        + '"text":"caf\\u00e9 \\u2713 \\u65e5\\u672c","tiny":1e-07,"whole":75}');
    assert.equal(raw.detail_commitment, detailCommitment(first.detail_salt, parseJson(raw.detail)));
    const res = verifyChain(await s.chainRows('n-seal'));
    assert.ok(res.ok, res.reason);
    assert.equal(res.sealedRows, 2);
    const [back] = await s.query({ requestId: first.request_id });
    assert.equal(back.detail.exact, 123456789012345678901234567890n);
});

test('a new store continues the chain from the stored tip', async () => {
    const path = dbPath();
    const before = new SqliteStore(path);
    await before.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
    const tip = await before.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
    await before.close();
    const later = open(path);
    const next = await later.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-restart' }));
    assert.deepEqual([next.monotonic_seq, next.prev_hash], [3, tip.hash]);
    assert.ok(verifyChain(await later.chainRows('n-restart')).ok);
});

test('two handles on one file writing in turn give one chain', async () => {
    const path = dbPath();
    const [a, b] = [open(path), open(path)];
    await Promise.all([a.init(), b.init()]);
    await Promise.all(Array.from({ length: 20 }, (_, i) =>
        (i % 2 ? a : b).insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-two' }))));
    assert.deepEqual(await seqsOf(a, 'n-two'), Array.from({ length: 20 }, (_, i) => i + 1));
    assert.ok(verifyChain(await b.chainRows('n-two')).ok);
});

// Each worker thread opens its own store on the file, so the writers really
// run at once and wait on SQLite's write lock.
const WORKER = `
import { workerData, parentPort } from 'node:worker_threads';
const { SqliteStore } = await import(workerData.store);
const s = new SqliteStore(workerData.path);
const go = new Int32Array(workerData.go);
Atomics.wait(go, 0, 0);
for (let i = 0; i < workerData.n; i++) {
    const id = 'evt-w' + workerData.w + '-' + i;
    await s.insert({ id, origin_id: id, monotonic_seq: 0, timestamp: '2026-08-21T10:00:00.000000Z',
        code: 'C', action: 'a', severity: 'info', service_id: 'svc', source_node_id: 'n-threads',
        tenant_id: null, actor: 'x', actor_kind: 'user', target: 'w' + workerData.w, category: 'c',
        domain: 'd', method: 'm', request_id: 'r', detail: { i } });
}
await s.close();
parentPort.postMessage('done');
`;

test('four threads writing one node at once give one unbroken chain', async () => {
    const path = dbPath();
    await open(path).init();
    const go = new SharedArrayBuffer(4);
    const N = 25;
    const store = new URL('../src/store/sqlite.js', import.meta.url).href;
    const workers = [0, 1, 2, 3].map((w) => new Worker(WORKER, {
        eval: true, workerData: { path, w, n: N, go, store },
    }));
    const done = workers.map((wk) => new Promise((resolve, reject) => {
        wk.once('message', resolve);
        wk.once('error', reject);
    }));
    await new Promise((r) => setTimeout(r, 100));
    Atomics.store(new Int32Array(go), 0, 1);
    Atomics.notify(new Int32Array(go), 0);
    await Promise.all(done);
    const s = open(path);
    const rows = await s.chainRows('n-threads');
    assert.deepEqual(rows.map((r) => r.monotonic_seq), Array.from({ length: 4 * N }, (_, i) => i + 1));
    assert.deepEqual(new Set(rows.map((r) => r.target)), new Set(['w0', 'w1', 'w2', 'w3']));
    const res = verifyChain(rows);
    assert.ok(res.ok, res.reason);
    assert.equal(res.sealedRows, 4 * N);
});

test('an insert waits for another connection\'s write lock', async () => {
    const path = dbPath();
    const s = open(path, { busyTimeoutMs: 200 });
    await s.init();
    const other = sql(path);
    other.exec('BEGIN IMMEDIATE');
    try {
        await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-lock' })), /locked/);
    } finally {
        other.exec('ROLLBACK');
        other.close();
    }
    const row = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-lock' }));
    assert.equal(row.monotonic_seq, 1);
    assert.equal(s._db.isTransaction, false);
});

test('a retried row returns the stored row; a different row under its id is rejected', async () => {
    const s = open();
    const row = makeRow({ monotonic_seq: 0, source_node_id: 'n-retry', detail: { n: 1.5 } });
    const first = await s.insert(row);
    const again = await s.insert(row);
    assert.deepEqual(
        [again.monotonic_seq, again.hash, again.prev_hash, again.detail_salt],
        [first.monotonic_seq, first.hash, first.prev_hash, first.detail_salt]);
    assert.equal(await s.count(), 1);
    for (const other of [{ target: 'u-2' }, { detail: { n: 2.5 } }, { code: 'USER_DELETED' }]) {
        await assert.rejects(s.insert({ ...row, ...other }), (err) =>
            err instanceof AuditRowRejectedError && /differs from the stored row/.test(err.message));
    }
    await assert.rejects(s.insert({ ...row, monotonic_seq: 5 }), AuditRowRejectedError);
    // Redacted since: the detail is not compared.
    await s.redactRows({ ids: [row.id] });
    assert.equal((await s.insert(row)).hash, first.hash);
});

test('a seq-0 row needs origin_id === id', async () => {
    const s = open();
    await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, origin_id: 'evt-elsewhere' })), (err) =>
        err instanceof AuditRowRejectedError && /origin_id/.test(err.message));
    assert.equal(await s.count(), 0);
});

test('a seq-0 row gets a new salt even when it carries one', async () => {
    const s = open();
    const stored = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-salt', detail_salt: 'ab'.repeat(32) }));
    assert.notEqual(stored.detail_salt, 'ab'.repeat(32));
    assert.ok(verifyChain(await s.chainRows('n-salt')).ok);
});

test('a row the store cannot seal is rejected, and a string detail must be a JSON object', async () => {
    const s = open();
    const lone = `doc/${'\u{1f600}'.slice(0, 1)}`;
    for (const bad of [{ target: lone }, { actor: 42 }]) {
        await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, ...bad })), AuditRowRejectedError);
    }
    const row = makeRow({
        monotonic_seq: 0, source_node_id: 'n-text',
        detail: '{"qty": 3, "price": 75.0, "tiny": 1e-7, "big": 123456789012345678901234567890}',
    });
    const stored = await s.insert(row);
    const raw = s._db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(row.id).detail;
    assert.equal(raw, '{"big":123456789012345678901234567890,"price":75.0,"qty":3,"tiny":1e-07}');
    assert.ok(verifyChain(await s.chainRows('n-text')).ok);
    assert.equal((await s.insert(row)).hash, stored.hash);
    for (const bad of ['[1]', 'null', '"x"', '7', 'not json', '{"a":']) {
        await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-text', detail: bad })),
            AuditRowRejectedError, bad);
    }
    assert.equal(await s.count(), 1);
});

test('a row with its own seq is refused when another row holds that seq', async () => {
    const path = dbPath();
    // Python's table: its (node, seq) index is not unique.
    const db = sql(path);
    db.exec(PY_DDL('audit_log'));
    db.close();
    const s = open(path);
    const first = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-own' }));
    const held = (err) => err instanceof AuditRowRejectedError && /seq 1 on node "n-own" is held by row /.test(err.message);
    await assert.rejects(s.insert(makeRow({ monotonic_seq: 1, source_node_id: 'n-own' })), held);
    await assert.rejects(s.insertSealed({ ...first, id: 'evt-other', origin_id: 'evt-other' }), held);
    const own = makeRow({ monotonic_seq: 7, source_node_id: 'n-own' });
    await s.insert(own);
    await s.insert(own);
    await s.insertSealed(first);
    assert.equal(await s.count({ sourceNodeId: 'n-own' }), 2);
});

test('a seq-0 row after an unsealed row with its own seq takes the next seq and links to the sealed tip', async () => {
    const s = open();
    const sealed = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-gap' }));
    await s.insert(makeRow({ monotonic_seq: 500, source_node_id: 'n-gap' }));
    const next = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-gap' }));
    assert.deepEqual([next.monotonic_seq, next.prev_hash], [501, sealed.hash]);
    const res = verifyChain(await s.chainRows('n-gap'));
    assert.deepEqual([res.ok, res.firstBreakAt], [false, 500]);
});

test('after a failed COMMIT the row is read back once', async () => {
    const s = open();
    await s.init();
    const exec = s._db.exec.bind(s._db);
    let mode = null;
    s._db.exec = (q) => {
        if (q !== 'COMMIT' || !mode) return exec(q);
        const landed = mode === 'landed';
        mode = null;
        if (landed) exec(q);
        throw new Error('disk I/O error');
    };
    mode = 'landed';
    const row = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-commit', target: 'landed' }));
    assert.equal(row.monotonic_seq, 1);
    mode = 'lost';
    await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-commit', target: 'lost' })),
        (err) => /disk I\/O error/.test(err.message) && !(err instanceof AuditOutcomeUnknownError));
    mode = 'lost';
    const held = s._held.bind(s);
    let calls = 0;
    s._held = (id) => { if (++calls === 2) throw new Error('read failed'); return held(id); };
    await assert.rejects(s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-commit', target: 'unknown' })),
        AuditOutcomeUnknownError);
    s._held = held;
    s._db.exec = exec;
    assert.deepEqual((await s.chainRows('n-commit')).map((r) => r.target), ['landed']);
    assert.equal(s._db.isTransaction, false);
});

test('a row changed in SQL breaks the chain at its seq, and an unreadable row is named', async () => {
    const path = dbPath();
    const s = open(path);
    for (let i = 0; i < 4; i++) await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'n-tamper', detail: { i } }));
    assert.ok(verifyChain(await s.chainRows('n-tamper')).ok);
    const db = sql(path);
    const at = (seq) => `source_node_id = 'n-tamper' AND monotonic_seq = ${seq}`;
    db.exec(`UPDATE audit_log SET target = 'elsewhere' WHERE ${at(3)}`);
    let res = verifyChain(await s.chainRows('n-tamper'));
    assert.deepEqual([res.firstBreakAt, /hash mismatch/.test(res.reason)], [3, true]);
    db.exec(`UPDATE audit_log SET detail = '{"i":99}' WHERE ${at(2)}`);
    res = verifyChain(await s.chainRows('n-tamper'));
    assert.deepEqual([res.firstBreakAt, /detail does not match its commitment/.test(res.reason)], [2, true]);
    const { id } = db.prepare(`UPDATE audit_log SET detail = 'not json' WHERE ${at(1)} RETURNING id`).get();
    db.close();
    await assert.rejects(s.chainRows('n-tamper'), (err) => err instanceof ChainError && err.message.includes(`SqliteStore: row ${id}: `));
});

test('an unpaired surrogate, a __proto__ key and big integers go through emit, SQLite and verifyChain', async () => {
    const s = open();
    const e = new Engine();
    const detail = JSON.parse('{"__proto__": {"x": 1}, "name": "\\udcff.txt"}');
    Object.assign(detail, { over: 2n ** 53n + 1n, neg: -(2n ** 64n), list: [2n ** 60n], half: 0.1 + 0.2 });
    e.init({ serviceId: 'svc', nodeId: 'n-e2e', auditStore: s, auditStoreFailureStrategy: 'raise' });
    let row;
    try {
        row = await quiet(() => e.emit({ code: 'TSQ_EVENT', target: 'x', detail }));
    } finally {
        await e.resetForTests();
    }
    const raw = s._db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(row.id).detail;
    assert.equal(raw, '{"__proto__":{"x":1},"half":0.30000000000000004,"list":[1152921504606846976],'
        + '"name":"\\udcff.txt","neg":-18446744073709551616,"over":9007199254740993}');
    const [back] = await s.chainRows('n-e2e');
    assert.equal(back.detail.name, '\udcff.txt');
    assert.ok(verifyChain([back]).ok);
});

test('redaction keeps the chain valid, and redactExpired records each row', async () => {
    const s = open();
    const e = new Engine();
    e.init({ serviceId: 'svc', nodeId: 'n-redact', auditStore: s, auditStoreFailureStrategy: 'raise' });
    try {
        const old = _daysAgo(40);
        const pii = makeRow({ monotonic_seq: 0, source_node_id: 'n-redact', code: 'TSQ_PII', timestamp: old, pii_in_detail: true });
        const plain = makeRow({ monotonic_seq: 0, source_node_id: 'n-redact', code: 'TSQ_PLAIN', timestamp: old });
        const fresh = makeRow({ monotonic_seq: 0, source_node_id: 'n-redact', code: 'TSQ_PII', pii_in_detail: true });
        for (const r of [pii, plain, fresh]) await s.insert(r);
        // A form-"1" row sealed by another SDK: its detail is hashed, so it stays.
        const sealed = makeRow({ monotonic_seq: 99, source_node_id: 'n-redact', code: 'TSQ_PII', timestamp: old });
        await s.insert(sealed);
        s._db.prepare(`UPDATE audit_log SET hash = '${'c'.repeat(64)}', prev_hash = 'genesis' WHERE id = ?`).run(sealed.id);
        const cutoff = new Date(Date.now() - 30 * 86_400_000);
        assert.deepEqual(await s.listRedactionCandidates({ before: cutoff, codes: ['TSQ_PII'] }).then((c) => c.skipped), 1);
        assert.deepEqual(await quiet(() => e.redactExpired({ before: cutoff })), [pii.id]);
        const byId = (id) => s._db.prepare('SELECT detail, detail_salt, hash FROM audit_log WHERE id = ?').get(id);
        assert.deepEqual([byId(pii.id).detail, byId(pii.id).detail_salt], ['null', '']);
        const mine = (await s.chainRows('n-redact')).filter((r) => r.monotonic_seq <= 4);
        const res = verifyChain(mine);
        assert.ok(res.ok, res.reason);
        assert.equal(mine.find((r) => r.id === pii.id).detail, null);
        assert.notEqual(byId(fresh.id).detail, 'null');
        assert.notEqual(byId(sealed.id).detail, 'null');
        assert.equal(await s.count({ code: 'AUDIT_ROW_REDACTED' }), 1);
        assert.deepEqual(await quiet(() => e.redactExpired({ before: cutoff })), []);
        assert.deepEqual(await s.redactRows({ ids: [pii.id, sealed.id] }), [pii.id]);
    } finally {
        await e.resetForTests();
    }
});

test('chain tips give checkpoints that the stored chain verifies against', async () => {
    const s = open();
    for (const node of ['n-a', 'n-b', 'n-b']) await s.insert(makeRow({ monotonic_seq: 0, source_node_id: node }));
    await s.insert(makeRow({ monotonic_seq: 9, source_node_id: 'n-c' }));
    const tips = await s.chainTips();
    assert.deepEqual(tips.map((x) => [x.source_node_id, x.monotonic_seq]), [['n-a', 1], ['n-b', 2]]);
    const checkpoints = await takeCheckpoints(s);
    assert.ok(verifyChain(await s.allChainRows(), { checkpoints }).ok);
    s._db.exec(`DELETE FROM audit_log WHERE source_node_id = 'n-b' AND monotonic_seq = 2`);
    const res = verifyChain(await s.allChainRows(), { checkpoints });
    assert.equal(res.reason, "node 'n-b': chain ends at seq 1 before checkpoint at seq 2");
    assert.ok(verifyChain(await s.chainRows('n-b'), { checkpoints, partial: true }).ok);
});

test('two engines on one node get seqs 1..N in one chain', async () => {
    const path = dbPath();
    const engines = [new Engine(), new Engine()];
    engines.forEach((e) => e.init({ serviceId: 'svc', nodeId: 'node-2e', auditStore: open(path) }));
    try {
        await quiet(async () => {
            for (let i = 0; i < 20; i++) engines[i % 2].emit({ code: 'TSQ_EVENT', target: `x-${i}` });
            for (const e of engines) assert.equal(await e.flush(10_000), true);
        });
    } finally {
        for (const e of engines) await e.resetForTests();
    }
    const rows = await open(path).chainRows('node-2e');
    assert.deepEqual(rows.map((r) => r.monotonic_seq), Array.from({ length: 20 }, (_, i) => i + 1));
    assert.ok(verifyChain(rows).ok);
});

test('insertSealed stores a row from elsewhere with its number tokens', async () => {
    const s = open();
    const [row] = loadVector('spec/go-sealed-numbers.json');
    await s.insertSealed(row);
    await s.insertSealed(row);
    const back = await s.chainRows(row.source_node_id);
    assert.equal(back.length, 1);
    assert.ok(verifyChain(back).ok);
    assert.equal(s._db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(row.id).detail, detailText(row.detail));
    await assert.rejects(s.insertSealed({ ...row, hash: 'f'.repeat(64) }), AuditRowRejectedError);
    await assert.rejects(s.insertSealed({ ...row, id: 'evt-unsealed', hash: '' }), AuditRowRejectedError);
    const [py] = loadVector('go/xlang_form2.json').map((c) => c.row);
    const text = '{"sku": "WIDGET", "qty": 3}';
    await s.insertReplicated({ ...py, source_node_id: 'n-py' }, { detailText: text });
    assert.equal(s._db.prepare('SELECT detail FROM audit_log WHERE id = ?').get(py.id).detail, text);
});

// ── Tables the Python and Go stores created ────────────────────────────────

// The tables python/fasten/store/sqlite.py and go/store.go create.
const PY_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL,
    timestamp TEXT NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
    severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
    tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
    target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
    method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL,
    shipped_at TEXT, canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt TEXT, detail_commitment TEXT,
    prev_hash TEXT NOT NULL DEFAULT 'genesis', hash TEXT NOT NULL DEFAULT '');
    CREATE INDEX idx_${t}_node_seq ON ${t}(source_node_id, monotonic_seq);`;
const GO_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL,
    timestamp TEXT NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
    severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
    tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
    target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
    method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL,
    pii_in_detail INTEGER NOT NULL DEFAULT 0, shipped_at TEXT,
    wire_version TEXT NOT NULL DEFAULT '1', hash TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '', canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt TEXT NOT NULL DEFAULT '', detail_commitment TEXT NOT NULL DEFAULT '');
    CREATE UNIQUE INDEX uq_${t}_node_seq ON ${t}(source_node_id, monotonic_seq);`;
// The table fasten-core/src/store/sqlite.rs creates.
const RUST_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1', origin_id TEXT NOT NULL,
    monotonic_seq INTEGER NOT NULL DEFAULT 0, timestamp TEXT NOT NULL, code TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
    service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '', tenant_id TEXT,
    actor TEXT NOT NULL DEFAULT '', actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}',
    pii_in_detail INTEGER NOT NULL DEFAULT 0, shipped_at TEXT,
    prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL DEFAULT '',
    canonical_form_id TEXT NOT NULL DEFAULT '1', detail_salt TEXT, detail_commitment TEXT,
    UNIQUE (source_node_id, monotonic_seq));`;
// A Python table from before chaining, without the chain columns.
const OLD_PY_DDL = (t) => `CREATE TABLE ${t} (
    id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL,
    timestamp TEXT NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
    severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
    tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
    target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
    method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL, shipped_at TEXT)`;

const ALL_COLUMNS = ['id', 'wire_version', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action',
    'severity', 'service_id', 'source_node_id', 'tenant_id', 'actor', 'actor_kind', 'target', 'category',
    'domain', 'method', 'request_id', 'detail', 'shipped_at', 'canonical_form_id', 'prev_hash', 'hash',
    'detail_salt', 'detail_commitment', 'pii_in_detail'];

const indexes = (db, t) => db.prepare(`SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ?`).all(t);
// The table's indexes on (source_node_id, monotonic_seq), constraints included.
const nodeSeqIndexes = (db, t) => db.prepare(`SELECT l.name, l."unique" AS "unique" FROM pragma_index_list(?) AS l
    WHERE (SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_index_info(l.name) ORDER BY seqno))
        = 'source_node_id,monotonic_seq'`).all(t);

const UNIQUE = new Set(['Go', 'Rust']);
for (const [name, ddl] of [['Python', PY_DDL], ['Go', GO_DDL], ['Rust', RUST_DDL], ['older Python', OLD_PY_DDL]]) {
    test(`writes into a table the ${name} store created`, async () => {
        const path = dbPath();
        const db = sql(path);
        db.exec(ddl('audit'));
        // An unchained row at seq 0, twice: such a table may repeat a seq.
        if (!UNIQUE.has(name)) {
            for (const id of ['evt-u1', 'evt-u2']) {
                db.prepare(`INSERT INTO audit (id, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, actor, actor_kind, target, category, domain, method, request_id, detail) VALUES (?, ?, 0, '2026-01-01T00:00:00.000000Z', 'C', 'a', 'info', 's', 'node-old', 'x', 'user', 't', 'c', 'd', 'm', 'r', '{}')`).run(id, id);
            }
        }
        const s = open(path, { table: 'audit' });
        const first = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'node-shared', pii_in_detail: true }));
        await s.insert(makeRow({ monotonic_seq: 0, source_node_id: 'node-shared' }));
        assert.deepEqual(await seqsOf(s, 'node-shared'), [1, 2]);
        const raw = db.prepare('SELECT prev_hash, hash, canonical_form_id, detail_salt FROM audit WHERE id = ?').get(first.id);
        assert.deepEqual([raw.prev_hash, raw.canonical_form_id, raw.detail_salt], ['genesis', '2', first.detail_salt]);
        assert.ok(verifyChain(await s.chainRows('node-shared')).ok);
        const cols = db.prepare('SELECT name FROM pragma_table_info(?)').all('audit').map((r) => r.name);
        for (const c of ALL_COLUMNS) assert.ok(cols.includes(c), `${name} table lacks ${c}`);
        // The (node, seq) index is the table's own, or a plain one: the old
        // rows repeat seq 0.
        const nodeSeq = nodeSeqIndexes(db, 'audit');
        assert.equal(nodeSeq.length, 1);
        assert.equal(nodeSeq[0].unique, UNIQUE.has(name) ? 1 : 0);
        await s.markShipped([first.id]);
        const [got] = await s.query({ requestId: first.request_id });
        assert.deepEqual([CANONICAL.test(got.shipped_at), got.pii_in_detail], [true, true]);
        db.close();
    });
}

test('a table the JS store creates has the Go store\'s unique (node, seq) index and no NULL salts', async () => {
    const path = dbPath();
    const s = open(path);
    const sealed = await s.insert(makeRow({ monotonic_seq: 0 }));
    const unsealed = makeRow({ source_node_id: 'own-seq' });
    await s.insert(unsealed);
    const db = sql(path);
    assert.deepEqual(db.prepare('SELECT name FROM pragma_table_info(?)').all('audit_log').map((r) => r.name), [
        'id', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action', 'severity', 'service_id',
        'source_node_id', 'tenant_id', 'actor', 'actor_kind', 'target', 'category', 'domain', 'method',
        'request_id', 'detail', 'shipped_at', 'canonical_form_id', 'detail_salt', 'detail_commitment',
        'prev_hash', 'hash', 'pii_in_detail', 'wire_version']);
    const uq = indexes(db, 'audit_log').find((i) => i.name === 'uq_audit_log_node_seq');
    assert.match(uq.sql, /UNIQUE INDEX/);
    assert.deepEqual({ ...db.prepare('SELECT detail_salt, detail_commitment FROM audit_log WHERE id = ?').get(unsealed.id) },
        { detail_salt: '', detail_commitment: '' });
    assert.match(sealed.detail_salt, /^[0-9a-f]{64}$/);
    // A second row at a seq fails in SQL too, whoever writes it.
    assert.throws(() => db.prepare(`INSERT INTO audit_log (id, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, actor, actor_kind, target, category, domain, method, request_id, detail) SELECT 'evt-dup', 'evt-dup', monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, actor, actor_kind, target, category, domain, method, request_id, detail FROM audit_log WHERE id = ?`).run(sealed.id), /UNIQUE/);
    db.close();
});

// Inserts a sealed row by plain SQL, the way another SDK's store writes it.
function sqlInsert(db, t, row, detail) {
    const cols = ['id', 'origin_id', 'monotonic_seq', 'timestamp', 'code', 'action', 'severity',
        'service_id', 'source_node_id', 'tenant_id', 'actor', 'actor_kind', 'target', 'category',
        'domain', 'method', 'request_id', 'detail', 'prev_hash', 'hash', 'canonical_form_id',
        'detail_salt', 'detail_commitment'];
    const vals = cols.map((c) => {
        if (c === 'detail') return detail;
        if (c === 'monotonic_seq') return Number(row[c]);
        return row[c] ?? (c === 'detail_salt' || c === 'detail_commitment' ? '' : null);
    });
    db.prepare(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...vals);
}

for (const [name, ddl, path, pick, render] of [
    // Go's json.Marshal writes compact text.
    ['Go', GO_DDL, 'spec/go-sealed-form2.json', (v) => v, (d) => detailText(d)],
    // Python's json.dumps writes ", " and ": ".
    ['Python', PY_DDL, 'spec/checkpoint-vectors.json', (v) => v.cases[0].rows.filter((r) => r.source_node_id === 'node-1'),
        (d) => detailText(d).replaceAll(',"', ', "').replaceAll('":', '": ')],
]) {
    test(`appends to a ${name}-sealed chain inserted by SQL`, async () => {
        const file = dbPath();
        const db = sql(file);
        db.exec(ddl('audit'));
        const rows = pick(loadVector(path));
        assert.ok(rows.length >= 2);
        for (const r of rows) sqlInsert(db, 'audit', r, render(r.detail));
        db.close();
        const s = open(file, { table: 'audit' });
        const node = rows[0].source_node_id;
        const next = await s.insert(makeRow({ monotonic_seq: 0, source_node_id: node, detail: { after: 1.25 } }));
        assert.deepEqual([next.monotonic_seq, next.prev_hash], [rows.length + 1, rows.at(-1).hash]);
        const back = await s.chainRows(node);
        const res = verifyChain(back);
        assert.ok(res.ok, res.reason);
        assert.equal(res.sealedRows, rows.length + 1);
        back.slice(0, rows.length).forEach((r, i) => assert.equal(r.hash, rows[i].hash));
    });
}
