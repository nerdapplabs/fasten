// The HTTP reader against in-memory stores: auth, tenant scope on every
// route, limits, paging, search, correlate, topology and the doctor.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Engine, register } from '../src/index.js';
import { reader, requireBearer } from '../src/reader.js';
import { MemoryAuditStore, MemoryStreamStore, captureLines, serve } from './reader_fixtures.mjs';

delete process.env.FASTEN_SEARCH_ENABLED;
delete process.env.FASTEN_PERSIST_STREAMS;

const TOKEN = 's3cret-token';
const AUTH = { authorization: `Bearer ${TOKEN}` };

let seq = 0;
function ts(n) {
    return `2026-08-21T10:00:${String(n).padStart(2, '0')}.000000Z`;
}
function auditRow(over = {}) {
    seq++;
    const id = `evt-${randomUUID().replace(/-/g, '').slice(0, 20)}`;
    return {
        wire_version: '1', id, origin_id: id, monotonic_seq: 0, timestamp: ts(seq % 60),
        code: 'USER_CREATED', action: 'create', severity: 'info', service_id: 'svc',
        source_node_id: 'n1', tenant_id: 'tenant-a', actor: 'alice', actor_kind: 'user',
        target: 'u-1', category: 'account', domain: 'user', method: 'sdk',
        request_id: 'req-a', detail: { note: 'hello' }, pii_in_detail: false, ...over,
    };
}

// An engine over a store holding rows for two tenants on one node, and
// stream stores with rows for both.
async function setup({ searchEnabled = true } = {}) {
    const store = new MemoryAuditStore();
    const engine = new Engine();
    await captureLines(() => engine.init({
        serviceId: 'svc', nodeId: 'n1', tenantId: 'host-tenant', auditStore: store,
        auditStoreFailureStrategy: 'raise', searchEnabled,
    }));
    store.insert(auditRow({ detail: { note: 'alpha needle' } }));
    store.insert(auditRow({ tenant_id: 'tenant-b', request_id: 'req-b', actor: 'bob', detail: { note: 'beta needle' } }));
    store.insert(auditRow({ detail: { big: 2n ** 60n, text: 'Grüße, 世界' } }));
    const sys = new MemoryStreamStore();
    const api = new MemoryStreamStore();
    await sys.insert({ level: 'info', event: 'login needle', request_id: 'req-a', tenant_id: 'tenant-a', timestamp: ts(1) });
    await sys.insert({ level: 'error', event: 'crash needle', request_id: 'req-b', tenant_id: 'tenant-b', timestamp: ts(2) });
    await sys.insert({ level: 'info', event: 'no tenant needle', request_id: 'req-a', timestamp: ts(3) });
    await api.insert({ method: 'GET', path: '/a', status: 200, request_id: 'req-a', tenant_id: 'tenant-a', timestamp: ts(1) });
    await api.insert({ method: 'POST', path: '/b', status: 500, request_id: 'req-b', tenant_id: 'tenant-b', timestamp: ts(2) });
    return { engine, store, sys, api };
}

before(() => {
    register('user', { USER_CREATED: { domain: 'user', action: 'create', severity: 'info' } });
});

describe('construction', () => {
    test('auth is required', () => {
        assert.throws(() => reader({}), /auth is required/);
        assert.throws(() => reader(), /auth is required/);
        assert.throws(() => reader({ auth: null }), /auth is required/);
        assert.throws(() => reader({ auth: {} }), /auth is required/);
        assert.throws(() => reader({ auth: { bearer: '' } }), /non-empty string/);
        assert.throws(() => reader({ auth: { bearer: 'x', verify: () => true } }), /not both/);
        assert.throws(() => reader({ auth: { verify: 'yes' } }), /must be a function/);
    });

    test('"none" is the explicit opt-out', async () => {
        const { engine } = await setup();
        await serve(reader({ auth: 'none', engine }), async (get) => {
            assert.equal((await get('/audit')).status, 200);
        });
    });

    test('requireBearer reads the token from the environment', () => {
        delete process.env.FASTEN_READER_TOKEN;
        assert.throws(() => requireBearer(), /FASTEN_READER_TOKEN is unset or empty/);
        process.env.MY_TOKEN = 't';
        assert.deepEqual(requireBearer('MY_TOKEN'), { bearer: 't' });
        delete process.env.MY_TOKEN;
    });

    test('enforceTenantIsolation needs tenantScope', () => {
        assert.throws(() => reader({ auth: 'none', enforceTenantIsolation: true }), /requires a tenantScope/);
    });
});

describe('auth', () => {
    let ctx;
    before(async () => {
        ctx = await setup();
    });

    for (const path of ['/audit', '/audit/doctor', '/correlate?request_id=req-a', '/search?q=x&since=2026-01-01T00:00:00Z', '/sys', '/api', '/topology']) {
        test(`${path} needs the token`, async () => {
            await serve(reader({ auth: { bearer: TOKEN }, engine: ctx.engine }), async (get) => {
                for (const headers of [{}, { authorization: TOKEN }, { authorization: `Basic ${TOKEN}` }, { authorization: 'Bearer wrong' }, { authorization: `Bearer ${TOKEN}x` }]) {
                    const r = await get(path, headers);
                    assert.equal(r.status, 401);
                    assert.deepEqual(r.body, { detail: 'unauthenticated' });
                }
                assert.equal((await get(path, AUTH)).status, 200);
            });
        });
    }

    test('a verify function decides, and may be async', async () => {
        const seen = [];
        const h = reader({ auth: { verify: async (req) => { seen.push(req.url); return req.headers['x-ok'] === '1'; } }, engine: ctx.engine });
        await serve(h, async (get) => {
            assert.equal((await get('/audit')).status, 401);
            assert.equal((await get('/audit', { 'x-ok': '1' })).status, 200);
        });
        assert.equal(seen.length, 2);
    });

    test('a verify function that throws is a 500 without its message', async () => {
        const h = reader({ auth: { verify: () => { throw new Error(`token ${TOKEN} bad`); } }, engine: ctx.engine });
        const { err } = await captureLines(() => serve(h, async (get) => {
            const r = await get('/audit');
            assert.equal(r.status, 500);
            assert.deepEqual(r.body, { detail: 'internal error' });
        }));
        assert.ok(!err.join('').includes(TOKEN));
        assert.ok(err.some((l) => l.includes('reader_query_failed')));
    });

    test('unknown paths go to next, or get a 404; other methods a 405', async () => {
        const h = reader({ auth: { bearer: TOKEN }, engine: ctx.engine });
        await serve(h, async (get) => {
            assert.equal((await get('/nope', AUTH)).status, 404);
            const r = await get('/audit', AUTH, 'POST');
            assert.equal(r.status, 405);
            assert.equal(r.headers.get('allow'), 'GET');
        });
        let called = false;
        await serve((req, res) => h(req, res, () => { called = true; res.end('next'); }), async (get) => {
            assert.equal((await get('/nope')).text, 'next');
        });
        assert.ok(called);
    });

    test('a prefix is stripped', async () => {
        await serve(reader({ auth: 'none', engine: ctx.engine, prefix: '/api/v1/logs/' }), async (get) => {
            assert.equal((await get('/api/v1/logs/audit')).status, 200);
            assert.equal((await get('/audit')).status, 404);
            assert.equal((await get('/api/v1/logsaudit')).status, 404);
        });
    });
});

describe('routes', () => {
    let ctx;
    let h;
    before(async () => {
        ctx = await setup();
        h = reader({ auth: 'none', engine: ctx.engine, streams: { sys: ctx.sys, api: ctx.api } });
    });

    test('/audit returns snake_case rows, totals and completeness', async () => {
        await serve(h, async (get) => {
            const r = await get('/audit');
            assert.equal(r.status, 200);
            assert.equal(r.headers.get('content-type'), 'application/json');
            assert.equal(r.body.total, 3);
            assert.equal(r.body.limit, 100);
            assert.equal(r.body.offset, 0);
            assert.equal(r.body.completeness.audit, 'store');
            assert.ok('source_node_id' in r.body.rows[0]);
            assert.ok('monotonic_seq' in r.body.rows[0]);
        });
    });

    test('BigInt and non-ASCII values come back exact', async () => {
        await serve(h, async (get) => {
            const r = await get('/audit');
            assert.ok(r.text.includes('"big":1152921504606846976'));
            assert.ok(r.text.includes('Grüße, 世界'));
        });
    });

    test('/audit filters, and a since in another offset is made canonical', async () => {
        await serve(h, async (get) => {
            assert.equal((await get('/audit?actor=bob')).body.rows.length, 1);
            assert.equal((await get('/audit?tenant_id=tenant-b')).body.total, 1);
            const r = await get(`/audit?since=${encodeURIComponent('2026-08-21T15:30:02+05:30')}`);
            const want = ctx.store.rows.filter((x) => x.timestamp >= '2026-08-21T10:00:02.000000Z').length;
            assert.equal(r.body.rows.length, want);
            assert.equal(r.body.total, want);
            assert.deepEqual((await get('/audit?since=2026-08-21T10:00:02Z')).body.rows, r.body.rows);
        });
    });

    test('cursor and offset paging both work', async () => {
        await serve(h, async (get) => {
            const p1 = await get('/audit?limit=2');
            assert.equal(p1.body.rows.length, 2);
            assert.equal(p1.body.next_after, p1.body.rows[1].monotonic_seq);
            const p2 = await get(`/audit?limit=2&after=${p1.body.next_after}`);
            assert.equal(p2.body.rows.length, 1);
            const o = await get('/audit?limit=2&offset=2');
            assert.equal(o.body.rows.length, 1);
            assert.equal((await get('/audit?source_node_id=none')).body.next_after, null);
        });
    });

    test('bad parameters are 422s with the field named', async () => {
        await serve(h, async (get) => {
            for (const [path, re] of [
                ['/audit?limit=0', /limit must be between 1 and 1000/],
                ['/audit?limit=1001', /limit must be between 1 and 1000/],
                ['/audit?limit=x', /limit must be an integer/],
                ['/audit?offset=-1', /offset must be non-negative/],
                ['/audit?after=0', /after must be >= 1/],
                ['/audit?since=yesterday', /since must be RFC3339/],
                ['/audit?until=2026-13-01T00:00:00Z', /until must be RFC3339/],
                ['/sys?limit=1001', /limit must be between 1 and 1000/],
                ['/api?status=abc', /status must be an integer/],
                ['/correlate', /request_id is required/],
                ['/correlate?request_id=', /request_id is required/],
                ['/search?since=2026-01-01T00:00:00Z', /q is required/],
                ['/search?q=x', /since is required/],
                ['/search?q=x&since=2026-01-01T00:00:00Z&limit=201', /limit must be between 1 and 200/],
                ['/sys?q=', /q must not be empty/],
                [`/sys?q=${'a'.repeat(1025)}`, /at most 1024 characters/],
                ['/topology?since=nope', /since must be RFC3339/],
            ]) {
                const r = await get(path);
                assert.equal(r.status, 422, path);
                assert.match(r.body.detail, re, path);
            }
        });
    });

    test('/sys and /api read the stream stores', async () => {
        await serve(h, async (get) => {
            const s = await get('/sys?level=error');
            assert.deepEqual(s.body.rows.map((x) => x.event), ['crash needle']);
            assert.equal(s.body.completeness.sys, 'store');
            const a = await get('/api?status=500');
            assert.deepEqual(a.body.rows.map((x) => x.path), ['/b']);
            assert.equal((await get('/sys?limit=1')).body.rows.length, 1);
        });
    });

    test('/api refuses q=', async () => {
        await serve(h, async (get) => {
            const r = await get('/api?q=x');
            assert.equal(r.status, 400);
            assert.match(r.body.detail, /not accepted on \/api/);
        });
    });

    test('/sys q= needs search on, a since, and no filters', async () => {
        await serve(h, async (get) => {
            assert.match((await get('/sys?q=needle')).body.error, /requires a 'since' bound/);
            const r = await get('/sys?q=needle&since=2026-01-01T00:00:00Z&level=info');
            assert.equal(r.status, 400);
            assert.match(r.body.detail, /cannot be combined with structured filters \(level\)/);
            const ok = await get('/sys?q=crash&since=2026-01-01T00:00:00Z');
            assert.deepEqual(ok.body.rows.map((x) => x.event), ['crash needle']);
        });
        const off = await setup({ searchEnabled: false });
        await serve(reader({ auth: 'none', engine: off.engine, streams: { sys: off.sys } }), async (get) => {
            assert.match((await get('/sys?q=x&since=2026-01-01T00:00:00Z')).body.error, /^search disabled/);
        });
    });

    test('/search covers the streams in order, with errors for those without a store', async () => {
        await serve(reader({ auth: 'none', engine: ctx.engine, streams: { sys: ctx.sys } }), async (get) => {
            const r = await get('/search?q=needle&since=2026-01-01T00:00:00Z&streams=audit,api,sys');
            assert.deepEqual([...new Set(r.body.matches.map((m) => m.stream))], ['sys', 'audit']);
            assert.equal(r.body.counts.api, 0);
            assert.equal(r.body.errors.api, 'requires api persistence: configure an api store');
            assert.equal(r.body.completeness.api, 'ring');
            const audit = r.body.matches.find((m) => m.stream === 'audit');
            assert.equal(audit.summary, 'USER_CREATED');
            assert.ok(audit.row.id);
            const bad = await get('/search?q=x&since=2026-01-01T00:00:00Z&streams=sys,bogus');
            assert.equal(bad.status, 400);
            assert.equal(bad.body.detail, "streams=['bogus', 'sys']: unknown stream(s) ['bogus']. Valid: ['api', 'audit', 'sys'].");
            const empty = await get('/search?q=x&since=');
            assert.match(empty.body.error, /requires a 'since' bound/);
        });
    });

    test('/correlate joins the streams with counts, totals and truncation', async () => {
        await serve(h, async (get) => {
            const r = await get('/correlate?request_id=req-a&limit=1');
            assert.equal(r.body.request_id, 'req-a');
            assert.deepEqual(r.body.counts, { audit: 1, api: 1, sys: 1 });
            assert.deepEqual(r.body.totals, { audit: 2, api: 1, sys: 2 });
            assert.deepEqual(r.body.truncated, { audit: true, api: false, sys: true });
            assert.deepEqual(r.body.completeness, { audit: 'store', api: 'store', sys: 'store' });
        });
    });

    test('/topology groups the writers', async () => {
        await serve(h, async (get) => {
            const r = await get('/topology');
            assert.equal(r.body.nodes, 1);
            assert.equal(r.body.services, 1);
            assert.equal(r.body.tenants, 2);
            assert.equal(r.body.sources.reduce((n, x) => n + x.rows, 0), 3);
        });
    });

    test('without a store or streams the routes say so', async () => {
        const e = new Engine();
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            const a = await get('/audit');
            assert.equal(a.body.error, 'audit store not initialised — call fasten.init() first');
            assert.equal(a.body.completeness.audit, 'ring');
            assert.equal((await get('/sys')).body.error, 'transport not initialised — call fasten.init() first');
            assert.equal((await get('/topology')).body.error, 'audit store not initialised — call fasten.init() first');
            const c = await get('/correlate?request_id=x');
            assert.deepEqual(c.body.totals, { audit: null, api: 0, sys: 0 });
        });
    });

    test('the engine rings serve sys rows without a store', async () => {
        const e = new Engine();
        await captureLines(() => {
            e.init({ serviceId: 'svc', nodeId: 'n1' });
            e.log.info('ring_event', { k: 1 });
        });
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            const r = await get('/sys?event=ring_event');
            assert.equal(r.body.rows.length, 1);
            assert.equal(r.body.completeness.sys, 'ring');
            const d = await get('/audit/doctor');
            assert.ok(d.body.transport.syslog_ring_depth >= 1);
        });
        await e.resetForTests();
    });

    test('a store error is a 500 logged by type only', async () => {
        const store = new MemoryAuditStore();
        store.query = () => { throw Object.assign(new Error('row value secret-123'), { name: 'PgError' }); };
        const { err } = await captureLines(() => serve(reader({ auth: 'none', engine: ctx.engine, store }), async (get) => {
            const r = await get('/audit');
            assert.equal(r.status, 500);
            assert.deepEqual(r.body, { detail: 'internal error' });
        }));
        const line = err.find((l) => l.includes('reader_query_failed'));
        assert.ok(line.includes('"error_type":"PgError"'));
        assert.ok(!err.join('').includes('secret-123'));
    });

    test('a degraded stream store says so', async () => {
        const sys = new MemoryStreamStore();
        sys.noteWriteFailure();
        await serve(reader({ auth: 'none', engine: ctx.engine, streams: { sys } }), async (get) => {
            assert.equal((await get('/sys')).body.completeness.sys, 'store-degraded');
        });
    });
});

describe('tenant scope', () => {
    let ctx;
    let h;
    before(async () => {
        ctx = await setup();
        h = reader({
            auth: 'none', engine: ctx.engine, streams: { sys: ctx.sys, api: ctx.api },
            tenantScope: (req) => req.headers['x-tenant'] ?? null, enforceTenantIsolation: true,
        });
    });
    const A = { 'x-tenant': 'tenant-a' };

    for (const path of ['/audit', '/audit/doctor', '/correlate?request_id=req-a', '/search?q=x&since=2026-01-01T00:00:00Z', '/sys', '/api', '/topology']) {
        test(`${path} is 401 without a tenant, or with a blank one`, async () => {
            await serve(h, async (get) => {
                for (const headers of [{}, { 'x-tenant': '' }]) {
                    const r = await get(path, headers);
                    assert.equal(r.status, 401);
                    assert.equal(r.body.detail, 'unauthenticated: tenant scope unresolved');
                }
            });
        });
    }

    test('/audit sees only its tenant and ignores ?tenant_id=', async () => {
        await serve(h, async (get) => {
            const r = await get('/audit?tenant_id=tenant-b', A);
            assert.equal(r.body.total, 2);
            assert.ok(r.body.rows.every((x) => x.tenant_id === 'tenant-a'));
        });
    });

    test('/correlate cannot reach another tenant by request_id', async () => {
        await serve(h, async (get) => {
            const r = await get('/correlate?request_id=req-b', A);
            assert.deepEqual(r.body.counts, { audit: 0, api: 0, sys: 0 });
            assert.deepEqual(r.body.totals, { audit: 0, api: 0, sys: 0 });
            const own = await get('/correlate?request_id=req-a', A);
            assert.deepEqual(own.body.counts, { audit: 2, api: 1, sys: 1 });
        });
    });

    test('/sys and /api leave out other tenants and rows without one', async () => {
        await serve(h, async (get) => {
            assert.deepEqual((await get('/sys', A)).body.rows.map((x) => x.event), ['login needle']);
            assert.deepEqual((await get('/api', A)).body.rows.map((x) => x.path), ['/a']);
        });
    });

    test('/search is scoped on every stream', async () => {
        await serve(h, async (get) => {
            const r = await get('/search?q=needle&since=2026-01-01T00:00:00Z&streams=sys,api,audit', A);
            assert.ok(r.body.matches.length > 0);
            assert.ok(r.body.matches.every((m) => m.row.tenant_id === 'tenant-a'));
        });
    });

    test('/topology lists only its tenant', async () => {
        await serve(h, async (get) => {
            const r = await get('/topology', A);
            assert.equal(r.body.tenants, 1);
            assert.ok(r.body.sources.every((x) => x.tenant_id === 'tenant-a'));
        });
    });

    test('the doctor counts its rows and hides the host tenant', async () => {
        await serve(h, async (get) => {
            const r = await get('/audit/doctor', A);
            assert.equal(r.body.store.rows, 2);
            assert.equal(r.body.init.tenant_id, null);
            assert.equal(r.body.chain.verified, true);
        });
    });

    test('the doctor hides the broken row from a scoped caller', async () => {
        const c = await setup();
        c.store.rows.find((r) => r.tenant_id === 'tenant-b').detail_commitment = 'f'.repeat(64);
        const scoped = reader({ auth: 'none', engine: c.engine, tenantScope: (req) => req.headers['x-tenant'] ?? null });
        await serve(scoped, async (get) => {
            const r = await get('/audit/doctor', A);
            assert.equal(r.body.chain.verified, false);
            assert.equal(r.body.chain.breaks, 1);
            assert.equal(r.body.chain.first_break_at, null);
            assert.equal(r.body.chain.reason, "chain break in this node's recent rows");
            assert.ok(!JSON.stringify(r.body).includes(c.store.rows[1].id));
        });
    });
});

describe('doctor', () => {
    test('a clean chain verifies', async () => {
        const c = await setup();
        await serve(reader({ auth: 'none', engine: c.engine }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.store.kind, 'MemoryAuditStore');
            assert.equal(r.body.store.reachable, true);
            assert.equal(r.body.store.rows, 3);
            assert.deepEqual(
                { verified: r.body.chain.verified, breaks: r.body.chain.breaks, reason: r.body.chain.reason, chain_unavailable: r.body.chain.chain_unavailable },
                { verified: true, breaks: 0, reason: null, chain_unavailable: false });
            assert.match(r.body.chain.last_verified_at, /\.\d{6}Z$/);
            assert.equal(r.body.init.service_id, 'svc');
            assert.equal(r.body.init.node_id, 'n1');
            assert.equal(r.body.init.tenant_id, 'host-tenant');
            assert.equal(r.body.init.failure_strategy, 'raise');
            assert.equal(r.body.init.worker_pid, process.pid);
            assert.equal(r.body.queue, null);
            assert.equal(r.body.redactor.active, true);
        });
    });

    test('a tampered row is reported at its seq', async () => {
        const c = await setup();
        c.store.rows[1].actor = 'mallory';
        await serve(reader({ auth: 'none', engine: c.engine }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.chain.verified, false);
            assert.equal(r.body.chain.breaks, 1);
            assert.equal(r.body.chain.first_break_at, 2);
            assert.match(r.body.chain.reason, /hash/);
        });
    });

    test('no rows means not checked, not clean', async () => {
        const store = new MemoryAuditStore();
        const e = new Engine();
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n1', auditStore: store, auditStoreFailureStrategy: 'raise' }));
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.chain.verified, null);
            assert.equal(r.body.chain.breaks, null);
        });
    });

    test('a failing check is reported with a fixed text and logged by type', async () => {
        const c = await setup();
        c.store.chainTail = () => { throw Object.assign(new Error('host db.internal user fasten'), { name: 'PgError' }); };
        c.store.count = () => { throw Object.assign(new Error('host db.internal'), { name: 'PgError' }); };
        const { err } = await captureLines(() => serve(reader({ auth: 'none', engine: c.engine }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.store.reachable, false);
            assert.equal(r.body.store.last_error, 'store check failed; see the service log');
            assert.equal(r.body.chain.verified, null);
            assert.equal(r.body.chain.error, 'PgError');
            assert.equal(r.body.chain.reason, 'chain check failed; see the service log');
        }));
        assert.ok(!err.join('').includes('db.internal'));
        assert.equal(err.filter((l) => l.includes('doctor_check_failed')).length, 2);
    });

    test('the doctor samples by seq after a clock step back', async () => {
        const c = await setup();
        c.store.insert(auditRow({ timestamp: '2020-01-01T00:00:00.000000Z' }));
        c.store.insert(auditRow());
        await serve(reader({ auth: 'none', engine: c.engine }), async (get) => {
            assert.equal((await get('/audit/doctor')).body.chain.verified, true);
        });
    });

    test('a store that does not seal is never verified', async () => {
        const store = new MemoryAuditStore();
        store.insert(auditRow());
        store.seals = () => false;
        const e = new Engine();
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n1', auditStore: store, auditStoreFailureStrategy: 'raise' }));
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.chain.chain_unavailable, true);
            assert.equal(r.body.chain.verified, false);
            assert.equal(r.body.chain.breaks, null);
        });
    });

    test('queue errors show their type only', async () => {
        const store = new MemoryAuditStore();
        const e = new Engine();
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n1', auditStore: store }));
        e._drainer._lastError = 'PgError: duplicate key value (id)=(secret)';
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.queue.last_error, 'PgError');
        });
        await e.resetForTests();
    });
});

after(() => {});
