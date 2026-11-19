/**
 * The reader and the stream stores against Postgres.
 *
 * Set FASTEN_TEST_POSTGRES_DSN to run; FASTEN_REQUIRE_POSTGRES=1 makes a
 * missing DSN a failure.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Engine, register, withRequestID } from '../src/index.js';
import { reader } from '../src/reader.js';
import { PostgresStore } from '../src/store/postgres.js';
import { PostgresStreamStore } from '../src/store/stream_postgres.js';
import { captureLines, serve } from './reader_fixtures.mjs';

const DSN = process.env.FASTEN_TEST_POSTGRES_DSN;
const skip = !DSN;

test('Postgres is configured when it is required', () => {
    assert.ok(!skip || process.env.FASTEN_REQUIRE_POSTGRES !== '1',
        'FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set');
});

const suffix = randomUUID().replace(/-/g, '').slice(0, 10);
const tables = [];
function table(name) {
    const t = `${name}_${suffix}`;
    tables.push(t);
    return t;
}

let pool;
before(async () => {
    if (skip) return;
    const { default: pg } = await import('pg');
    pool = new pg.Pool({ connectionString: DSN });
});
after(async () => {
    if (skip) return;
    for (const t of tables) await pool.query(`DROP TABLE IF EXISTS ${t}`);
    await pool.query(`DROP SCHEMA IF EXISTS s_${suffix} CASCADE`);
    await pool.end();
});

describe('PostgresStreamStore', { skip }, () => {
    test('needs a safe table name', () => {
        assert.throws(() => new PostgresStreamStore(DSN, {}), /table name is required/);
        assert.throws(() => new PostgresStreamStore(DSN, { table: 'a;b' }), /not a valid SQL identifier/);
    });

    test('query, count, search, purge', async () => {
        const s = new PostgresStreamStore(DSN, { table: table('api_log') });
        await s.insert({ method: 'GET', path: '/a', status: 200, request_id: 'r1', service_id: 'svc', timestamp: '2026-01-01T00:00:00.000000Z', note: 'Grüße 100%' });
        await s.insert({ method: 'POST', path: '/b', status: '500', request_id: 'r2', timestamp: '2026-01-02T00:00:00.000000Z', big: 2n ** 60n });
        await s.insert({ method: 'GET', path: '/c', status: 'n/a', request_id: 'r3' });
        assert.deepEqual((await s.query()).map((r) => r.path), ['/c', '/b', '/a']);
        assert.deepEqual((await s.query({ status: 500 })).map((r) => r.path), ['/b']);
        assert.deepEqual(await s.query({ method: 'get' }), []);
        assert.equal(await s.countMatching({ method: 'GET' }), 2);
        assert.deepEqual((await s.query({ since: '2026-01-02T00:00:00.000000Z' })).map((r) => r.path), ['/b']);
        assert.deepEqual((await s.query({ until: '2026-01-01T00:00:00.000000Z' })).map((r) => r.path), ['/c', '/a']);
        assert.equal((await s.query({ path: '/b' }))[0].big, 2n ** 60n);
        assert.deepEqual((await s.search({ q: '100%', since: '2026' })).map((r) => r.path), ['/a']);
        assert.deepEqual((await s.search({ q: 'grüße', since: '' })).map((r) => r.path), ['/a']);
        assert.deepEqual(await s.search({ q: 'x_y', since: '' }), []);
        assert.equal(await s.purge({ before: new Date('2026-01-02T00:00:00Z') }), 1);
        assert.equal(await s.count(), 2);
        const raw = await pool.query(`SELECT status, payload FROM ${s._table} ORDER BY seq`);
        assert.deepEqual(raw.rows.map((r) => r.status), [500, null]);
        assert.ok(raw.rows[0].payload.includes('1152921504606846976'));
        await s.close();
    });

    test('a schema-qualified table and a pool of the caller', async () => {
        const t = `s_${suffix}.syslog`;
        const s = new PostgresStreamStore(pool, { table: t });
        await Promise.all(Array.from({ length: 30 }, (_, i) => s.insert({ event: `e${i}`, level: 'info' })));
        assert.deepEqual((await s.query({ limit: 30 })).map((r) => r.event).reverse(),
            Array.from({ length: 30 }, (_, i) => `e${i}`));
        await s.close();
        assert.equal((await pool.query('SELECT 1 AS one')).rows[0].one, 1);
    });
});

describe('engine and reader on Postgres', { skip }, () => {
    let audit;
    let api;
    let sys;
    let engine;
    let rows;

    before(async () => {
        register('pgr', { PGR_EVENT: { domain: 'pgr', action: 'do', severity: 'info' } });
        audit = new PostgresStore(DSN, { table: table('audit') });
        api = new PostgresStreamStore(DSN, { table: table('api_log') });
        sys = new PostgresStreamStore(DSN, { table: table('syslog') });
        engine = new Engine();
        rows = [];
        await captureLines(async () => {
            engine.init({
                serviceId: 'svc', nodeId: 'node-pg', tenantId: 'tenant-a', auditStore: audit,
                apiStore: api, syslogStore: sys, persistStreams: ['api', 'sys'],
                auditStoreFailureStrategy: 'raise', searchEnabled: true,
            });
            // Numbers JS writes differently from Python, so the doctor must
            // read the detail text as stored.
            for (const detail of [{ a: 5e-5 }, { b: 1e16 }, { c: 2n ** 60n, s: 'Grüße 世界' }, { d: -0 }, { e: 1.5 }]) {
                rows.push(await withRequestID('req-pg', () => engine.emit({ code: 'PGR_EVENT', target: 't', detail })));
            }
            withRequestID('req-pg', () => {
                engine.log.warn('pg_sys_event', { password: 'p', note: 'needle' });
                engine.writeApi({ method: 'GET', path: '/x', status: 200, request_id: 'req-pg' });
            });
            await engine.flush();
        });
    });

    after(async () => {
        await engine.resetForTests();
        await audit.close();
        await api.close();
        await sys.close();
    });

    test('stream rows are stored redacted', async () => {
        const s = await sys.query({ event: 'pg_sys_event' });
        assert.equal(s.length, 1);
        assert.equal(s[0].password, '***');
        assert.equal(s[0].request_id, 'req-pg');
        assert.equal((await api.query({ requestId: 'req-pg' })).length, 1);
    });

    test('the doctor verifies the stored chain', async () => {
        await serve(reader({ auth: 'none', engine }), async (get) => {
            const r = await get('/audit/doctor');
            assert.equal(r.body.store.kind, 'PostgresStore');
            assert.equal(r.body.store.rows, rows.length);
            assert.equal(r.body.chain.verified, true, JSON.stringify(r.body.chain));
            assert.equal(r.body.chain.breaks, 0);
        });
    });

    test('/audit, /correlate, /search, /topology read the tables', async () => {
        await serve(reader({ auth: 'none', engine }), async (get) => {
            const a = await get('/audit?limit=2');
            assert.equal(a.body.total, rows.length);
            assert.equal(a.body.next_after, a.body.rows[1].monotonic_seq);
            const a2 = await get(`/audit?limit=10&after=${a.body.next_after}`);
            assert.equal(a2.body.rows.length, rows.length - 2);
            assert.ok(a.text.includes('Grüße 世界') || a2.text.includes('Grüße 世界'));
            assert.ok((a.text + a2.text).includes('"c":1152921504606846976'));
            const c = await get('/correlate?request_id=req-pg');
            assert.deepEqual(c.body.counts, { audit: rows.length, api: 1, sys: 1 });
            assert.deepEqual(c.body.completeness, { audit: 'store', api: 'store', sys: 'store' });
            const s = await get('/search?q=GRÜSSE&since=2026-01-01T00:00:00Z&streams=audit,sys');
            assert.equal(s.body.counts.audit, 0);
            const s2 = await get('/search?q=needle&since=2026-01-01T00:00:00Z&streams=sys,api');
            assert.equal(s2.body.counts.sys, 1);
            assert.equal(s2.body.counts.api, 0);
            const t = await get('/topology');
            assert.deepEqual(t.body.sources.map((x) => [x.source_node_id, x.tenant_id, x.rows]), [['node-pg', 'tenant-a', rows.length]]);
        });
    });

    test('a scoped caller of another tenant sees nothing', async () => {
        await serve(reader({ auth: 'none', engine, tenantScope: () => 'tenant-b' }), async (get) => {
            assert.equal((await get('/audit')).body.total, 0);
            assert.deepEqual((await get('/correlate?request_id=req-pg')).body.counts, { audit: 0, api: 0, sys: 0 });
            assert.equal((await get('/topology')).body.sources.length, 0);
            assert.equal((await get('/audit/doctor')).body.store.rows, 0);
        });
    });

    test('a tampered row breaks the doctor, hidden from a scoped caller', async () => {
        const victim = rows[2];
        await pool.query(`UPDATE ${audit._table} SET actor = 'mallory' WHERE id = $1`, [victim.id]);
        try {
            await serve(reader({ auth: 'none', engine }), async (get) => {
                const r = await get('/audit/doctor');
                assert.equal(r.body.chain.verified, false);
                assert.equal(r.body.chain.first_break_at, victim.monotonic_seq);
            });
            await serve(reader({ auth: 'none', engine, tenantScope: () => 'tenant-b' }), async (get) => {
                const r = await get('/audit/doctor');
                assert.equal(r.body.chain.verified, false);
                assert.equal(r.body.chain.first_break_at, null);
                assert.ok(!r.text.includes(victim.id));
            });
        } finally {
            await pool.query(`UPDATE ${audit._table} SET actor = $2 WHERE id = $1`, [victim.id, victim.actor]);
        }
    });

    test('a failed stream write keeps the line and degrades the stream', async () => {
        const t = table('syslog_gone');
        const gone = new PostgresStreamStore(DSN, { table: t });
        await gone.init();
        const e = new Engine();
        const { out, err } = await captureLines(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n2', syslogStore: gone });
            await e.flush();
            await pool.query(`DROP TABLE ${t}`);
            e.log.info('lost_event', { v: 'row-value-xyz' });
            await e.flush();
            await gone.init();
        });
        assert.ok(out.some((l) => l.includes('lost_event')));
        assert.ok(gone.degraded);
        assert.ok(err.some((l) => /^fasten: syslog persist failed: \w+\n$/.test(l)));
        assert.ok(!err.some((l) => l.startsWith('fasten:') && l.includes('row-value-xyz')));
        await serve(reader({ auth: 'none', engine: e }), async (get) => {
            assert.equal((await get('/sys')).body.completeness.sys, 'store-degraded');
        });
        await e.resetForTests();
        await gone.close();
    });
});
