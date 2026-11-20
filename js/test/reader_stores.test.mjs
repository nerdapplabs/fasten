/**
 * The reader over the bundled stores: Postgres and SQLite.
 *
 * Set FASTEN_TEST_POSTGRES_DSN to run the Postgres half;
 * FASTEN_REQUIRE_POSTGRES=1 makes a missing DSN a failure. The SQLite half
 * always runs.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Engine, register, withRequestID } from '../src/index.js';
import { reader } from '../src/reader.js';
import { PostgresStore } from '../src/store/postgres.js';
import { SqliteStore } from '../src/store/sqlite.js';
import { PostgresStreamStore } from '../src/store/stream_postgres.js';
import { SqliteStreamStore } from '../src/store/stream_sqlite.js';
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

    test('an INSERT whose answer was lost is not run again, so the row is stored once', async () => {
        const { default: pg } = await import('pg');
        const own = new pg.Pool({ connectionString: DSN });
        const query = own.query.bind(own);
        let inserts = 0;
        // The first INSERT commits, then its connection is reported lost.
        own.query = async (...args) => {
            const res = await query(...args);
            if (/^INSERT/.test(String(args[0])) && ++inserts === 1) {
                throw Object.assign(new Error('terminating connection due to administrator command'),
                    { code: '57P01', severity: 'FATAL' });
            }
            return res;
        };
        const s = new PostgresStreamStore(own, { table: table('api_once') });
        try {
            await assert.rejects(s.insert({ method: 'GET', path: '/once' }), (err) => err.code === '57P01');
            assert.equal(inserts, 1);
            assert.equal(await s.count(), 1);
            await s.insert({ method: 'GET', path: '/next' });
            assert.equal(await s.count(), 2);
        } finally {
            await own.end();
        }
    });

    test('through the engine, that failed write marks the stream degraded', async () => {
        const { default: pg } = await import('pg');
        const own = new pg.Pool({ connectionString: DSN });
        const query = own.query.bind(own);
        let inserts = 0;
        own.query = async (...args) => {
            const res = await query(...args);
            if (/^INSERT/.test(String(args[0])) && ++inserts === 1) {
                throw Object.assign(new Error('terminating connection'), { code: '57P01', severity: 'FATAL' });
            }
            return res;
        };
        const s = new PostgresStreamStore(own, { table: table('api_once_e') });
        const e = new Engine();
        try {
            const { err } = await captureLines(async () => {
                e.init({ serviceId: 'svc', nodeId: 'n', apiStore: s });
                e.pushApi({ method: 'GET', path: '/x' });
                await e.flush();
            });
            assert.ok(err.includes('fasten: api persist failed: Error\n'), JSON.stringify(err));
            assert.equal(e._readerState().streams.api.source(), 'store-degraded');
            assert.equal(await s.count(), 1);
        } finally {
            await e.resetForTests();
            await own.end();
        }
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

register('pgr', { PGR_EVENT: { domain: 'pgr', action: 'do', severity: 'info' } });

// The engine and the reader over one backend. `backend()` opens its stores
// and says how to reach under them:
//   { kind, audit, api, sys, setActor(id, actor), goneStream() }
// goneStream() resolves { store, drop(), restore() } for a sys store whose
// table can be dropped from under it.
function readerSuite(label, { skip: skipIt = false, backend }) {
    describe(`engine and reader on ${label}`, { skip: skipIt }, () => {
        let be;
        let audit;
        let api;
        let sys;
        let engine;
        let rows;

        before(async () => {
            be = await backend();
            ({ audit, api, sys } = be);
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
            await be.close?.();
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
                assert.equal(r.body.store.kind, be.kind);
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
                const s1 = await get('/search?q=1152921504606846976&since=2026-01-01T00:00:00Z&streams=audit');
                assert.equal(s1.body.counts.audit, 1);
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
            await be.setActor(victim.id, 'mallory');
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
                await be.setActor(victim.id, victim.actor);
            }
        });

        test('a failed stream write keeps the line and degrades the stream', async () => {
            const { store: gone, drop, restore } = await be.goneStream();
            const e = new Engine();
            const { out, err } = await captureLines(async () => {
                e.init({ serviceId: 'svc', nodeId: 'n2', syslogStore: gone });
                await e.flush();
                await drop();
                e.log.info('lost_event', { v: 'row-value-xyz' });
                await e.flush();
                await restore();
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

        // Last: it adds another tenant's rows to the tables.
        test('a scoped caller sees exactly its own rows beside another tenant', async () => {
            const b = new Engine();
            await captureLines(async () => {
                b.init({
                    serviceId: 'svc-b', nodeId: 'node-b', tenantId: 'tenant-b', auditStore: audit,
                    apiStore: api, syslogStore: sys, auditStoreFailureStrategy: 'raise',
                    searchEnabled: true,
                });
                for (const rid of ['req-pg', 'req-b']) {
                    await withRequestID(rid, () => b.emit({ code: 'PGR_EVENT', target: 't', detail: { note: 'needle b' } }));
                }
                withRequestID('req-pg', () => {
                    b.log.info('b_sys_event', { tenant_id: 'tenant-b', note: 'needle' });
                    b.writeApi({ method: 'GET', path: '/b', status: 200, request_id: 'req-pg', tenant_id: 'tenant-b', note: 'needle', timestamp: '2026-09-01T00:00:00.000000Z' });
                    engine.log.info('a_sys_event', { tenant_id: 'tenant-a', note: 'needle' });
                    engine.writeApi({ method: 'GET', path: '/a', status: 201, request_id: 'req-pg', tenant_id: 'tenant-a', note: 'needle', timestamp: '2026-09-01T00:00:00.000000Z' });
                });
                await b.flush();
                await engine.flush();
            });
            try {
                await serve(reader({ auth: 'none', engine, tenantScope: () => 'tenant-a' }), async (get) => {
                    const a = await get('/audit?limit=100');
                    assert.equal(a.body.total, rows.length);
                    assert.deepEqual(a.body.rows.map((r) => r.id).sort(), rows.map((r) => r.id).sort());
                    const c = await get('/correlate?request_id=req-pg');
                    assert.deepEqual(c.body.counts, { audit: rows.length, api: 1, sys: 1 });
                    assert.deepEqual(c.body.totals, { audit: rows.length, api: 1, sys: 1 });
                    assert.deepEqual(c.body.truncated, { audit: false, api: false, sys: false });
                    assert.equal(c.body.sys[0].event, 'a_sys_event');
                    assert.equal(c.body.api[0].path, '/a');
                    const t = await get('/topology');
                    assert.deepEqual(t.body.sources.map((x) => [x.source_node_id, x.tenant_id, x.rows]),
                        [['node-pg', 'tenant-a', rows.length]]);
                    const s = await get('/search?q=needle&since=2026-01-01T00:00:00Z&streams=sys,api,audit');
                    assert.deepEqual(s.body.counts, { sys: 1, api: 1, audit: 0 });
                    assert.ok(s.body.matches.every((m) => m.row.tenant_id === 'tenant-a'));
                    assert.deepEqual((await get('/sys')).body.rows.map((r) => r.event), ['a_sys_event']);
                    assert.deepEqual((await get('/api')).body.rows.map((r) => r.path), ['/a']);
                    assert.equal((await get('/audit/doctor')).body.store.rows, rows.length);
                });
                await serve(reader({ auth: 'none', engine, tenantScope: () => 'tenant-b' }), async (get) => {
                    assert.equal((await get('/audit')).body.total, 2);
                    assert.deepEqual((await get('/correlate?request_id=req-pg')).body.counts, { audit: 1, api: 1, sys: 1 });
                    const s = await get('/search?q=needle&since=2026-01-01T00:00:00Z&streams=audit');
                    assert.equal(s.body.counts.audit, 2);
                });
                const found = await audit.search({ q: 'needle', since: '2026-01-01T00:00:00.000000Z', tenantId: 'tenant-b' });
                assert.equal(found.length, 2);
                assert.ok(found.every((r) => r.tenant_id === 'tenant-b'));
                assert.deepEqual(await audit.search({ q: 'needle', since: '2026-01-01T00:00:00.000000Z', tenantId: 'tenant-a' }), []);
            } finally {
                await b.resetForTests();
            }
        });
    });
}

readerSuite('Postgres', {
    skip,
    backend: async () => ({
        kind: 'PostgresStore',
        audit: new PostgresStore(DSN, { table: table('audit') }),
        api: new PostgresStreamStore(DSN, { table: table('api_log') }),
        sys: new PostgresStreamStore(DSN, { table: table('syslog') }),
        async setActor(id, actor) {
            await pool.query(`UPDATE ${this.audit._table} SET actor = $2 WHERE id = $1`, [id, actor]);
        },
        async goneStream() {
            const t = table('syslog_gone');
            const store = new PostgresStreamStore(DSN, { table: t });
            await store.init();
            return { store, drop: () => pool.query(`DROP TABLE ${t}`), restore: () => store.init() };
        },
    }),
});

const DIR = mkdtempSync(join(tmpdir(), 'fasten-reader-'));
after(() => rmSync(DIR, { recursive: true, force: true }));

readerSuite('SQLite', {
    backend: async () => {
        const path = join(DIR, 'reader.db');
        const raw = new DatabaseSync(path);
        return {
            kind: 'SqliteStore',
            close: () => raw.close(),
            audit: new SqliteStore(path),
            api: new SqliteStreamStore(path, { table: 'api_log' }),
            sys: new SqliteStreamStore(path, { table: 'syslog' }),
            setActor(id, actor) {
                raw.prepare('UPDATE audit_log SET actor = ? WHERE id = ?').run(actor, id);
            },
            async goneStream() {
                const store = new SqliteStreamStore(path, { table: 'syslog_gone' });
                await store.init();
                return {
                    store,
                    drop: () => raw.exec('DROP TABLE syslog_gone'),
                    restore: async () => {
                        const again = new SqliteStreamStore(path, { table: 'syslog_gone' });
                        await again.init();
                        await again.close();
                    },
                };
            },
        };
    },
});

describe('the doctor across a re-init', () => {
    test('before the first emit, and after a re-init onto another sealing store', async () => {
        const first = new SqliteStore(':memory:');
        const second = new SqliteStore(':memory:');
        const e = new Engine();
        try {
            await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n-re', auditStore: first, auditStoreFailureStrategy: 'raise' }));
            await serve(reader({ auth: 'none', engine: e }), async (get) => {
                const r = (await get('/audit/doctor')).body;
                assert.equal(r.store.reachable, true);
                assert.equal(r.store.rows, 0);
                assert.deepEqual([r.chain.verified, r.chain.breaks, r.chain.chain_unavailable], [null, null, false]);
            });
            await captureLines(async () => {
                e.init({ serviceId: 'svc', nodeId: 'n-re', auditStore: second, auditStoreFailureStrategy: 'raise' });
                await e.emit({ code: 'PGR_EVENT', target: 't' });
                await e.emit({ code: 'PGR_EVENT', target: 't' });
            });
            await serve(reader({ auth: 'none', engine: e }), async (get) => {
                const r = (await get('/audit/doctor')).body;
                assert.equal(r.store.rows, 2);
                assert.deepEqual([r.chain.verified, r.chain.breaks, r.chain.sealed_rows], [true, 0, 2]);
            });
            assert.equal(await first.count(), 0);
        } finally {
            await e.resetForTests();
            await first.close();
            await second.close();
        }
    });
});

// The same rows in the ring, a SqliteStreamStore and a PostgresStreamStore
// read back the same through /sys and /api.
describe('/sys and /api agree across the ring and the stream stores', () => {
    const SYS = [
        { level: 'info', event: 'cmp_a', request_id: 'r1', timestamp: '2025-01-01T00:00:00.000000Z' },
        { level: 'error', event: 'cmp_b', request_id: 'r2' },
        { level: 'error', event: 'cmp_c', request_id: 'r3', timestamp: '2025-01-03T00:00:00.000000Z' },
        { level: 'info', event: 'cmp_d', request_id: 'r4', timestamp: '2025-01-04T00:00:00.000000Z' },
    ];
    const API = [
        { method: 'GET', path: '/a', status: 200, request_id: 'r1', timestamp: '2025-01-01T00:00:00.000000Z' },
        { method: 'POST', path: '/b', status: 500, request_id: 'r2' },
        { method: 'GET', path: '/c', status: '500', request_id: 'r3', timestamp: '2025-01-03T00:00:00.000000Z' },
        { method: 'GET', path: '/d', status: 500, request_id: 'r4', timestamp: '2025-01-05T00:00:00.000000Z' },
    ];
    const QUERIES = [
        '/sys?until=2025-01-03T00:00:00Z', '/sys?since=2025-01-02T00:00:00Z', '/sys?level=error',
        '/sys?level=error&since=2025-01-01T00:00:00Z', '/sys?limit=2', '/sys?until=2025-01-02T00:00:00Z&limit=1',
        '/api?status=500', '/api?status=500&since=2025-01-02T00:00:00Z', '/api?until=2025-01-02T00:00:00Z',
        '/api?limit=2', '/api?status=500&limit=1', '/api?method=GET&until=2025-01-04T00:00:00Z',
    ];

    async function readAll(streams) {
        const e = new Engine();
        const out = {};
        try {
            await captureLines(async () => {
                e.init({ serviceId: 'svc', nodeId: 'n-cmp', apiStore: streams?.api, syslogStore: streams?.sys });
                for (const r of SYS) e.pushSyslog(r);
                for (const r of API) e.pushApi(r);
                await e.flush();
            });
            await serve(reader({ auth: 'none', engine: e }), async (get) => {
                for (const q of QUERIES) {
                    // Only these rows: the init writes sys lines of its own.
                    out[q] = (await get(q)).body.rows.filter((r) => /^(cmp_|$)/.test(r.event ?? '') && r.request_id?.startsWith('r'));
                }
            });
        } finally {
            await e.resetForTests();
        }
        return out;
    }

    test('ring and SqliteStreamStore', async () => {
        const ring = await readAll(null);
        const sqlite = {
            api: new SqliteStreamStore(':memory:', { table: 'api_log' }),
            sys: new SqliteStreamStore(':memory:', { table: 'syslog' }),
        };
        const fromSqlite = await readAll(sqlite);
        assert.deepEqual(fromSqlite, ring);
        assert.deepEqual(ring['/api?status=500'].map((r) => r.path), ['/d', '/c', '/b']);
        assert.deepEqual(ring['/sys?until=2025-01-03T00:00:00Z'].map((r) => r.event), ['cmp_c', 'cmp_b', 'cmp_a']);
        assert.deepEqual(ring['/sys?since=2025-01-02T00:00:00Z'].map((r) => r.event), ['cmp_d', 'cmp_c']);
        if (!skip) {
            const pg = {
                api: new PostgresStreamStore(DSN, { table: table('cmp_api') }),
                sys: new PostgresStreamStore(DSN, { table: table('cmp_sys') }),
            };
            try {
                assert.deepEqual(await readAll(pg), ring);
            } finally {
                await pg.api.close();
                await pg.sys.close();
            }
        }
        await sqlite.api.close();
        await sqlite.sys.close();
    });
});
