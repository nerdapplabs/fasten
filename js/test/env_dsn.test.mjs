/**
 * Stores opened from FASTEN_AUDIT_DSN, FASTEN_API_DSN and FASTEN_SYSLOG_DSN,
 * with the DSN forms and precedence of the Python SDK. The Postgres cases
 * that connect need FASTEN_TEST_POSTGRES_DSN.
 */
import { test, describe, afterEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Engine, register, verifyChain } from '../src/index.js';
import { PostgresStore } from '../src/store/postgres.js';
import { SqliteStore } from '../src/store/sqlite.js';
import { PostgresStreamStore } from '../src/store/stream_postgres.js';
import { SqliteStreamStore } from '../src/store/stream_sqlite.js';
import { captureLines } from './reader_fixtures.mjs';

const PG = process.env.FASTEN_TEST_POSTGRES_DSN;
const VARS = ['FASTEN_AUDIT_DSN', 'FASTEN_API_DSN', 'FASTEN_SYSLOG_DSN'];
const saved = Object.fromEntries(VARS.map((v) => [v, process.env[v]]));
const DIR = mkdtempSync(join(tmpdir(), 'fasten-env-dsn-'));
const engines = [];

register('envdsn', { ENVDSN_EVENT: { domain: 'envdsn', action: 'do', severity: 'info' } });

function setEnv(vars) {
    for (const v of VARS) delete process.env[v];
    Object.assign(process.env, vars);
}

async function init(opts = {}) {
    const e = new Engine();
    engines.push(e);
    await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'node-env', auditStoreFailureStrategy: 'raise', ...opts }));
    return e;
}

afterEach(async () => {
    for (const e of engines.splice(0)) {
        const stores = [e.auditStore(), ...Object.values(e._readerState().streams ?? {}).map((s) => s.store)];
        await e.resetForTests();
        for (const s of stores) await s?.close?.();
    }
    setEnv({});
});

after(() => {
    setEnv(Object.fromEntries(Object.entries(saved).filter(([, v]) => v !== undefined)));
    rmSync(DIR, { recursive: true, force: true });
});

describe('FASTEN_AUDIT_DSN', () => {
    test('sqlite:////abs/path opens a SqliteStore that seals into the file', async () => {
        const path = join(DIR, `${randomUUID()}.db`);
        assert.ok(path.startsWith('/'));
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${path}` });
        const e = await init();
        assert.ok(e.auditStore() instanceof SqliteStore);
        let row;
        await captureLines(async () => {
            row = await e.emit({ code: 'ENVDSN_EVENT', target: 't' });
        });
        assert.equal(row.monotonic_seq, 1);
        const db = new DatabaseSync(path);
        const stored = db.prepare('SELECT id, hash FROM audit_log').all();
        db.close();
        assert.deepEqual(stored.map((r) => [r.id, r.hash]), [[row.id, row.hash]]);
        assert.ok(verifyChain(await e.auditStore().chainRows('node-env')).ok);
    });

    test('sqlite:///rel.db is relative to the working directory, a bare path is a path', async () => {
        const cwd = process.cwd();
        const dir = mkdtempSync(join(DIR, 'rel-'));
        process.chdir(dir);
        try {
            setEnv({ FASTEN_AUDIT_DSN: 'sqlite:///rel.db' });
            await init();
            assert.ok(existsSync(join(dir, 'rel.db')));
            setEnv({ FASTEN_AUDIT_DSN: join(dir, 'bare.db') });
            assert.ok((await init()).auditStore() instanceof SqliteStore);
            assert.ok(existsSync(join(dir, 'bare.db')));
        } finally {
            process.chdir(cwd);
        }
    });

    test('?table= names the table and ?wal=false turns WAL off', async () => {
        const path = join(DIR, `${randomUUID()}.db`);
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${path}?table=my_audit&wal=false` });
        const e = await init();
        await captureLines(() => e.emit({ code: 'ENVDSN_EVENT', target: 't' }));
        const db = new DatabaseSync(path);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM my_audit').get().n, 1);
        assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
        db.close();
    });

    test('a store passed in wins over the environment', async () => {
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${join(DIR, 'unused.db')}` });
        const mine = new SqliteStore(':memory:');
        const e = await init({ auditStore: mine });
        assert.equal(e.auditStore(), mine);
        assert.ok(!existsSync(join(DIR, 'unused.db')));
    });

    test('a re-init with the same DSN keeps the store', async () => {
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${join(DIR, `${randomUUID()}.db`)}` });
        const e = new Engine();
        engines.push(e);
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
        const first = e.auditStore();
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
        assert.equal(e.auditStore(), first);
    });

    test('postgres:// and postgresql:// open a PostgresStore; ?table= is taken off the DSN', async () => {
        for (const scheme of ['postgres', 'postgresql']) {
            setEnv({ FASTEN_AUDIT_DSN: `${scheme}://u:p@db.invalid:5432/x?sslmode=disable&table=aud_x` });
            const s = (await init()).auditStore();
            assert.ok(s instanceof PostgresStore);
            assert.equal(s._table, 'aud_x');
            assert.equal(s._connectionString, `${scheme}://u:p@db.invalid:5432/x?sslmode=disable`);
        }
    });

    test('a DSN without a path is an error', async () => {
        setEnv({ FASTEN_AUDIT_DSN: 'sqlite://' });
        await assert.rejects(init(), /^Error: fasten SqliteStore: the DSN has no path\. Audit storage must be durable/);
    });

    test('rows reach Postgres through a postgres:// DSN', { skip: !PG }, async () => {
        const table = `env_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
        setEnv({ FASTEN_AUDIT_DSN: `${PG}${PG.includes('?') ? '&' : '?'}table=${table}` });
        const e = await init();
        let row;
        await captureLines(async () => {
            row = await e.emit({ code: 'ENVDSN_EVENT', target: 't' });
        });
        assert.equal(row.monotonic_seq, 1);
        const rows = await e.auditStore().chainRows('node-env');
        assert.deepEqual(rows.map((r) => r.id), [row.id]);
        const { default: pg } = await import('pg');
        const admin = new pg.Pool({ connectionString: PG });
        await admin.query(`DROP TABLE ${table}`);
        await admin.end();
    });
});

describe('FASTEN_API_DSN and FASTEN_SYSLOG_DSN', () => {
    test('a sqlite DSN opens a SqliteStreamStore on api_log or syslog', async () => {
        const path = join(DIR, `${randomUUID()}.db`);
        setEnv({ FASTEN_API_DSN: `sqlite:///${path}`, FASTEN_SYSLOG_DSN: path });
        const e = await init();
        const { streams } = e._readerState();
        assert.ok(streams.api.store instanceof SqliteStreamStore);
        assert.ok(streams.sys.store instanceof SqliteStreamStore);
        assert.deepEqual([streams.api.store._table, streams.sys.store._table], ['api_log', 'syslog']);
        assert.deepEqual([...e.persistedStreams()].sort(), ['api', 'sys']);
        await captureLines(() => {
            e.log.info('env_event', {});
            e.writeApi({ method: 'GET', path: '/x', status: 200 });
        });
        assert.equal(streams.sys.store.countMatching({ event: 'env_event' }), 1);
        assert.equal(streams.api.store.countMatching({ path: '/x' }), 1);
    });

    test('?table= overrides the default table', async () => {
        setEnv({ FASTEN_SYSLOG_DSN: `sqlite:///${join(DIR, `${randomUUID()}.db`)}?table=my_sys` });
        const e = await init();
        assert.equal(e._readerState().streams.sys.store._table, 'my_sys');
        assert.equal(e._readerState().streams.api.store, null);
    });

    test('postgres:// opens a PostgresStreamStore', async () => {
        setEnv({ FASTEN_API_DSN: 'postgresql://u:p@db.invalid/x?table=my_api' });
        const s = (await init())._readerState().streams.api.store;
        assert.ok(s instanceof PostgresStreamStore);
        assert.equal(s._table, 'my_api');
        assert.equal(s._connectionString, 'postgresql://u:p@db.invalid/x');
    });

    test('stream stores passed in win over the environment', async () => {
        setEnv({ FASTEN_API_DSN: 'mysql://nope', FASTEN_SYSLOG_DSN: 'mysql://nope' });
        const api = new SqliteStreamStore(':memory:', { table: 'api_log' });
        const sys = new SqliteStreamStore(':memory:', { table: 'syslog' });
        const e = await init({ apiStore: api, syslogStore: sys });
        assert.equal(e._readerState().streams.api.store, api);
    });

    test('another scheme or no path is an error', async () => {
        setEnv({ FASTEN_SYSLOG_DSN: 'mysql://app:s3cret@db/x' });
        await assert.rejects(init(), (err) =>
            err.message === "fasten: stream DSN scheme 'mysql' not supported. Use sqlite:///./streams.db, postgres://..., or a bare filesystem path."
            && !err.message.includes('s3cret'));
        setEnv({ FASTEN_API_DSN: 'postgresql+psycopg://h/db' });
        await assert.rejects(init(), /stream DSN scheme 'postgresql\+psycopg' not supported/);
        setEnv({ FASTEN_API_DSN: 'sqlite://' });
        await assert.rejects(init(), /^Error: fasten: the stream DSN has no path\. Use sqlite:\/\/\/\.\/streams\.db$/);
    });
});
