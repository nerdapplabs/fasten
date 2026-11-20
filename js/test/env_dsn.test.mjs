/**
 * Stores opened from FASTEN_AUDIT_DSN, FASTEN_API_DSN and FASTEN_SYSLOG_DSN,
 * with the DSN forms and precedence of the Python SDK. The Postgres cases
 * that connect need FASTEN_TEST_POSTGRES_DSN.
 */
import { test, describe, afterEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
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
        assert.equal(await streams.sys.store.countMatching({ event: 'env_event' }), 1);
        assert.equal(await streams.api.store.countMatching({ path: '/x' }), 1);
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

describe('an audit DSN with an unknown scheme is an error, as a stream DSN is', () => {
    test('the error names the scheme only, and no file is created', async () => {
        const cwd = process.cwd();
        const dir = mkdtempSync(join(DIR, 'scheme-'));
        process.chdir(dir);
        try {
            for (const [dsn, scheme] of [
                ['mysql://app:s3cret@db/x', 'mysql'],
                ['Mysql://app:s3cret@db/x', 'mysql'],
                ['postgresql+psycopg://app:s3cret@db/x', 'postgresql+psycopg'],
                ['file:///tmp/s3cret.db', 'file'],
            ]) {
                setEnv({ FASTEN_AUDIT_DSN: dsn });
                await assert.rejects(init(), (err) =>
                    err.message === `fasten: audit DSN scheme '${scheme}' not supported. Use sqlite:///./audit.db, postgres://..., or a bare filesystem path.`
                    && !err.message.includes('s3cret'), dsn);
            }
            setEnv({ FASTEN_AUDIT_DSN: 'host=db.internal user=app password=s3cret dbname=x' });
            await assert.rejects(init(), (err) =>
                /^fasten: audit DSN in libpq keyword form not supported/.test(err.message)
                && !err.message.includes('s3cret') && !err.message.includes('db.internal'));
            setEnv({ FASTEN_SYSLOG_DSN: 'host=db.internal password=s3cret' });
            await assert.rejects(init(), /stream DSN in libpq keyword form not supported/);
            assert.deepEqual(readdirSync(dir), []);
        } finally {
            process.chdir(cwd);
        }
    });

    test('an upper-case postgres scheme opens a PostgresStore', async () => {
        setEnv({ FASTEN_AUDIT_DSN: 'POSTGRES://u:p@db.invalid/x' });
        assert.ok((await init()).auditStore() instanceof PostgresStore);
    });
});

describe('DSN parameters', () => {
    test('a fragment is dropped and the other parameters keep their order', async () => {
        setEnv({ FASTEN_AUDIT_DSN: 'postgres://u:p@db.invalid/x?sslmode=require&table=aud_f&application_name=a%20b&connect_timeout=5#frag' });
        const s = (await init()).auditStore();
        assert.equal(s._table, 'aud_f');
        assert.equal(s._connectionString, 'postgres://u:p@db.invalid/x?sslmode=require&application_name=a+b&connect_timeout=5#frag');
        const path = join(DIR, `${randomUUID()}.db`);
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${path}?table=frag_t#x` });
        assert.equal((await init()).auditStore()._table, 'frag_t');
        assert.ok(existsSync(path));
    });

    test('an empty ?table= is the default table, as Python reads it', async () => {
        setEnv({ FASTEN_AUDIT_DSN: 'postgres://u:p@db.invalid/x?table=' });
        assert.equal((await init()).auditStore()._table, 'audit_log');
        setEnv({ FASTEN_SYSLOG_DSN: `sqlite:///${join(DIR, `${randomUUID()}.db`)}?table=` });
        assert.equal((await init())._readerState().streams.sys.store._table, 'syslog');
    });

    test('an invalid ?table= is an error that does not quote the DSN', async () => {
        for (const dsn of ['postgres://u:s3cret@db.invalid/x?table=a;b', `sqlite:///${join(DIR, 's3cret.db')}?table=a-b`]) {
            setEnv({ FASTEN_AUDIT_DSN: dsn });
            await assert.rejects(init(), (err) =>
                /not a valid SQL identifier/.test(err.message) && !err.message.includes('s3cret'), dsn);
        }
    });
});

describe('the environment at init', () => {
    test('without an audit store, the line says which variable was read', async () => {
        setEnv({});
        const e = new Engine();
        engines.push(e);
        const { err } = await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
        const line = err.map((l) => JSON.parse(l)).find((r) => r.event === 'audit_chain_unavailable');
        assert.match(line.reason, /FASTEN_AUDIT_DSN unset/);
    });

    test('a set FASTEN_* variable named like a DSN but not read is reported once, without its value', async () => {
        process.env.FASTEN_AUDIT_DNS = 'postgres://u:s3cret@db/x';
        process.env.FASTEN_SYSLOG_URL = 'sqlite:///x.db';
        try {
            const e = new Engine();
            engines.push(e);
            const first = await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
            const warned = first.err.map((l) => JSON.parse(l)).filter((r) => r.event === 'env_dsn_not_read');
            assert.deepEqual(warned.map((r) => r.variable).sort(), ['FASTEN_AUDIT_DNS', 'FASTEN_SYSLOG_URL']);
            assert.equal(warned[0].level, 'warn');
            assert.ok(!first.err.join('').includes('s3cret'));
            const again = await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
            assert.ok(!again.err.some((l) => l.includes('env_dsn_not_read')));
        } finally {
            delete process.env.FASTEN_AUDIT_DNS;
            delete process.env.FASTEN_SYSLOG_URL;
        }
    });
});

describe('stores opened from the environment', () => {
    test('close() closes them after the stream writes settle, and a later init opens them again', async () => {
        const path = join(DIR, `${randomUUID()}.db`);
        setEnv({ FASTEN_AUDIT_DSN: `sqlite:///${path}`, FASTEN_SYSLOG_DSN: `sqlite:///${path}` });
        const e = new Engine();
        engines.push(e);
        let closed;
        await captureLines(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n' });
            e.emit({ code: 'ENVDSN_EVENT', target: 't' });
            e.log.info('before_close', {});
            closed = await e.close();
        });
        assert.equal(closed, true);
        const audit = e.auditStore();
        const sys = e._readerState().streams.sys.store;
        assert.equal(audit._db.isOpen, false);
        assert.equal(sys._db.isOpen, false);
        const db = new DatabaseSync(path);
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n, 1);
        assert.equal(db.prepare("SELECT COUNT(*) AS n FROM syslog WHERE event = 'before_close'").get().n, 1);
        db.close();
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
        assert.notEqual(e.auditStore(), audit);
        assert.equal(e.auditStore()._db.isOpen, true);
    });

    test('a re-init with another DSN closes the store it no longer uses', async () => {
        const [p1, p2] = [join(DIR, `${randomUUID()}.db`), join(DIR, `${randomUUID()}.db`)];
        setEnv({ FASTEN_SYSLOG_DSN: p1 });
        const e = new Engine();
        engines.push(e);
        await captureLines(() => e.init({ serviceId: 'svc', nodeId: 'n' }));
        const first = e._readerState().streams.sys.store;
        setEnv({ FASTEN_SYSLOG_DSN: p2 });
        await captureLines(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n' });
            await e.flush();
            await new Promise((r) => setImmediate(r));
        });
        assert.equal(first._db.isOpen, false);
        assert.equal(e._readerState().streams.sys.store._db.isOpen, true);
        setEnv({});
        await captureLines(async () => {
            e.init({ serviceId: 'svc', nodeId: 'n', syslogStore: null });
            await e.flush();
            await new Promise((r) => setImmediate(r));
        });
    });
});
