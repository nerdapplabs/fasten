// Stored sys and api logs: persistStreams, the write-through to a stream
// store, redaction before it, failures, and the SQLite stream store.
import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Engine, apiLogger, currentRequestID, isSentinel, mintSentinel, withRequestID } from '../src/index.js';
import { SqliteStreamStore } from '../src/store/stream_sqlite.js';
import { MAX_PENDING, REPORT_EVERY_MS, Ring } from '../src/streams.js';
import { MemoryStreamStore, captureLines } from './reader_fixtures.mjs';

delete process.env.FASTEN_PERSIST_STREAMS;
delete process.env.FASTEN_REDACT_KEYS;
delete process.env.FASTEN_REDACT_REPLACEMENT;

const base = { serviceId: 'svc', nodeId: 'n1' };
const engines = [];
function engine() {
    const e = new Engine();
    engines.push(e);
    return e;
}
afterEach(async () => {
    for (const e of engines.splice(0)) await e.resetForTests();
});

describe('persistStreams', () => {
    test('unset leaves the attached stores to decide', async () => {
        const e = engine();
        await captureLines(() => e.init({ ...base, apiStore: new MemoryStreamStore() }));
        assert.deepEqual([...e.persistedStreams()].sort(), ['api']);
    });

    test('matches the attached stores', async () => {
        const e = engine();
        await captureLines(() => e.init({
            ...base, apiStore: new MemoryStreamStore(), syslogStore: new MemoryStreamStore(),
            persistStreams: ['api', 'sys'],
        }));
        assert.deepEqual([...e.persistedStreams()].sort(), ['api', 'sys']);
    });

    test('empty with no stores is fine', async () => {
        const e = engine();
        await captureLines(() => e.init({ ...base, persistStreams: [] }));
        assert.equal(e.persistedStreams().size, 0);
    });

    test('a named stream without a store is an error', () => {
        assert.throws(() => engine().init({ ...base, persistStreams: ['sys'] }),
            /named in persistStreams but no store attached: \["sys"\]/);
    });

    test('a store not named is an error', () => {
        assert.throws(() => engine().init({ ...base, apiStore: new MemoryStreamStore(), persistStreams: [] }),
            /store attached but not in persistStreams: \["api"\]/);
    });

    test('both mismatches are reported together', () => {
        assert.throws(() => engine().init({ ...base, apiStore: new MemoryStreamStore(), persistStreams: ['sys'] }),
            /no store attached: \["sys"\]; store attached but not in persistStreams: \["api"\]/);
    });

    test('unknown names are refused, audit included', () => {
        assert.throws(() => engine().init({ ...base, persistStreams: ['audit', 'sys'] }),
            /unknown stream\(s\) \["audit"\]/);
    });

    test('is read from FASTEN_PERSIST_STREAMS', () => {
        process.env.FASTEN_PERSIST_STREAMS = 'api, sys';
        try {
            assert.throws(() => engine().init({ ...base, apiStore: new MemoryStreamStore() }),
                /no store attached: \["sys"\]/);
        } finally {
            delete process.env.FASTEN_PERSIST_STREAMS;
        }
    });

    test('a failed check leaves the engine as it was', async () => {
        const e = engine();
        await captureLines(() => e.init({ ...base, syslogStore: new MemoryStreamStore() }));
        assert.throws(() => e.init({ ...base, persistStreams: ['api'] }));
        assert.deepEqual([...e.persistedStreams()], ['sys']);
    });
});

describe('write-through', () => {
    test('sys rows reach the store, redacted, with a request_id', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            e.log.info('login', { password: 'hunter2', user: 'a' });
            await e.flush();
        });
        const row = store.rows.find((r) => r.event === 'login');
        assert.ok(row);
        assert.equal(row.password, '***');
        assert.equal(row.user, 'a');
        assert.equal(row.shape, undefined);
        assert.equal(row.level, 'info');
        assert.equal(row.service_id, 'svc');
        assert.ok(row.request_id.startsWith('boot-svc-'));
    });

    test('the boot id gives way to orphan ids after the first real request', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            e.log.info('before');
            withRequestID('req-1', () => e.log.info('during'));
            e.log.info('after');
            await e.flush();
        });
        const by = (ev) => store.rows.find((r) => r.event === ev).request_id;
        assert.match(by('before'), /^boot-svc-/);
        assert.equal(by('during'), 'req-1');
        assert.match(by('after'), /^orphan-svc-/);
    });

    test('a failed store write keeps the stdout line and marks the store degraded', async () => {
        const e = engine();
        const store = new MemoryStreamStore({ fail: true });
        const { out, err } = await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            e.log.info('secret_event', { card: '4111' });
            await e.flush();
        });
        assert.ok(out.some((l) => l.includes('secret_event')));
        assert.ok(store.degraded);
        const failures = err.filter((l) => l.startsWith('fasten: syslog persist failed'));
        assert.ok(failures.length >= 1);
        assert.equal(failures[0], 'fasten: syslog persist failed: NotNullViolation\n');
        assert.ok(!err.some((l) => l.startsWith('fasten:') && l.includes('4111')));
    });

    test('a store that throws synchronously is handled the same way', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        store.insert = () => { throw new TypeError('boom'); };
        const { err } = await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            e.pushApi({ method: 'GET', path: '/x', status: 200 });
        });
        assert.ok(store.degraded);
        assert.ok(err.includes('fasten: api persist failed: TypeError\n'));
    });

    test('writeApi redacts, stores and writes an api line', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        const { out } = await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            e.writeApi({ method: 'POST', path: '/login', status: 201, token: 'abc', request_id: 'r-1' });
            await e.flush();
        });
        assert.equal(store.rows[0].token, '***');
        assert.equal(store.rows[0].status, 201);
        const line = JSON.parse(out.find((l) => l.includes('"shape":"api"')));
        assert.equal(line.token, '***');
        assert.equal(line.request_id, 'r-1');
    });

    test('pushSyslog stores without a stdout line', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        const { out } = await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            e.pushSyslog({ level: 'warn', event: 'from_pino', api_key: 'k' });
            await e.flush();
        });
        assert.equal(store.rows[0].event, 'from_pino');
        assert.equal(store.rows[0].api_key, '***');
        assert.ok(!out.some((l) => l.includes('from_pino')));
    });

    test('rows wait until init', () => {
        const e = engine();
        e.pushApi({ method: 'GET' });
        e.pushSyslog({ event: 'x' });
    });

    test('inserts keep their order', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            for (let i = 0; i < 20; i++) e.pushSyslog({ event: `e${i}` });
            await e.flush();
        });
        assert.deepEqual(store.rows.map((r) => r.event).reverse().filter((x) => x.startsWith('e')),
            Array.from({ length: 20 }, (_, i) => `e${i}`));
    });

    test('a retention for a store without purge() is an init error', () => {
        const store = new MemoryStreamStore();
        store.purge = undefined;
        assert.throws(() => engine().init({ ...base, apiStore: store, retentionApi: '7d' }), /retentionApi.*purge\(\)/);
    });

    test('retention purges on init', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        store.rows.push({ event: 'old', timestamp: '2000-01-01T00:00:00.000000Z' });
        await captureLines(async () => {
            e.init({ ...base, syslogStore: store, retentionSyslog: '1d' });
            await new Promise((r) => setImmediate(r));
            await new Promise((r) => setImmediate(r));
        });
        assert.ok(!store.rows.some((r) => r.event === 'old'));
    });
});

describe('apiLogger', () => {
    test('records method, path, status and the request id', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const { EventEmitter } = await import('node:events');
            const res = Object.assign(new EventEmitter(), {
                statusCode: 404, headersSent: false, headers: {},
                setHeader(k, v) { this.headers[k] = v; },
            });
            const req = { method: 'GET', url: '/items/7?x=1', headers: { 'x-request-id': 'abc-123' } };
            let seen;
            apiLogger({ engine: e })(req, res, () => {
                seen = currentRequestID();
            });
            res.emit('finish');
            res.emit('close');
            await e.flush();
            assert.equal(seen, 'abc-123');
            assert.equal(res.headers['X-Request-ID'], 'abc-123');
        });
        assert.equal(store.rows.length, 1);
        const row = store.rows[0];
        assert.deepEqual(
            { method: row.method, path: row.path, status: row.status, request_id: row.request_id },
            { method: 'GET', path: '/items/7', status: 404, request_id: 'abc-123' });
        assert.equal(typeof row.duration_ms, 'number');
        assert.match(row.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/);
    });

    test('an unusable header gets a new id', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const { EventEmitter } = await import('node:events');
            const res = Object.assign(new EventEmitter(), { statusCode: 200, setHeader() {} });
            apiLogger({ engine: e })({ method: 'GET', url: '/', headers: { 'x-request-id': 'bad id!' } }, res, () => {});
            res.emit('finish');
            await e.flush();
        });
        assert.match(store.rows[0].request_id, /^[0-9a-f]{12}$/);
    });
});

describe('apiLogger options and edge cases', () => {
    async function fakeRes(status = 200) {
        const { EventEmitter } = await import('node:events');
        return Object.assign(new EventEmitter(), { statusCode: status, headersSent: false, setHeader() {} });
    }

    test('a request id that looks like a sentinel is not taken from the client', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            for (const id of ['boot-svc-abc123def456', 'orphan-x', 'bg-1', 'sched-a', 'lib-b']) {
                const res = await fakeRes();
                apiLogger({ engine: e })({ method: 'GET', url: '/', headers: { 'x-request-id': id } }, res, () => {});
                res.emit('finish');
            }
            await e.flush();
        });
        assert.equal(store.rows.length, 5);
        for (const r of store.rows) {
            assert.match(r.request_id, /^[0-9a-f]{12}$/);
            assert.ok(!isSentinel(r.request_id));
        }
    });

    test('apiLogger can rewrite the stored path; skip matches the path as sent', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const mw = apiLogger({
                engine: e, skip: ['/healthz'],
                path: (req) => req.url.split('?')[0].replace(/\/reset\/[^/]+$/, '/reset/:token'),
            });
            for (const url of ['/reset/tok-s3cret?x=1', '/healthz', '/items']) {
                const res = await fakeRes();
                mw({ method: 'GET', url, headers: {} }, res, () => {});
                res.emit('finish');
            }
            await e.flush();
        });
        assert.deepEqual(store.rows.map((r) => r.path).reverse(), ['/reset/:token', '/items']);
        assert.ok(!JSON.stringify(store.rows).includes('s3cret'));
        assert.throws(() => apiLogger({ path: '/fixed' }), TypeError);
    });

    test('a request aborted before the response finished is recorded as 499', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const res = await fakeRes(200);
            apiLogger({ engine: e })({ method: 'POST', url: '/upload', headers: {} }, res, () => {});
            res.emit('close');
            res.emit('finish');
            await e.flush();
        });
        assert.equal(store.rows.length, 1);
        assert.equal(store.rows[0].status, 499);
        assert.equal(store.rows[0].aborted, true);
    });

    test('over node:http: a finished response is its status, an aborted one 499', async () => {
        const http = await import('node:http');
        const e = engine();
        const store = new MemoryStreamStore();
        await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const mw = apiLogger({ engine: e });
            let aborted;
            const gone = new Promise((r) => { aborted = r; });
            const server = http.createServer((req, res) => mw(req, res, () => {
                if (req.url === '/slow') {
                    res.on('close', () => setImmediate(aborted));
                    return;
                }
                res.statusCode = 201;
                res.end('ok');
            }));
            await new Promise((r) => server.listen(0, '127.0.0.1', r));
            const { port } = server.address();
            await (await fetch(`http://127.0.0.1:${port}/fine`)).text();
            const ctl = new AbortController();
            const slow = fetch(`http://127.0.0.1:${port}/slow`, { signal: ctl.signal }).catch(() => {});
            await new Promise((r) => setTimeout(r, 50));
            ctl.abort();
            await slow;
            await gone;
            server.closeAllConnections();
            await new Promise((r) => server.close(r));
            await e.flush();
        });
        const by = Object.fromEntries(store.rows.map((r) => [r.path, r]));
        assert.equal(by['/fine'].status, 201);
        assert.equal(by['/fine'].aborted, undefined);
        assert.equal(by['/slow'].status, 499);
        assert.equal(by['/slow'].aborted, true);
    });

    test('a throw while recording is logged by error type, not raised', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        const { err } = await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            const res = await fakeRes();
            apiLogger({ engine: e, path: () => { throw new RangeError('s3cret path'); } })(
                { method: 'GET', url: '/x', headers: {} }, res, () => {});
            res.emit('finish');
            await e.flush();
        });
        const line = err.map((l) => { try { return JSON.parse(l); } catch { return {}; } })
            .find((r) => r.event === 'api_log_failed');
        assert.equal(line.error_type, 'RangeError');
        assert.ok(!err.join('').includes('s3cret'));
        assert.equal(store.rows.length, 0);
    });
});

describe('stream cap, flush and outage reporting', () => {
    test('a store that never resolves: 10,001 writes, one dropped as QueueFull, stdout lines kept', async () => {
        const e = engine();
        const store = { insert: () => new Promise(() => {}), query: () => [], countMatching: () => 0, search: () => [] };
        let flushed;
        const { out, err } = await captureLines(async () => {
            e.init({ ...base, apiStore: store });
            for (let i = 0; i <= MAX_PENDING; i++) e.writeApi({ method: 'GET', path: `/p${i}`, status: 200 });
            flushed = await e.flush(50);
        });
        assert.equal(flushed, false);
        assert.equal(out.filter((l) => l.includes('"shape":"api"')).length, MAX_PENDING + 1);
        assert.deepEqual(err.filter((l) => l.startsWith('fasten: api persist failed')), ['fasten: api persist failed: QueueFull\n']);
        const st = e._readerState().streams.api;
        assert.equal(st.writeFailures, 1);
        assert.equal(st.source(), 'store-degraded');
        assert.equal(await e.close(50), false);
    });

    test('flush and close wait for writes pushed while they wait', async () => {
        const e = engine();
        const store = new MemoryStreamStore();
        const insert = store.insert.bind(store);
        store.insert = (row) => new Promise((r) => setTimeout(r, 5)).then(() => insert(row));
        let flushed;
        let closed;
        await captureLines(async () => {
            e.init({ ...base, syslogStore: store });
            e.pushSyslog({ event: 'a' });
            const f = e.flush(2000);
            setTimeout(() => e.pushSyslog({ event: 'b' }), 2);
            flushed = await f;
            const c = e.close(2000);
            e.pushSyslog({ event: 'c' });
            closed = await c;
        });
        assert.equal(flushed, true);
        assert.equal(closed, true);
        assert.deepEqual(store.rows.map((r) => r.event).filter((x) => x.length === 1).sort(), ['a', 'b', 'c']);
    });

    test('flush and close wait for the stream a re-init replaced', async () => {
        const e = engine();
        const slow = new MemoryStreamStore();
        const insert = slow.insert.bind(slow);
        slow.insert = (row) => new Promise((r) => setTimeout(r, 30)).then(() => insert(row));
        await captureLines(async () => {
            e.init({ ...base, syslogStore: slow });
            for (let i = 0; i < 5; i++) e.pushSyslog({ event: `old${i}` });
            e.init({ ...base, syslogStore: new MemoryStreamStore() });
            assert.equal(await e.flush(2000), true);
        });
        assert.equal(slow.rows.filter((r) => r.event.startsWith('old')).length, 5);
    });

    test('close resolves false when stream writes do not finish in time, with or without a drainer', async () => {
        const never = { insert: () => new Promise(() => {}), query: () => [], countMatching: () => 0, search: () => [] };
        for (const auditStore of [null, { insert() {} }]) {
            const e = engine();
            let closed;
            await captureLines(async () => {
                e.init({ ...base, syslogStore: never, auditStore });
                e.pushSyslog({ event: 'stuck' });
                closed = await e.close(100);
            });
            assert.equal(closed, false, `auditStore ${auditStore ? 'set' : 'unset'}`);
        }
    });

    test('during an outage stderr gets the first failure, then a count', async () => {
        const e = engine();
        const store = new MemoryStreamStore({ fail: true });
        const realNow = Date.now;
        let lines;
        try {
            ({ err: lines } = await captureLines(async () => {
                e.init({ ...base, syslogStore: store });
                for (let i = 0; i < 5; i++) e.pushSyslog({ event: `f${i}` });
                await e.flush();
                Date.now = () => realNow() + REPORT_EVERY_MS + 1000;
                e.pushSyslog({ event: 'late' });
                await e.flush();
                e.pushSyslog({ event: 'more1' });
                e.pushSyslog({ event: 'more2' });
                await e.flush();
                store.fail = false;
                e.pushSyslog({ event: 'ok' });
                await e.flush();
            }));
        } finally {
            Date.now = realNow;
        }
        const persist = lines.filter((l) => l.startsWith('fasten: syslog persist failed'));
        assert.equal(persist[0], 'fasten: syslog persist failed: NotNullViolation\n');
        // The count includes the init's own sys line, which failed too.
        assert.match(persist[1], /^fasten: syslog persist failed: NotNullViolation \(6 since the last report\)\n$/);
        assert.equal(persist.at(-1), 'fasten: syslog persist failed: 2 more, then a write succeeded\n');
        assert.equal(persist.length, 3);
    });
});

describe('sentinels and the ring', () => {
    test('mintSentinel and isSentinel', () => {
        const id = mintSentinel('bg', 'svc');
        assert.match(id, /^bg-svc-[0-9a-f]{12}$/);
        assert.ok(isSentinel(id));
        assert.ok(!isSentinel('abc123'));
        assert.throws(() => mintSentinel('nope'));
    });

    test('ring filters are exact and newest first', () => {
        const r = new Ring(3);
        for (let i = 0; i < 5; i++) r.push({ event: `e${i}`, level: i % 2 ? 'info' : 'INFO', status: 200 + i });
        assert.equal(r.length, 3);
        assert.deepEqual(r.query().map((x) => x.event), ['e4', 'e3', 'e2']);
        assert.deepEqual(r.query({ level: 'info' }).map((x) => x.event), ['e3']);
        assert.equal(r.countMatching({ status: '204' }), 1);
    });
});

describe('SqliteStreamStore', () => {
    let dir;
    afterEach(() => {
        if (dir) rmSync(dir, { recursive: true, force: true });
        dir = null;
    });

    test('rejects a missing or unsafe table name', () => {
        assert.throws(() => new SqliteStreamStore(':memory:', {}), /table name is required/);
        assert.throws(() => new SqliteStreamStore(':memory:', { table: 'x; drop' }), /not a valid SQL identifier/);
    });

    test('creates the file owner-only', async () => {
        dir = mkdtempSync(join(tmpdir(), 'fasten-stream-'));
        const path = join(dir, 's.db');
        const s = new SqliteStreamStore(path, { table: 'syslog' });
        await s.close();
        assert.equal(statSync(path).mode & 0o777, 0o600);
    });

    test('query, count, search and purge', async () => {
        const s = new SqliteStreamStore(':memory:', { table: 'api_log' });
        await s.insert({ method: 'GET', path: '/a', status: 200, request_id: 'r1', timestamp: '2026-01-01T00:00:00.000000Z', note: 'Grüße 100%' });
        await s.insert({ method: 'POST', path: '/b', status: '500', request_id: 'r2', timestamp: '2026-01-02T00:00:00.000000Z', big: 2n ** 60n });
        await s.insert({ method: 'GET', path: '/c', status: 'n/a', request_id: 'r3' });
        assert.deepEqual((await s.query()).map((r) => r.path), ['/c', '/b', '/a']);
        assert.deepEqual((await s.query({ status: 500 })).map((r) => r.path), ['/b']);
        assert.deepEqual((await s.query({ method: 'get' })), []);
        assert.equal((await s.countMatching({ method: 'GET' })), 2);
        assert.deepEqual((await s.query({ since: '2026-01-02T00:00:00.000000Z' })).map((r) => r.path), ['/b']);
        assert.deepEqual((await s.search({ q: '100%', since: '2026' })).map((r) => r.path), ['/a']);
        assert.deepEqual((await s.search({ q: 'x_y', since: '' })), []);
        assert.equal((await s.query({ path: '/b' }))[0].big, 2n ** 60n);
        assert.deepEqual((await s.search({ q: 'grüße', since: '' })).map((r) => r.path), ['/a']);
        assert.equal((await s.count()), 3);
        assert.equal((await s.purge({ before: '2026-01-02T00:00:00.000000Z' })), 1);
        assert.equal((await s.count()), 2);
        assert.equal(s._db.prepare('SELECT payload FROM api_log WHERE path = ?').get('/b').payload.includes('1152921504606846976'), true);
        await s.close();
    });

    // The stream DDL of Python's StreamStore (fasten/store/stream.py) and Go's
    // NewStreamStore (stream_store.go), as each runs it.
    const PY_STREAM_DDL = (t) => `
CREATE TABLE IF NOT EXISTS ${t} (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_${t}_req ON ${t}(request_id);
CREATE INDEX IF NOT EXISTS idx_${t}_ts  ON ${t}(timestamp);
CREATE INDEX IF NOT EXISTS idx_${t}_lvl ON ${t}(level);
CREATE INDEX IF NOT EXISTS idx_${t}_svc ON ${t}(service_id);
CREATE INDEX IF NOT EXISTS idx_${t}_evt ON ${t}(event);
CREATE INDEX IF NOT EXISTS idx_${t}_mth ON ${t}(method);
CREATE INDEX IF NOT EXISTS idx_${t}_pth ON ${t}(path);
CREATE INDEX IF NOT EXISTS idx_${t}_sts ON ${t}(status);`;
    const GO_STREAM_DDL = (t) => `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS ${t} (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    timestamp  TEXT,
    level      TEXT,
    service_id TEXT,
    event      TEXT,
    method     TEXT,
    path       TEXT,
    status     INTEGER,
    payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_${t}_req ON ${t}(request_id);
CREATE INDEX IF NOT EXISTS idx_${t}_ts  ON ${t}(timestamp);
CREATE INDEX IF NOT EXISTS idx_${t}_lvl ON ${t}(level);
CREATE INDEX IF NOT EXISTS idx_${t}_svc ON ${t}(service_id);
CREATE INDEX IF NOT EXISTS idx_${t}_evt ON ${t}(event);
CREATE INDEX IF NOT EXISTS idx_${t}_mth ON ${t}(method);
CREATE INDEX IF NOT EXISTS idx_${t}_pth ON ${t}(path);
CREATE INDEX IF NOT EXISTS idx_${t}_sts ON ${t}(status);`;

    // Each writes the lifted columns and the row as JSON: Python with
    // json.dumps(ensure_ascii=False) (", " and ": "), Go compact.
    for (const [name, ddl, json] of [
        ['Python', PY_STREAM_DDL, (r) => JSON.stringify(r).replaceAll(',"', ', "').replaceAll('":', '": ')],
        ['Go', GO_STREAM_DDL, (r) => JSON.stringify(r)],
    ]) {
        test(`reads and appends to a table ${name}'s SQLite stream store created`, async () => {
            dir = mkdtempSync(join(tmpdir(), 'fasten-stream-'));
            const path = join(dir, 's.db');
            const db = new DatabaseSync(path);
            db.exec(ddl('syslog'));
            const ins = db.prepare('INSERT INTO syslog (request_id,timestamp,level,service_id,event,method,path,status,payload) VALUES (?,?,?,?,?,?,?,?,?)');
            const rows = [
                { request_id: 'r1', timestamp: '2026-01-01T00:00:00.000000Z', level: 'info', service_id: 'py', event: 'boot', note: 'Grüße' },
                { request_id: 'r2', timestamp: '2026-01-02T00:00:00.000000Z', level: 'error', service_id: 'py', event: 'db_down', status: 503 },
            ];
            for (const r of rows) {
                ins.run(r.request_id, r.timestamp, r.level, r.service_id, r.event, null, null, r.status ?? null, json(r));
            }
            db.close();
            const s = new SqliteStreamStore(path, { table: 'syslog' });
            assert.deepEqual((await s.query()).map((r) => r.event), ['db_down', 'boot']);
            assert.deepEqual((await s.query({ level: 'error' }))[0], rows[1]);
            assert.equal((await s.countMatching({ serviceId: 'py' })), 2);
            assert.deepEqual((await s.query({ status: 503 })).map((r) => r.event), ['db_down']);
            assert.deepEqual((await s.search({ q: 'grüße', since: '2026' })).map((r) => r.event), ['boot']);
            await s.insert({ request_id: 'r3', timestamp: '2026-01-03T00:00:00.000000Z', level: 'info', service_id: 'js', event: 'js_row' });
            assert.deepEqual((await s.query({ limit: 1 })).map((r) => r.event), ['js_row']);
            assert.equal((await s.purge({ before: '2026-01-02T00:00:00.000000Z' })), 1);
            await s.close();
            const back = new DatabaseSync(path);
            assert.deepEqual(back.prepare('SELECT seq, service_id, event FROM syslog ORDER BY seq').all().map((r) => ({ ...r })),
                [{ seq: 2, service_id: 'py', event: 'db_down' }, { seq: 3, service_id: 'js', event: 'js_row' }]);
            back.close();
        });
    }
});
