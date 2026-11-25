// Queue mode and raise mode against stub stores. Mirrors
// python/tests/test_audit_queue.py, except emit() never blocks here.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
    init, emit, register, registry as _reg,
    AuditStoreError, queueStats, flush, close, _clearCoreRegistry, defaultEngine,
} from '../src/index.js';
import { DatabaseSync } from 'node:sqlite';
import { uninstallDrainer, activeDrainer, rejectsRow } from '../src/audit_queue.js';
import { SqliteStore } from '../src/store/sqlite.js';

// Stub stores

class RecordingStore {
    constructor() { this.rows = []; }
    insert(row) { this.rows.push(row); }
}

class SlowStore extends RecordingStore {
    constructor(delayMs) { super(); this.delayMs = delayMs; }
    async insert(row) {
        await new Promise(r => setTimeout(r, this.delayMs));
        super.insert(row);
    }
}

class BrokenStore {
    constructor(msg = 'store down') { this.msg = msg; this.attempts = 0; }
    insert(_row) {
        this.attempts++;
        throw new Error(this.msg);
    }
}

class FlakyStore {
    constructor(failFirst) {
        this.failFirst = failFirst;
        this.attempts = 0;
        this.success = 0;
    }
    insert(_row) {
        this.attempts++;
        if (this.attempts <= this.failFirst) {
            throw new Error(`transient #${this.attempts}`);
        }
        this.success++;
    }
}

// Fixtures

const TEST_META = {
    USER_CREATED: {
        id: 'USER_CREATED', domain: 'user', category: 'account',
        action: 'create', severity: 'info',
        retention_class: 'short', description: 'test', emitter: 'test',
    },
};

beforeEach(async () => {
    await defaultEngine.resetForTests();
    _clearCoreRegistry();
    _reg().clear();
    register('user', TEST_META);
});

afterEach(async () => {
    await defaultEngine.resetForTests();
});

function _initQueue(store, opts = {}) {
    init({
        serviceId: 'svc',
        nodeId: 'node',
        auditStore: store,
        auditStoreFailureStrategy: 'queue',
        queueCapacity: 100,
        ...opts,
    });
}

function _initRaise(store) {
    init({
        serviceId: 'svc',
        nodeId: 'node',
        auditStore: store,
        auditStoreFailureStrategy: 'raise',
    });
}

// Happy path

test('queue mode drains within one second', async () => {
    const store = new RecordingStore();
    _initQueue(store);
    emit({ code: 'USER_CREATED', target: 'u-1' });
    emit({ code: 'USER_CREATED', target: 'u-2' });
    assert.equal(await flush(1000), true, 'flush should succeed');
    assert.equal(store.rows.length, 2);
});

test('queue mode emit returns immediately under slow store', async () => {
    const store = new SlowStore(50);
    _initQueue(store);
    const t0 = Date.now();
    for (let i = 0; i < 10; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 100, `emit() should return immediately; took ${elapsed}ms`);
    assert.equal(await flush(2000), true, 'flush should drain the slow store');
    assert.equal(store.rows.length, 10);
});

// Raise mode

test('raise mode throws AuditStoreError on failure', () => {
    const store = new BrokenStore();
    _initRaise(store);
    assert.throws(
        () => emit({ code: 'USER_CREATED', target: 'u-1' }),
        (err) => err instanceof AuditStoreError && /store down/.test(err.message),
    );
});

test('raise mode does not install drainer', () => {
    const store = new RecordingStore();
    _initRaise(store);
    assert.equal(queueStats(), null);
});

// Outage + recovery

test('outage then recovery drains pending rows', async () => {
    const store = new FlakyStore(2);
    _initQueue(store, {
        queueRetryInitialMs: 10,
        queueRetryMaxMs: 50,
        queueRetryJitter: false,
    });
    emit({ code: 'USER_CREATED', target: 'u-1' });
    assert.equal(await flush(2000), true, 'drainer should retry past 2 failures');
    assert.equal(store.success, 1);
    assert.ok(store.attempts >= 3, `want >=3 attempts (2 fail + 1 success); got ${store.attempts}`);
});

// A row the database refuses is dead-lettered after one attempt, and the
// rows behind it are stored.
test('a rejected row is dead-lettered at once', async () => {
    const store = {
        attempts: 0,
        stored: [],
        insert(row) {
            this.attempts++;
            if (row.target === 'bad') {
                const err = new Error('index row size exceeds maximum');
                err.code = '54000';
                throw err;
            }
            this.stored.push(row.target);
        },
    };
    _initQueue(store, { queueRetryInitialMs: 60000, queueRetryMaxMs: 60000, queueRetryJitter: false });
    emit({ code: 'USER_CREATED', target: 'bad' });
    emit({ code: 'USER_CREATED', target: 'good' });
    await flush(2000);
    assert.deepEqual(store.stored, ['good']);
    assert.equal(store.attempts, 2, 'one attempt per row');
    assert.equal(queueStats().dead_lettered_total, 1);
});

test('rejectsRow reads the SQLSTATE class', () => {
    for (const code of ['22021', '23505', '54000', 'SQLITE_CONSTRAINT', 'SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_MISMATCH']) {
        assert.equal(rejectsRow({ code }), true, code);
    }
    for (const code of ['08006', '40001', '42501', '42P01', '53300', '57P01', 'SQLITE_BUSY', 'ECONNRESET', undefined, 54000]) {
        assert.equal(rejectsRow({ code }), false, String(code));
    }
});

test('rejectsRow reads node:sqlite\'s extended result code', () => {
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE t (a TEXT NOT NULL, b INTEGER CHECK (b > 0))');
    for (const sql of ['INSERT INTO t VALUES (NULL, 1)', 'INSERT INTO t VALUES (\'x\', 0)']) {
        let err;
        try {
            db.exec(sql);
        } catch (e) {
            err = e;
        }
        assert.equal(err.code, 'ERR_SQLITE_ERROR');
        assert.equal(err.errcode & 0xff, 19);
        assert.equal(rejectsRow(err), true, sql);
    }
    let noTable;
    try {
        db.exec('SELECT * FROM missing');
    } catch (e) {
        noTable = e;
    }
    assert.equal(rejectsRow(noTable), false);
    db.close();
});

test('a row a SqliteStore constraint refuses is dead-lettered at once', async () => {
    const store = new SqliteStore(':memory:');
    await store.init();
    store._db.exec(`CREATE TRIGGER refuse_bad BEFORE INSERT ON audit_log
        WHEN NEW.target = 'bad' BEGIN SELECT RAISE(ABORT, 'refused'); END`);
    let attempts = 0;
    const insert = store.insert.bind(store);
    store.insert = (row) => {
        attempts++;
        return insert(row);
    };
    _initQueue(store, { queueRetryInitialMs: 60000, queueRetryMaxMs: 60000, queueRetryJitter: false });
    emit({ code: 'USER_CREATED', target: 'bad' });
    emit({ code: 'USER_CREATED', target: 'good' });
    assert.equal(await flush(2000), true);
    assert.equal(attempts, 2, 'one attempt per row');
    assert.equal(queueStats().dead_lettered_total, 1);
    assert.deepEqual((await store.query({})).map((r) => r.target), ['good']);
    await store.close();
});

// Sys self-report

test('drainer first failure emits warn to sys (captured via stderr)', async () => {
    const store = new FlakyStore(1);
    const captured = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
        try {
            const obj = JSON.parse(String(chunk).trim());
            if (obj.shape === 'sys') captured.push(obj);
        } catch { /* not json */ }
        return origWrite(chunk, ...rest);
    };
    try {
        _initQueue(store, {
            queueRetryInitialMs: 5,
            queueRetryMaxMs: 20,
            queueRetryJitter: false,
        });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        assert.equal(await flush(2000), true);
    } finally {
        process.stderr.write = origWrite;
    }
    const events = captured.map(r => r.event);
    assert.ok(events.includes('audit_drain_failed'),
        `expected audit_drain_failed; got ${JSON.stringify(events)}`);
    assert.ok(events.includes('audit_drain_recovered'),
        `expected audit_drain_recovered; got ${JSON.stringify(events)}`);
});

test('changing the row emit() returned does not change what is stored', async () => {
    const store = new RecordingStore();
    _initQueue(store);
    const row = emit({ code: 'USER_CREATED', target: 'u-1', detail: { note: 'ok', password: 'hunter2' } });
    assert.equal(row.detail.password, '***');
    row.detail.password = 'hunter2';
    row.detail.note = 'changed';
    assert.equal(await flush(2000), true);
    assert.equal(store.rows.length, 1);
    assert.equal(store.rows[0].detail.password, '***');
    assert.equal(store.rows[0].detail.note, 'ok');
});

// Emits one row per target through `store` and returns the drainer's
// audit_drain_* events in order.
async function drainEvents(store, targets, opts = {}) {
    const captured = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
        try {
            const obj = JSON.parse(String(chunk).trim());
            if (obj.shape === 'sys') captured.push(obj.event);
        } catch { /* not json */ }
        return origWrite(chunk, ...rest);
    };
    try {
        _initQueue(store, {
            queueRetryInitialMs: 5,
            queueRetryMaxMs: 5,
            queueRetryJitter: false,
            ...opts,
        });
        for (const target of targets) emit({ code: 'USER_CREATED', target });
        assert.equal(await flush(2000), true);
    } finally {
        process.stderr.write = origWrite;
    }
    return captured.filter((e) => e.startsWith('audit_drain_'));
}

// Rejects the row whose target is 'bad' (SQLSTATE 23505), stores the rest.
class RejectBadStore extends RecordingStore {
    insert(row) {
        if (row.target === 'bad') throw Object.assign(new Error('duplicate'), { code: '23505' });
        super.insert(row);
    }
}

test('a row stored right after a dead letter reports recovery (spec §4)', async () => {
    assert.deepEqual(
        await drainEvents(new FlakyStore(2), ['a', 'b'], { queueDrainMaxAttempts: 2 }),
        ['audit_drain_failed', 'audit_drain_dead_letter', 'audit_drain_recovered'],
    );
});

test('the row after a dead letter reports its own first failure', async () => {
    assert.deepEqual(
        await drainEvents(new FlakyStore(3), ['a', 'b'], { queueDrainMaxAttempts: 2 }),
        ['audit_drain_failed', 'audit_drain_dead_letter', 'audit_drain_failed', 'audit_drain_recovered'],
    );
});

test('a row rejected on its first attempt, then a success, reports no recovery', async () => {
    assert.deepEqual(
        await drainEvents(new RejectBadStore(), ['bad', 'good']),
        ['audit_drain_dead_letter'],
    );
});

test('drainer degraded after 5 failures', async () => {
    const store = new BrokenStore();
    const captured = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
        try {
            const obj = JSON.parse(String(chunk).trim());
            if (obj.shape === 'sys') captured.push(obj);
        } catch { /* not json */ }
        return origWrite(chunk, ...rest);
    };
    try {
        _initQueue(store, {
            queueRetryInitialMs: 5,
            queueRetryMaxMs: 20,
            queueRetryJitter: false,
        });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        const deadline = Date.now() + 3000;
        while (Date.now() < deadline) {
            if (captured.some(r => r.event === 'audit_drain_degraded')) break;
            await new Promise(r => setTimeout(r, 50));
        }
    } finally {
        process.stderr.write = origWrite;
    }
    assert.ok(
        captured.some(r => r.event === 'audit_drain_degraded'),
        `audit_drain_degraded never fired; got ${JSON.stringify(captured.map(c => c.event))}`,
    );
});

test('queue high water emits warn at 50%', async () => {
    const store = new BrokenStore();
    const captured = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
        try {
            const obj = JSON.parse(String(chunk).trim());
            if (obj.shape === 'sys') captured.push(obj);
        } catch { /* not json */ }
        return origWrite(chunk, ...rest);
    };
    try {
        _initQueue(store, {
            queueCapacity: 4,
            queueRetryInitialMs: 5_000,
            queueRetryJitter: false,
        });
        for (let i = 0; i < 2; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
        await new Promise(r => setTimeout(r, 100));
    } finally {
        process.stderr.write = origWrite;
    }
    assert.ok(
        captured.some(r => r.event === 'audit_queue_high_water'),
        `expected audit_queue_high_water; got ${JSON.stringify(captured.map(c => c.event))}`,
    );
});

// QueueStats + flush

test('public flush blocks until drained', async () => {
    const store = new RecordingStore();
    _initQueue(store);
    for (let i = 0; i < 5; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    assert.equal(await flush(2000), true);
    assert.equal(store.rows.length, 5);
});

test('public flush is no-op in raise mode', async () => {
    const store = new RecordingStore();
    _initRaise(store);
    emit({ code: 'USER_CREATED', target: 'u-1' });
    assert.equal(await flush(100), true);
});

test('queue stats fields', async () => {
    const store = new RecordingStore();
    _initQueue(store);
    emit({ code: 'USER_CREATED', target: 'u-1' });
    assert.equal(await flush(1000), true);
    const s = queueStats();
    assert.ok(s !== null, 'expected non-null stats');
    assert.equal(s.depth, 0);
    assert.equal(s.capacity, 100);
    assert.ok(s.high_water >= 1);
    assert.equal(s.drained_total, 1);
    assert.equal(s.retry_count_active, 0);
    assert.equal(s.last_error, null);
});

test('queue stats high water monotonic', async () => {
    const store = new RecordingStore();
    _initQueue(store, { queueCapacity: 10 });
    for (let i = 0; i < 5; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    assert.equal(await flush(1000), true);
    const high = queueStats().high_water;
    emit({ code: 'USER_CREATED', target: 'u-x' });
    assert.equal(await flush(1000), true);
    assert.ok(queueStats().high_water >= high);
});

// ── async stores, stop, degraded backoff (#137) ────────────────────────────

class AsyncBrokenStore {
    constructor(msg = 'store down') { this.msg = msg; this.attempts = 0; }
    async insert(_row) {
        this.attempts++;
        await new Promise(r => setTimeout(r, 1));
        throw new Error(this.msg);
    }
}

// Runs fn(captured) with sys lines on stderr captured; returns them.
async function captureSys(fn) {
    const captured = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => {
        try {
            const obj = JSON.parse(String(chunk).trim());
            if (obj.shape === 'sys') { captured.push(obj); return true; }
        } catch { /* not json */ }
        return origWrite(chunk, ...rest);
    };
    try {
        await fn(captured);
    } finally {
        process.stderr.write = origWrite;
    }
    return captured;
}

// Fails the test if a promise rejection goes unhandled while fn runs.
async function noUnhandledRejection(fn) {
    const seen = [];
    const onRejection = (err) => seen.push(err);
    process.on('unhandledRejection', onRejection);
    try {
        await fn();
        await new Promise(r => setTimeout(r, 20));
    } finally {
        process.off('unhandledRejection', onRejection);
    }
    assert.deepEqual(seen, []);
}

test('raise mode rejects with AuditStoreError for an async store', async () => {
    await noUnhandledRejection(async () => {
        _initRaise(new AsyncBrokenStore());
        await assert.rejects(
            emit({ code: 'USER_CREATED', target: 'u-1' }),
            (err) => err instanceof AuditStoreError && /store down/.test(err.message),
        );
    });
});

test('raise mode resolves to the row for an async store', async () => {
    const store = new SlowStore(1);
    _initRaise(store);
    const row = await emit({ code: 'USER_CREATED', target: 'u-1' });
    assert.equal(row.target, 'u-1');
    assert.equal(store.rows.length, 1);
});

test('sync fallback logs a failed async insert', async () => {
    let captured;
    await noUnhandledRejection(async () => {
        captured = await captureSys(async () => {
            _initQueue(new AsyncBrokenStore());
            await uninstallDrainer();
            emit({ code: 'USER_CREATED', target: 'u-1' });
            await new Promise(r => setTimeout(r, 20));
        });
    });
    assert.ok(captured.some(r => r.event === 'audit_sync_fallback_failed'),
        `got ${JSON.stringify(captured.map(c => c.event))}`);
});

// An error shaped like pg's DatabaseError, whose name is "error" and whose
// message can carry a row value.
class DatabaseError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'error';
        this.code = code;
        this.severity = 'ERROR';
    }
}

test('the drainer records the error type, as the other SDKs do', async () => {
    const secret = 'Key (id)=(alice@example.com) already exists';
    let failFor = 6;
    const store = {
        insert() {
            if (failFor-- > 0) throw new DatabaseError(secret, '57P01');
            throw new DatabaseError(secret, '23505');
        },
    };
    const captured = await captureSys(async () => {
        _initQueue(store, { queueRetryInitialMs: 1, queueRetryMaxMs: 1, queueRetryJitter: false });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        await flush(2000);
    });
    // This test's events: a drainer an earlier test left stopping can log
    // the same ones with another error type.
    const by = (e) => captured.find((r) => r.event === e && (r.error ?? r.last_error) === 'DatabaseError');
    assert.ok(by('audit_drain_failed'), JSON.stringify(captured));
    assert.ok(by('audit_drain_degraded'), JSON.stringify(captured));
    assert.ok(by('audit_drain_dead_letter'), JSON.stringify(captured));
    assert.equal(queueStats().last_error, 'DatabaseError');
    assert.ok(!JSON.stringify(captured).includes('alice'), JSON.stringify(captured));
});

test('sync fallback records the error type, as the other SDKs do', async () => {
    let row;
    const captured = await captureSys(async () => {
        _initQueue(new AsyncBrokenStore('value (id)=(alice@example.com)'));
        await uninstallDrainer();
        row = emit({ code: 'USER_CREATED', target: 'u-1' });
        await new Promise(r => setTimeout(r, 20));
    });
    const ev = captured.find((r) => r.event === 'audit_sync_fallback_failed' && r.row_id === row.id);
    assert.equal(ev.error_type, 'Error');
    assert.equal(ev.error, undefined);
    assert.ok(!JSON.stringify(captured).includes('alice'));
});

test('stop writes the rows still queued', async () => {
    const store = new SlowStore(5);
    _initQueue(store);
    for (let i = 0; i < 5; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    await uninstallDrainer();
    assert.equal(store.rows.length, 5);
});

test('stop reports rows whose last attempt fails as lost', async () => {
    const store = new BrokenStore();
    const ids = new Set();
    let stopped;
    const captured = await captureSys(async () => {
        _initQueue(store, {
            queueRetryInitialMs: 60_000,
            queueRetryMaxMs: 60_000,
            queueRetryJitter: false,
        });
        ids.add(emit({ code: 'USER_CREATED', target: 'u-1' }).id);
        ids.add(emit({ code: 'USER_CREATED', target: 'u-2' }).id);
        while (store.attempts === 0) await new Promise(r => setTimeout(r, 5));
        const t0 = Date.now();
        stopped = await uninstallDrainer();
        assert.ok(Date.now() - t0 < 1000, 'stop must cut the backoff short');
    });
    const events = captured.map(c => c.event);
    const lost = captured.filter(r => r.event === 'audit_drain_lost_at_stop' && ids.has(r.row_id));
    assert.equal(lost.length, 2, `got ${JSON.stringify(events)}`);
    assert.equal(lost[0].error_type, 'Error');
    assert.ok(!events.includes('audit_drain_dead_letter'));
    assert.equal(stopped, false);
    // u-1: its first attempt, then one after the stop. u-2: one, after the stop.
    assert.equal(store.attempts, 3);
});

test('drainer degraded reports the backoff it is about to wait', async () => {
    // An error type of its own: a drainer an earlier test left stopping can
    // report degraded too.
    class BackoffProbeError extends Error {
        name = 'BackoffProbeError';
    }
    const store = { insert() { throw new BackoffProbeError('down'); } };
    const ours = (r) => r.event === 'audit_drain_degraded' && r.last_error === 'BackoffProbeError';
    const captured = await captureSys(async (seen) => {
        _initQueue(store, {
            queueRetryInitialMs: 200,
            queueRetryMaxMs: 200,
            queueRetryJitter: false,
        });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        const deadline = Date.now() + 5000;
        while (!seen.some(ours) && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
    });
    const degraded = captured.find(ours);
    assert.ok(degraded, 'audit_drain_degraded never fired');
    assert.equal(degraded.retry_count, 5);
    assert.ok(degraded.in_backoff_seconds > 0.15 && degraded.in_backoff_seconds <= 0.2,
        `in_backoff_seconds was ${degraded.in_backoff_seconds}`);
});

test('stop gives up after its timeout and reports what it holds as lost', async () => {
    const store = { insert: () => new Promise(() => {}) };
    const ids = new Set();
    const captured = await captureSys(async () => {
        _initQueue(store);
        ids.add(emit({ code: 'USER_CREATED', target: 'u-1' }).id);
        ids.add(emit({ code: 'USER_CREATED', target: 'u-2' }).id);
        await new Promise(r => setTimeout(r, 20));
        const t0 = Date.now();
        assert.equal(await uninstallDrainer(100), false);
        assert.ok(Date.now() - t0 < 1000);
    });
    const lost = captured.filter(r => r.event === 'audit_drain_lost_at_stop' && ids.has(r.row_id));
    assert.deepEqual(lost.map(r => r.error_type), ['TimeoutError', 'TimeoutError']);
});

test('close resolves true once every row is stored', async () => {
    const store = new SlowStore(5);
    _initQueue(store);
    for (let i = 0; i < 3; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    assert.equal(await close(2000), true);
    assert.equal(store.rows.length, 3);
    assert.equal(queueStats(), null);
    // After close the row skips the queue.
    emit({ code: 'USER_CREATED', target: 'u-after' });
    await new Promise(r => setTimeout(r, 20));
    assert.equal(store.rows.at(-1).target, 'u-after');
});

test('close resolves false for a row in backoff, and a second close agrees', async () => {
    const store = new BrokenStore();
    let results;
    let row;
    const captured = await captureSys(async () => {
        _initQueue(store, {
            queueRetryInitialMs: 60_000,
            queueRetryMaxMs: 60_000,
            queueRetryJitter: false,
        });
        row = emit({ code: 'USER_CREATED', target: 'u-1' });
        while (store.attempts === 0) await new Promise(r => setTimeout(r, 5));
        results = await Promise.all([close(200), close(200)]);
    });
    assert.deepEqual(results, [false, false]);
    assert.equal(captured.filter(r => r.event === 'audit_drain_lost_at_stop' && r.row_id === row.id).length, 1);
});

test('flush counts a dead-lettered row as done', async () => {
    _initQueue(new BrokenStore(), {
        queueRetryInitialMs: 1,
        queueRetryMaxMs: 5,
        queueRetryJitter: false,
        queueDrainMaxAttempts: 3,
    });
    emit({ code: 'USER_CREATED', target: 'u-1' });
    const t0 = Date.now();
    assert.equal(await flush(2000), true);
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(queueStats().dead_lettered_total, 1);
    assert.equal(queueStats().in_backoff_seconds, 0);
});

// Re-init (spec §10)

test('close waits for the drainer a re-init is retiring', async () => {
    const a = new SlowStore(20);
    const b = new RecordingStore();
    _initQueue(a);
    for (let i = 0; i < 5; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    _initQueue(b);
    assert.equal(await close(5000), true);
    assert.equal(a.rows.length, 5);
});

test('flush waits for the drainer a re-init is retiring', async () => {
    const a = new SlowStore(20);
    _initQueue(a);
    for (let i = 0; i < 3; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    _initQueue(new RecordingStore());
    assert.equal(await flush(5000), true);
    assert.equal(a.rows.length, 3);
});

test('re-init reports rows the old drainer could not store', async () => {
    const store = { insert: () => new Promise(() => {}) };
    const ids = new Set();
    let closed;
    const captured = await captureSys(async () => {
        _initQueue(store);
        ids.add(emit({ code: 'USER_CREATED', target: 'u-1' }).id);
        ids.add(emit({ code: 'USER_CREATED', target: 'u-2' }).id);
        _initQueue(new RecordingStore());
        const t0 = Date.now();
        closed = await close(300);
        assert.ok(Date.now() - t0 < 1500, 'close must keep to its timeout');
    });
    assert.equal(closed, false);
    const lost = captured.filter(r => r.event === 'audit_drain_lost_at_stop' && ids.has(r.row_id));
    assert.equal(lost.length, 2);
    const inc = captured.filter(r => r.event === 'audit_drain_install_incomplete');
    assert.equal(inc.length, 1, `got ${JSON.stringify(captured.map(c => c.event))}`);
    assert.equal(inc[0].level, 'warn');
    assert.equal(inc[0].unstored, 2);
    assert.equal(typeof inc[0].flushed, 'boolean');
});

test('re-init that stores every row reports nothing', async () => {
    const captured = await captureSys(async () => {
        _initQueue(new SlowStore(5));
        emit({ code: 'USER_CREATED', target: 'u-1' });
        _initQueue(new RecordingStore());
        assert.equal(await close(2000), true);
    });
    assert.ok(!captured.some(r => r.event === 'audit_drain_install_incomplete'));
});

for (const [name, reinit] of [
    ['queue mode', () => _initQueue(new RecordingStore())],
    ['raise mode with no store', () => init({
        serviceId: 'svc', nodeId: 'node', auditStoreFailureStrategy: 'raise',
    })],
]) {
    test(`re-init to ${name} flushes the old drainer and reports its loss`, async () => {
        const store = new BrokenStore();
        let closed;
        const captured = await captureSys(async (seen) => {
            _initQueue(store, {
                queueRetryInitialMs: 60_000,
                queueRetryMaxMs: 60_000,
                queueRetryJitter: false,
            });
            emit({ code: 'USER_CREATED', target: 'u-1' });
            while (store.attempts === 0) await new Promise(r => setTimeout(r, 5));
            reinit();
            await new Promise(r => setTimeout(r, 50));
            assert.equal(store.attempts, 1, 'the row waits out the flush first');
            const deadline = Date.now() + 8000;
            while (!seen.some(r => r.event === 'audit_drain_install_incomplete')
                && Date.now() < deadline) {
                await new Promise(r => setTimeout(r, 20));
            }
            closed = await close(1000);
        });
        const inc = captured.filter(r => r.event === 'audit_drain_install_incomplete');
        assert.equal(inc.length, 1, `got ${JSON.stringify(captured.map(c => c.event))}`);
        assert.equal(inc[0].flushed, false);
        assert.equal(inc[0].unstored, 1);
        // The loss is reported by the re-init's events; a close() with
        // nothing pending afterwards loses nothing, as in Python and Go.
        assert.equal(closed, true);
    });
}

test('close keeps to its timeout while a re-init is stopping the old drainer', async () => {
    const store = { insert: () => new Promise(() => {}) };
    let closed;
    await captureSys(async () => {
        _initQueue(store);
        emit({ code: 'USER_CREATED', target: 'u-1' });
        const old = activeDrainer();
        _initQueue(new RecordingStore());
        // The re-init's 5 s flush times out and it starts its own stop.
        const deadline = Date.now() + 8000;
        while (!old._stopped && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
        assert.ok(old._stopped);
        const t0 = Date.now();
        closed = await close(300);
        assert.ok(Date.now() - t0 < 1000, `close took ${Date.now() - t0} ms`);
    });
    assert.equal(closed, false);
});

// Idle drainer

test('an idle drainer lets the process exit', async () => {
    const { spawn } = await import('node:child_process');
    const src = new URL('../src/index.js', import.meta.url).href;
    const script = `
        import { init, emit, register, flush } from ${JSON.stringify(src)};
        register('user', { USER_CREATED: { domain: 'user', action: 'create' } });
        const rows = [];
        init({ serviceId: 's', nodeId: 'n', auditStore: { insert: (r) => { rows.push(r); } } });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        await flush(1000);
        process.stderr.write('stored ' + rows.length + '\\n');
    `;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
        stdio: ['ignore', 'ignore', 'pipe'],
    });
    let err = '';
    child.stderr.on('data', (d) => { err += d; });
    const t0 = Date.now();
    const code = await new Promise((resolve) => {
        const timer = setTimeout(() => { child.kill(); resolve('timeout'); }, 5000);
        child.on('exit', (c) => { clearTimeout(timer); resolve(c); });
    });
    assert.equal(code, 0, `child did not exit on its own (${Date.now() - t0} ms)`);
    assert.match(err, /stored 1/);
});
