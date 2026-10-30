/**
 * P1-15 cross-language: same wire/API semantics as Python's
 * tests/test_audit_queue.py — happy path, slow store, outage+recovery,
 * raise mode, sys self-report, queue_stats, flush.
 *
 * JS deviation: emit() doesn't block on capacity (single-threaded
 * event loop). queueCapacity is the high-water-warn threshold; the
 * drainer + retry-forever-with-backoff matches Python exactly.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
    init, emit, register, registry as _reg,
    AuditStoreError, queueStats, flush, _clearRustRegistry,
} from '../src/index.js';
import { uninstallDrainer } from '../src/audit_queue.js';

// ── stub stores ────────────────────────────────────────────────────────────

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

// ── fixtures ───────────────────────────────────────────────────────────────

const TEST_META = {
    USER_CREATED: {
        id: 'USER_CREATED', domain: 'user', category: 'account',
        action: 'create', severity: 'info',
        retention_class: 'short', description: 'test', emitter: 'test',
    },
};

beforeEach(() => {
    uninstallDrainer();
    _clearRustRegistry();
    _reg().clear();
    register('user', TEST_META);
});

afterEach(() => {
    uninstallDrainer();
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

// ── #1 happy path ──────────────────────────────────────────────────────────

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

// ── #2 raise mode ──────────────────────────────────────────────────────────

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

// ── #3 outage + recovery ───────────────────────────────────────────────────

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

// ── #5 sys self-report ────────────────────────────────────────────────────

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

// ── #6 queueStats + flush ──────────────────────────────────────────────────

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

test('stop writes the rows still queued', async () => {
    const store = new SlowStore(5);
    _initQueue(store);
    for (let i = 0; i < 5; i++) emit({ code: 'USER_CREATED', target: `u-${i}` });
    await uninstallDrainer();
    assert.equal(store.rows.length, 5);
});

test('stop dead-letters rows whose last attempt fails', async () => {
    const store = new BrokenStore();
    const captured = await captureSys(async () => {
        _initQueue(store, {
            queueRetryInitialMs: 60_000,
            queueRetryMaxMs: 60_000,
            queueRetryJitter: false,
        });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        emit({ code: 'USER_CREATED', target: 'u-2' });
        while (store.attempts === 0) await new Promise(r => setTimeout(r, 5));
        const t0 = Date.now();
        await uninstallDrainer();
        assert.ok(Date.now() - t0 < 1000, 'stop must cut the backoff short');
    });
    const dead = captured.filter(r => r.event === 'audit_drain_dead_letter');
    assert.equal(dead.length, 2, `got ${JSON.stringify(captured.map(c => c.event))}`);
    // u-1: its first attempt, then one after the stop. u-2: one, after the stop.
    assert.equal(store.attempts, 3);
});

test('drainer degraded reports the backoff it is about to wait', async () => {
    const captured = await captureSys(async (seen) => {
        _initQueue(new BrokenStore(), {
            queueRetryInitialMs: 200,
            queueRetryMaxMs: 200,
            queueRetryJitter: false,
        });
        emit({ code: 'USER_CREATED', target: 'u-1' });
        const deadline = Date.now() + 5000;
        while (!seen.some(r => r.event === 'audit_drain_degraded') && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 20));
        }
    });
    const degraded = captured.find(r => r.event === 'audit_drain_degraded');
    assert.ok(degraded, 'audit_drain_degraded never fired');
    assert.ok(degraded.in_backoff_seconds > 0.15,
        `in_backoff_seconds was ${degraded.in_backoff_seconds}`);
});
