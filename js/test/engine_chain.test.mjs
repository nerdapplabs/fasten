// The engine with a store that seals: the two stdout lines per row (spec §8),
// audit_chain_unavailable, and how failures after and during sealing show.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import {
    Engine, register, verifyChain, seal, GENESIS, parseJson,
    AuditSealError, AuditRowRejectedError,
} from '../src/index.js';

delete process.env.FASTEN_REDACT_KEYS;
delete process.env.FASTEN_REDACT_REPLACEMENT;

before(() => {
    register('chain', {
        CHAIN_EVENT: { domain: 'chain', action: 'do', severity: 'info', retentionClass: 'long' },
    });
});

// Seals each row as it stores it, like the Postgres store, in memory.
class SealingStore {
    constructor({ async = false } = {}) {
        this.rows = [];
        this.async = async;
    }

    seals() {
        return true;
    }

    insert(row) {
        const mine = this.rows.filter((r) => r.source_node_id === row.source_node_id);
        const sealed = seal(mine.at(-1)?.hash ?? GENESIS, { ...row, monotonic_seq: mine.length + 1 });
        this.rows.push(sealed);
        return this.async ? Promise.resolve(sealed) : sealed;
    }
}

// Runs fn with stdout and stderr captured; returns their lines.
async function capture(fn, { failSealed = false } = {}) {
    const out = [];
    const err = [];
    const [ow, ew] = [process.stdout.write, process.stderr.write];
    // fasten's lines are taken; the test runner's own output goes through.
    const ours = (chunk) => typeof chunk === 'string' && chunk.startsWith('{"shape":');
    process.stdout.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ow.call(process.stdout, chunk, ...rest);
        if (failSealed && /"hash":"[0-9a-f]{64}"/.test(chunk)) throw Object.assign(new Error('EPIPE'), { name: 'BrokenPipe' });
        out.push(chunk);
        const cb = rest.find((x) => typeof x === 'function');
        if (cb) cb();
        return true;
    };
    process.stderr.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ew.call(process.stderr, chunk, ...rest);
        err.push(chunk);
        return true;
    };
    try {
        await fn();
    } finally {
        process.stdout.write = ow;
        process.stderr.write = ew;
    }
    const parse = (lines) => lines.flatMap((l) => l.split('\n')).filter(Boolean);
    return { out: parse(out), err: parse(err).map((l) => JSON.parse(l)) };
}

const auditLines = (lines) => lines.filter((l) => l.includes('"shape":"audit"'));

describe('two stdout lines per stored row', () => {
    for (const strategy of ['queue', 'raise']) {
        for (const async of [false, true]) {
            test(`${strategy} mode, ${async ? 'async' : 'sync'} store`, async () => {
                const store = new SealingStore({ async });
                const e = new Engine();
                const results = [];
                const { out } = await capture(async () => {
                    e.init({ serviceId: 'svc', nodeId: 'node-e', auditStore: store, auditStoreFailureStrategy: strategy });
                    for (let i = 0; i < 3; i++) {
                        results.push(await e.emit({ code: 'CHAIN_EVENT', target: `t-${i}`, detail: { i, v: 75.5, tiny: 1e-7 } }));
                    }
                    if (strategy === 'queue') assert.equal(await e.flush(5000), true);
                    await e.resetForTests();
                });
                const lines = auditLines(out);
                assert.equal(lines.length, 6);
                const parsed = lines.map((l) => parseJson(l));
                // Each row: the unsealed line at emit, then the sealed one.
                parsed.forEach((p, i) => {
                    const sealedAt = parsed.findIndex((q) => q.hash && q.id === p.id);
                    if (!p.hash) assert.ok(sealedAt > i, `row ${p.id}: no sealed line after the unsealed one`);
                });
                const sealedLines = parsed.filter((p) => p.hash);
                assert.deepEqual(sealedLines.map((p) => Number(p.monotonic_seq)), [1, 2, 3]);
                for (const p of sealedLines) {
                    assert.equal(p.canonical_form_id, '2');
                    assert.match(p.detail_salt, /^[0-9a-f]{64}$/);
                }
                const res = verifyChain(lines);
                assert.ok(res.ok, res.reason);
                assert.equal(res.sealedRows, 3);
                if (strategy === 'raise') {
                    assert.deepEqual(results.map((r) => r.monotonic_seq), [1, 2, 3]);
                    assert.equal(results[2].prev_hash, results[1].hash);
                } else {
                    assert.deepEqual(results.map((r) => r.monotonic_seq), [0, 0, 0]);
                }
            });
        }
    }

    test('a store that does not seal gets one line per row', async () => {
        const store = { insert() {} };
        const e = new Engine();
        const { out } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-u', auditStore: store, auditStoreFailureStrategy: 'raise' });
            e.emit({ code: 'CHAIN_EVENT', target: 'x' });
            await e.resetForTests();
        });
        assert.equal(auditLines(out).length, 1);
    });

    test('a BigInt in detail keeps its digits on both lines and in the hash', async () => {
        const store = new SealingStore();
        const e = new Engine();
        let row;
        const { out } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-b', auditStore: store, auditStoreFailureStrategy: 'raise' });
            row = e.emit({ code: 'CHAIN_EVENT', target: 'x', detail: { big: 2n ** 70n, small: 5n, n: 2 ** 60 } });
            await e.resetForTests();
        });
        assert.equal(row.detail.big, 2n ** 70n);
        assert.equal(row.detail.small, 5);
        assert.equal(row.detail.n, 2 ** 60);
        const lines = auditLines(out);
        assert.equal(lines.length, 2);
        for (const l of lines) assert.ok(l.includes('"big":1180591620717411303424'), l);
        assert.ok(verifyChain(lines).ok);
    });
});

describe('audit_chain_unavailable', () => {
    const logged = async (store) => {
        const e = new Engine();
        const { err } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-c', auditStore: store });
            await e.resetForTests();
        });
        return err.filter((l) => l.event === 'audit_chain_unavailable');
    };

    test('logged with no store', async () => {
        const [line] = await logged(null);
        assert.match(line.reason, /no audit store/);
    });

    test('logged with a store that does not seal', async () => {
        for (const store of [{ insert() {} }, { insert() {}, seals: () => false }]) {
            const [line] = await logged(store);
            assert.match(line.reason, /does not seal/);
        }
    });

    test('not logged with a store that seals', async () => {
        assert.deepEqual(await logged(new SealingStore()), []);
    });
});

describe('failures', () => {
    test('a failed stdout write after the insert is logged, not thrown', async () => {
        for (const strategy of ['raise', 'queue']) {
            const store = new SealingStore();
            const e = new Engine();
            let row;
            const { out, err } = await capture(async () => {
                e.init({ serviceId: 'svc', nodeId: 'node-f', auditStore: store, auditStoreFailureStrategy: strategy });
                row = e.emit({ code: 'CHAIN_EVENT', target: 'x' });
                if (strategy === 'queue') assert.equal(await e.flush(5000), true);
                await e.resetForTests();
            }, { failSealed: true });
            assert.equal(store.rows.length, 1);
            if (strategy === 'raise') assert.equal(row.hash, store.rows[0].hash);
            assert.equal(auditLines(out).length, 1);
            const failed = err.filter((l) => l.event === 'audit_stdout_failed');
            assert.equal(failed.length, 1, strategy);
            assert.deepEqual([failed[0].row_id, failed[0].sealed, failed[0].error_type], [store.rows[0].id, true, 'BrokenPipe']);
            assert.equal(err.filter((l) => /dead_letter|drain_failed/.test(l.event)).length, 0);
        }
    });

    test('a seal failure is retried and named as one', async () => {
        let calls = 0;
        const store = {
            seals: () => true,
            insert(row) {
                calls++;
                if (calls === 1) throw new AuditSealError(new Error('random source unavailable'));
                return seal(GENESIS, { ...row, monotonic_seq: 1 });
            },
        };
        const e = new Engine();
        const { out, err } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-s', auditStore: store, queueRetryInitialMs: 1, queueRetryJitter: false });
            e.emit({ code: 'CHAIN_EVENT', target: 'x' });
            assert.equal(await e.flush(5000), true);
            await e.resetForTests();
        });
        const failed = err.find((l) => l.event === 'audit_drain_failed');
        assert.match(failed.error, /^AuditSealError: seal failed: random source unavailable/);
        assert.equal(calls, 2);
        assert.equal(auditLines(out).length, 2);
    });

    test('a row the store rejects is dead-lettered at once', async () => {
        let calls = 0;
        const store = {
            seals: () => true,
            insert(row) {
                calls++;
                throw new AuditRowRejectedError(`row ${row.id}: differs from the stored row with that id`);
            },
        };
        const e = new Engine();
        const { err } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-r', auditStore: store, queueRetryInitialMs: 1 });
            e.emit({ code: 'CHAIN_EVENT', target: 'x' });
            assert.equal(await e.flush(5000), true);
            await e.resetForTests();
        });
        assert.equal(calls, 1);
        const dead = err.find((l) => l.event === 'audit_drain_dead_letter');
        assert.match(dead.last_error, /^AuditRowRejectedError: /);
    });
});
