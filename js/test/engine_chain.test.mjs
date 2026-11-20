// The engine with a store that seals: the two stdout lines per row (spec §8),
// audit_chain_unavailable, and how failures after and during sealing show.
import { test, describe, before } from 'node:test';
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import * as fasten from '../src/index.js';
import {
    Engine, register, verifyChain, seal, GENESIS, parseJson,
    AuditSealError, AuditRowRejectedError, ChainError,
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

// Runs fn with stdout and stderr captured; returns their lines. failSealed
// makes a sealed line's write throw; asyncError hands each sealed line's
// write callback that error on the next tick.
async function capture(fn, { failSealed = false, asyncError = null } = {}) {
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
        if (asyncError && /"hash":"[0-9a-f]{64}"/.test(chunk)) process.nextTick(() => cb?.(asyncError));
        else if (cb) cb();
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

    test('a seal failure the row did not cause is retried and named as one', async () => {
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
        assert.equal(failed.error, 'AuditSealError');
        assert.equal(calls, 2);
        assert.equal(auditLines(out).length, 2);
    });

    test('a row field no store can seal fails emit() at once, in both modes', async () => {
        for (const strategy of ['queue', 'raise']) {
            const store = new SealingStore();
            const e = new Engine();
            const { out } = await capture(async () => {
                e.init({ serviceId: 'svc', nodeId: 'node-v', auditStore: store, auditStoreFailureStrategy: strategy });
                for (const input of [
                    { target: `doc/${'\u{1f600}'.slice(0, 1)}` }, { target: 'x', actor: 42 },
                    { target: 7 }, { target: 'x', actorKind: '\udc00' },
                ]) {
                    assert.throws(() => e.emit({ code: 'CHAIN_EVENT', ...input }),
                        (err) => err instanceof ChainError && /^emit: /.test(err.message), JSON.stringify(input));
                }
                await e.emit({ code: 'CHAIN_EVENT', target: 'ok' });
                if (strategy === 'queue') assert.equal(await e.flush(5000), true);
                await e.resetForTests();
            });
            assert.equal(store.rows.length, 1, strategy);
            assert.equal(auditLines(out).length, 2, strategy);
        }
    });

    test('a store that says it seals but returns no hashed row writes no sealed line, and says so once', async () => {
        const returns = [undefined, (row) => ({ ...row, id: 'evt-other', hash: 'f'.repeat(64) }), (row) => ({ ...row })];
        for (const give of returns) {
            for (const strategy of ['raise', 'queue']) {
                const store = { seals: () => true, insert: (row) => (typeof give === 'function' ? give(row) : give) };
                const e = new Engine();
                const results = [];
                const { out, err } = await capture(async () => {
                    e.init({ serviceId: 'svc', nodeId: 'node-n', auditStore: store, auditStoreFailureStrategy: strategy });
                    results.push(e.emit({ code: 'CHAIN_EVENT', target: 'a' }), e.emit({ code: 'CHAIN_EVENT', target: 'b' }));
                    if (strategy === 'queue') assert.equal(await e.flush(5000), true);
                    await e.resetForTests();
                });
                assert.equal(auditLines(out).length, 2, strategy);
                const said = err.filter((l) => l.event === 'audit_chain_row_unsealed');
                assert.equal(said.length, 1, strategy);
                assert.equal(said[0].row_id, results[0].id);
                // emit() returns the row as built when insert() gave another id.
                for (const r of results) assert.equal(r.hash ?? '', '');
            }
        }
    });

    test('a write callback error is logged with its code, not thrown', async () => {
        const store = new SealingStore({ async: true });
        const e = new Engine();
        const epipe = Object.assign(new Error('write EPIPE'), { code: 'EPIPE' });
        const { out, err } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-p', auditStore: store, auditStoreFailureStrategy: 'raise' });
            const row = await e.emit({ code: 'CHAIN_EVENT', target: 'x' });
            assert.match(row.hash, /^[0-9a-f]{64}$/);
            await new Promise((r) => setImmediate(r));
            await e.resetForTests();
        }, { asyncError: epipe });
        assert.equal(auditLines(out).length, 2);
        const failed = err.filter((l) => l.event === 'audit_stdout_failed');
        assert.equal(failed.length, 1);
        assert.deepEqual([failed[0].error_code, failed[0].sealed, failed[0].row_id], ['EPIPE', true, store.rows[0].id]);
    });

    test('an error event on the stream stdout writes to is logged, not thrown', async () => {
        // A stand-in for process.stdout, so the test runner's own stdout is
        // left alone.
        const stub = new EventEmitter();
        stub.write = (chunk, cb) => { cb?.(); return true; };
        const real = Object.getOwnPropertyDescriptor(process, 'stdout');
        const e = new Engine();
        const { err } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-q', auditStore: new SealingStore(), auditStoreFailureStrategy: 'raise' });
            Object.defineProperty(process, 'stdout', { value: stub, configurable: true, writable: true });
            try {
                e.emit({ code: 'CHAIN_EVENT', target: 'x' });
                assert.equal(stub.listenerCount('error'), 1);
                e.emit({ code: 'CHAIN_EVENT', target: 'y' });
                assert.equal(stub.listenerCount('error'), 1);
                // With no listener this would end the process.
                stub.emit('error', Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
            } finally {
                Object.defineProperty(process, 'stdout', real);
            }
            await e.resetForTests();
        });
        const failed = err.filter((l) => l.event === 'audit_stdout_failed');
        assert.equal(failed.length, 1);
        assert.deepEqual([failed[0].error_code, failed[0].error_type], ['EPIPE', 'Error']);
    });

    test('a BigInt keeps its digits at the edges, in arrays and under a redacted key', async () => {
        const store = new SealingStore();
        const e = new Engine();
        let row;
        const { out } = await capture(async () => {
            e.init({ serviceId: 'svc', nodeId: 'node-bi', auditStore: store, auditStoreFailureStrategy: 'raise' });
            row = e.emit({
                code: 'CHAIN_EVENT', target: 'x',
                detail: { over: 2n ** 53n + 1n, neg: -(2n ** 64n), list: [1n, 2n ** 60n], password: 2n ** 70n },
            });
            await e.resetForTests();
        });
        assert.deepEqual([row.detail.over, row.detail.neg, row.detail.list, row.detail.password],
            [2n ** 53n + 1n, -(2n ** 64n), [1, 2n ** 60n], '***']);
        const lines = auditLines(out);
        for (const l of lines) {
            for (const tok of ['"over":9007199254740993', '"neg":-18446744073709551616', '[1,1152921504606846976]', '"password":"***"']) {
                assert.ok(l.includes(tok), `${tok} not in ${l}`);
            }
        }
        assert.ok(verifyChain(lines).ok);
    });

    test('the public surface has no compareCodePoints or rowHash', () => {
        assert.equal(fasten.compareCodePoints, undefined);
        assert.equal(fasten.rowHash, undefined);
        assert.equal(fasten.default.compareCodePoints, undefined);
        assert.equal(fasten.default.rowHash, undefined);
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
        assert.equal(dead.last_error, 'AuditRowRejectedError');
    });
});
