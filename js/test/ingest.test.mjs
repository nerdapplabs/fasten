/**
 * Replication ingest (spec §4) on SqliteStore and, with
 * FASTEN_TEST_POSTGRES_DSN set, PostgresStore. The cases follow Python's
 * tests/test_ingest_*.py and Go's ingest*_test.go.
 */
import { describe, test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SqliteStore } from '../src/store/sqlite.js';
import { PostgresStore } from '../src/store/postgres.js';
import {
    AuditRowRejectedError, AuditStoreError, ChainError, defaultEngine, Engine, ingestReplicated, init, listUnshipped,
    markShipped, register as registerCodes, seal, verifyChain,
} from '../src/index.js';
import { detailText, parseJson } from '../src/chain.js';

const DSN = process.env.FASTEN_TEST_POSTGRES_DSN;

function row(seq, { target = 'u/1', id, node = 'node-1', detail = { k: 'v' } } = {}) {
    const rid = id ?? `evt-${seq}`;
    return {
        id: rid, origin_id: rid, monotonic_seq: seq,
        timestamp: `2026-06-15T10:30:${String(seq % 60).padStart(2, '0')}.000000Z`,
        code: 'USER_CREATED', action: 'create', severity: 'info',
        service_id: 'svc', source_node_id: node, tenant_id: null,
        actor: 'a', actor_kind: 'user', target, category: 'account', domain: 'user',
        method: 'sdk', request_id: `req-${seq}`, detail,
    };
}

function chain(seqs, { prev = 'genesis', ...kw } = {}) {
    const out = [];
    for (const seq of seqs) {
        const r = seal(prev, row(seq, kw));
        prev = r.hash;
        out.push(r);
    }
    return out;
}

const unsealed = (seq, kw) => ({ ...row(seq, kw), hash: '', prev_hash: '' });

const BACKENDS = [
    ['SqliteStore', async () => ({ store: new SqliteStore(':memory:'), drop: async () => {} })],
    ['PostgresStore', async () => {
        const table = `ingest_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
        const store = new PostgresStore(DSN, { table });
        return {
            store,
            drop: async () => {
                const { default: pg } = await import('pg');
                const admin = new pg.Pool({ connectionString: DSN });
                await admin.query(`DROP TABLE IF EXISTS ${table}`);
                await admin.end();
            },
        };
    }],
];

const opened = [];
after(async () => {
    for (const { store, drop } of opened) {
        await store.close().catch(() => {});
        await drop();
    }
});

for (const [name, make] of BACKENDS) {
    const skip = name === 'PostgresStore' && !DSN;
    describe(`ingestReplicated on ${name}`, { skip }, () => {
        const fresh = async () => {
            const o = await make();
            opened.push(o);
            return o.store;
        };
        const stored = async (s) =>
            (await s.query({ limit: 1000 })).map((r) => [r.monotonic_seq, r.id, r.target])
                .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : 1));
        const seqs = async (s) => (await stored(s)).map((x) => x[0]);

        test('a clean batch is stored as it was sealed, and verifies', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3], { detail: { price: 75.5, n: 2n ** 70n } });
            const res = await s.ingestReplicated(rows);
            assert.deepEqual(res, { inserted: 3, rejectedFromSeq: null, reason: null });
            const back = await s.chainRows('node-1');
            assert.deepEqual(back.map((r) => r.hash), rows.map((r) => r.hash));
            assert.ok(verifyChain(back).ok);
            // Not sealed again: hash, prev_hash, origin_id and salt are the origin's.
            assert.deepEqual(back.map((r) => [r.prev_hash, r.origin_id, r.detail_salt]),
                rows.map((r) => [r.prev_hash, r.origin_id, r.detail_salt]));
        });

        test('rows as JSON text keep their number tokens', async () => {
            const s = await fresh();
            // 75.0 is a float to Python; JSON.parse would make it 75.
            const sealed = seal('genesis', { ...row(1), detail: parseJson('{"price": 75.0, "tiny": 1e-7}') });
            const wire = JSON.stringify(sealed);
            assert.ok(wire.includes('"price":75.0'), wire);
            assert.deepEqual(await s.ingestReplicated([wire]), { inserted: 1, rejectedFromSeq: null, reason: null });
            const [back] = await s.chainRows('node-1');
            assert.equal(back.hash, sealed.hash);
            assert.ok(verifyChain([back]).ok);
            // The same row read with JSON.parse breaks at once and stores nothing.
            const t = await fresh();
            const res = await t.ingestReplicated([JSON.parse(wire)]);
            assert.deepEqual([res.inserted, res.rejectedFromSeq], [0, 1]);
            assert.match(res.reason, /commitment/);
        });

        test('a tampered row: the verified prefix is stored and the break reported', async () => {
            const s = await fresh();
            const real = chain([1, 2, 3, 4, 5]);
            const rows = [...real];
            rows[2] = { ...rows[2], target: 'u/evil' };
            const res = await s.ingestReplicated(rows);
            assert.deepEqual([res.inserted, res.rejectedFromSeq], [2, 3]);
            assert.match(res.reason, /row evt-3: hash mismatch/);
            assert.deepEqual(await seqs(s), [1, 2]);
            // The sender resends from 3 with the real rows.
            const again = await s.ingestReplicated(real.slice(2));
            assert.deepEqual(again, { inserted: 3, rejectedFromSeq: null, reason: null });
            assert.ok(verifyChain(await s.chainRows('node-1')).ok);
        });

        test('a re-delivered batch is a no-op', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3]);
            await s.ingestReplicated(rows);
            const again = await s.ingestReplicated(rows);
            assert.deepEqual(again, { inserted: 3, rejectedFromSeq: null, reason: null });
            assert.deepEqual(await seqs(s), [1, 2, 3]);
        });

        test('a row sent twice in a batch is stored once', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3]);
            const res = await s.ingestReplicated([rows[0], rows[1], rows[1], rows[2]]);
            assert.deepEqual([res.inserted, res.rejectedFromSeq], [3, null]);
            assert.deepEqual(await seqs(s), [1, 2, 3]);
        });

        test('a batch continuing a stored chain is stored', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3, 4, 5]);
            await s.ingestReplicated(rows.slice(0, 3));
            assert.equal((await s.ingestReplicated(rows.slice(3))).rejectedFromSeq, null);
            assert.deepEqual(await seqs(s), [1, 2, 3, 4, 5]);
            assert.ok(verifyChain(await s.chainRows('node-1')).ok);
        });

        test('a different row under a stored id is rejected', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1, 2, 3], { target: 'u/other' }));
            const res = await s.ingestReplicated(chain([1, 2, 3]));
            assert.deepEqual([res.rejectedFromSeq, res.inserted], [1, 0]);
            assert.equal(res.reason, 'row evt-1: differs from the stored row with that id');
            assert.ok((await stored(s)).every((x) => x[2] === 'u/other'));
        });

        test('a new row at a stored seq is rejected', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1, 2]));
            const res = await s.ingestReplicated([seal('genesis', row(1, { id: 'evt-x1' }))]);
            assert.equal(res.rejectedFromSeq, 1);
            assert.equal(res.reason, "row evt-x1: seq 1 on node 'node-1' is stored as row evt-1");
            assert.deepEqual(await seqs(s), [1, 2]);
        });

        test('a new row must link to the stored row before it', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1, 2]));
            const res = await s.ingestReplicated(chain([3, 4], { prev: '0'.repeat(64) }));
            assert.equal(res.rejectedFromSeq, 3);
            assert.equal(res.reason, 'row evt-3: prev_hash does not match stored row evt-2');
            assert.deepEqual(await seqs(s), [1, 2]);
        });

        test('the stored row after a new one must link to it', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3]);
            await s.ingestReplicated([rows[0]]);
            await s.ingestReplicated([rows[2]]);
            const filler = [seal(rows[0].hash, row(2, { target: 'u/other' }))];
            const res = await s.ingestReplicated(filler);
            assert.equal(res.rejectedFromSeq, 2);
            assert.equal(res.reason, 'row evt-2: stored row evt-3 does not link to it');
            assert.equal((await s.ingestReplicated([rows[1]])).rejectedFromSeq, null);
        });

        test('a kept row is checked against the stored row after it', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3, 4, 5, 6]);
            await s.ingestReplicated(rows.slice(0, 4));
            await s.ingestReplicated([rows[5]]);
            const other = chain([5, 6], { prev: rows[3].hash, target: 'u/other' });
            other[1] = seal(other[0].hash, row(6, { id: 'evt-x6', target: 'u/other' }));
            const res = await s.ingestReplicated(other);
            assert.deepEqual([res.rejectedFromSeq, res.inserted], [5, 0]);
            assert.equal((await s.ingestReplicated([rows[4]])).rejectedFromSeq, null);
        });

        test('one id on two nodes in a batch is rejected', async () => {
            const s = await fresh();
            const res = await s.ingestReplicated([...chain([1]), ...chain([1], { node: 'node-2' })]);
            assert.deepEqual([res.rejectedFromSeq, res.inserted], [1, 0]);
            assert.equal(res.reason, "row evt-1: also in this batch at seq 1 on node 'node-1'");
            assert.deepEqual(await stored(s), []);
        });

        test('one id twice on one node in a batch is rejected', async () => {
            const s = await fresh();
            const res = await s.ingestReplicated(chain([1, 2, 3], { id: 'evt-x' }));
            assert.deepEqual([res.rejectedFromSeq, res.inserted], [1, 0]);
            assert.match(res.reason, /two sealed copies with different hashes/);
        });

        test('an unsealed row before the chain is skipped; after it, it is a break', async () => {
            const s = await fresh();
            const head = [unsealed(1), ...chain([2, 3])];
            assert.deepEqual(await s.ingestReplicated([...head, head[2]]), { inserted: 2, rejectedFromSeq: null, reason: null });
            assert.deepEqual(await seqs(s), [2, 3]);
            // In the batch.
            const t = await fresh();
            const res = await t.ingestReplicated([unsealed(1), ...chain([2]), unsealed(5)]);
            assert.deepEqual([res.rejectedFromSeq, res.inserted], [5, 1]);
            assert.match(res.reason, /no hash after the node's chain started/);
            // Against the stored rows.
            for (const batch of [[unsealed(4), ...chain([5, 6])], [unsealed(4)]]) {
                const u = await fresh();
                await u.ingestReplicated(chain([1, 2, 3]));
                const r = await u.ingestReplicated(batch);
                assert.deepEqual(r, { inserted: 0, rejectedFromSeq: 4, reason: "row evt-4: no hash after the node's chain started" });
                assert.deepEqual(await seqs(u), [1, 2, 3]);
            }
        });

        test('a row after a stored unsealed row links to genesis', async () => {
            const s = await fresh();
            await s.insert(unsealed(1));
            assert.equal((await s.ingestReplicated(chain([2], { prev: 'f'.repeat(64) }))).rejectedFromSeq, 2);
            assert.deepEqual(await s.ingestReplicated(chain([2])), { inserted: 1, rejectedFromSeq: null, reason: null });
        });

        test('a form-1 row without a form id is stored as form 1', async () => {
            const s = await fresh();
            // Python's original form, sealed by hand.
            const [py] = parseJson(readFileSync(new URL('../../spec/python-sealed-forms.json', import.meta.url), 'utf8'))
                .cases.map((c) => c.row);
            for (const formId of [null, '']) {
                const t = await fresh();
                assert.equal((await t.ingestReplicated([{ ...py, canonical_form_id: formId }])).inserted, 1);
                const back = await t.chainRows(py.source_node_id);
                assert.deepEqual(back.map((r) => r.canonical_form_id), ['1']);
                assert.ok(verifyChain(back).ok);
            }
            assert.equal(await s.count(), 0);
        });

        test('rows from the local node are refused', async () => {
            const s = await fresh();
            // Continuing the local chain.
            const res = await s.ingestReplicated(chain([1, 2]), { localNodeId: 'node-1' });
            assert.deepEqual(res, { inserted: 0, rejectedFromSeq: 1, reason: "row evt-1: source_node_id 'node-1' is this node" });
            // A mixed batch is cut at the lowest local seq; other nodes' rows
            // from there are left for the sender to resend.
            const batch = [...chain([1, 2, 3], { node: 'node-2' }), seal('genesis', row(2, { id: 'evt-local' }))];
            const res2 = await s.ingestReplicated(batch, { localNodeId: 'node-1' });
            assert.deepEqual(res2, { inserted: 1, rejectedFromSeq: 2, reason: "row evt-local: source_node_id 'node-1' is this node" });
            assert.deepEqual(await seqs(s), [1]);
            // An earlier break is still the one reported.
            const t = await fresh();
            const broken = chain([1, 2, 3], { node: 'node-2' });
            broken[0] = { ...broken[0], target: 'u/evil' };
            const res3 = await t.ingestReplicated([...broken, seal('genesis', row(3, { id: 'evt-l3' }))], { localNodeId: 'node-1' });
            assert.equal(res3.rejectedFromSeq, 1);
            assert.match(res3.reason, /hash mismatch/);
            // Without a local node id there is no such check.
            const u = await fresh();
            assert.equal((await u.ingestReplicated(chain([1]), { localNodeId: '' })).inserted, 1);
        });

        test('a row the batch cannot read throws ChainError naming it', async () => {
            const s = await fresh();
            await assert.rejects(s.ingestReplicated([chain([1])[0], { monotonic_seq: 'x' }]),
                (err) => err instanceof ChainError && /^rows\[1\]: /.test(err.message));
            await assert.rejects(s.ingestReplicated(['not json']), ChainError);
        });

        test('a timestamp that is not RFC 3339 is refused by insert, insertSealed and ingest', async () => {
            const s = await fresh();
            for (const ts of ['yesterday', '2026-02-30T10:00:00.000000Z', '2026-08-21T10:00:00+24:00']) {
                await assert.rejects(s.insert({ ...row(0, { id: `evt-own-${ts}` }), timestamp: ts }),
                    (err) => err instanceof AuditRowRejectedError && /timestamp .* is not an RFC 3339 timestamp/.test(err.message), ts);
                // seal() hashes the text it cannot read as it is, so the row verifies.
                const bad = chain([1, 2]);
                bad[1] = seal(bad[0].hash, { ...row(2), timestamp: ts });
                assert.ok(verifyChain(bad).ok);
                await assert.rejects(s.insertSealed(bad[1]), AuditRowRejectedError, ts);
                await assert.rejects(s.ingestReplicated(bad),
                    (err) => err instanceof ChainError && /^rows\[1\]: timestamp /.test(err.message), ts);
            }
            await assert.rejects(s.insertSealed({ ...chain([1])[0], shipped_at: 'soon' }),
                (err) => err instanceof AuditRowRejectedError && /shipped_at "soon"/.test(err.message));
            assert.deepEqual(await stored(s), []);
            // Another offset is put in the wire form.
            await s.insert({ ...row(0, { id: 'evt-offset' }), timestamp: '2026-08-21T12:00:00.5+02:00' });
            assert.equal((await s.query({}))[0].timestamp, '2026-08-21T10:00:00.500000Z');
        });

        test('rows ingested from another node are not listed to ship again', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1, 2], { node: 'node-2' }));
            const own = await s.insert({ ...row(0, { id: 'evt-own', node: 'node-9' }), monotonic_seq: 0 });
            assert.equal((await s.listUnshipped(10)).length, 3);
            const mine = await s.listUnshipped(10, { serviceId: 'svc', sourceNodeId: 'node-9', exact: true });
            assert.deepEqual(mine.map((r) => r.id), [own.id]);
            // What the scoped, exact listing gives is what another store ingests.
            const t = await fresh();
            assert.deepEqual(await t.ingestReplicated(mine.map((r) => JSON.stringify(r))),
                { inserted: 1, rejectedFromSeq: null, reason: null });
        });

        test('listUnshipped takes both of serviceId and sourceNodeId, or neither', async () => {
            const s = await fresh();
            await assert.rejects(s.listUnshipped(10, { serviceId: 'svc' }), TypeError);
            await assert.rejects(s.listUnshipped(10, { sourceNodeId: 'node-1' }), TypeError);
            assert.deepEqual(await s.listUnshipped(10, {}), []);
        });

        test('purge takes a Date or a timestamp in any offset', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1, 2]));
            await s.markShipped(['evt-1', 'evt-2']);
            // evt-1 is 10:30:01Z, evt-2 10:30:02Z.
            assert.equal(await s.purge({ before: '2026-06-15T16:00:01.5+05:30' }), 1);
            assert.equal(await s.purge({ before: new Date('2026-06-15T10:30:03Z') }), 1);
            await assert.rejects(s.purge({ before: 'not a date' }), /bad before/);
            assert.equal(await s.count(), 0);
        });

        test('an insert error mid-batch stores nothing and leaves no transaction open', async () => {
            const s = await fresh();
            const rows = chain([1, 2, 3, 4]);
            const insertRow = s._insertRow.bind(s);
            let n = 0;
            s._insertRow = (...args) => {
                if (++n === 3) throw Object.assign(new Error('disk full'), { code: 'SQLITE_FULL' });
                return insertRow(...args);
            };
            await assert.rejects(s.ingestReplicated(rows), /disk full/);
            s._insertRow = insertRow;
            assert.equal(await s.count(), 0);
            if (name === 'SqliteStore') {
                assert.equal(s._db.isTransaction, false);
            } else {
                assert.equal(s._pool.idleCount, s._pool.totalCount);
            }
            assert.deepEqual(await s.ingestReplicated(rows), { inserted: 4, rejectedFromSeq: null, reason: null });
            assert.ok(verifyChain(await s.chainRows('node-1')).ok);
        });

        test('local rows given out of order: the batch is cut at the lowest local seq, every time', async () => {
            const s = await fresh();
            const batch = [
                ...chain([1, 2, 3, 4], { node: 'node-2' }),
                seal('genesis', row(3, { id: 'evt-l3' })),
                seal('genesis', row(2, { id: 'evt-l2' })),
            ];
            const want = { inserted: 1, rejectedFromSeq: 2, reason: "row evt-l2: source_node_id 'node-1' is this node" };
            assert.deepEqual(await s.ingestReplicated(batch, { localNodeId: 'node-1' }), want);
            // Sent again, it is refused again, and nothing more is stored.
            assert.deepEqual(await s.ingestReplicated(batch, { localNodeId: 'node-1' }), want);
            assert.deepEqual(await stored(s), [[1, 'evt-1', 'u/1']]);
        });

        if (name === 'PostgresStore') test('rows stored meanwhile by another writer three times over: it gives up', async () => {
            const s = await fresh();
            await s.ingestReplicated(chain([1], { node: 'node-2' }));
            const transaction = s._transaction.bind(s);
            let rounds = 0;
            s._transaction = (fn) => transaction((client) => {
                rounds++;
                return fn({
                    query: (q, p) => (/SELECT hash FROM \S+ WHERE id = /.test(q) && p?.[0] === 'evt-1'
                        ? Promise.resolve({ rows: [] }) : client.query(q, p)),
                });
            });
            await assert.rejects(s.ingestReplicated(chain([1, 2])), /rows kept being stored by another writer/);
            s._transaction = transaction;
            assert.equal(rounds, 3);
            assert.deepEqual(await stored(s), [[1, 'evt-1', 'u/1']]);
        });

        if (name === 'PostgresStore') test('a COMMIT whose answer was lost: the resend is a re-delivery', async () => {
            const s = await fresh();
            await s._ensureReady();
            const rows = chain([1, 2, 3]);
            const connect = s._pool.connect.bind(s._pool);
            let commits = 0;
            s._pool.connect = async () => {
                const client = await connect();
                const q = client.query.bind(client);
                client.query = async (...args) => {
                    const res = await q(...args);
                    if (args[0] === 'COMMIT' && ++commits === 1) {
                        throw Object.assign(new Error('terminating connection'), { code: '57P01', severity: 'FATAL' });
                    }
                    return res;
                };
                return client;
            };
            try {
                await assert.rejects(s.ingestReplicated(rows), (err) => err.code === '57P01');
            } finally {
                s._pool.connect = connect;
            }
            assert.equal(await s.count(), 3);
            assert.deepEqual(await s.ingestReplicated(rows), { inserted: 3, rejectedFromSeq: null, reason: null });
            assert.equal(await s.count(), 3);
            assert.ok(verifyChain(await s.chainRows('node-1')).ok);
        });

        test('a row stored meanwhile is not counted as stored', async () => {
            const s = await fresh();
            // evt-1 is stored on node-2; the batch carries evt-1 on node-1, and
            // the first stored-row lookup for it misses, as when another writer
            // stores it between the checks and the insert.
            await s.ingestReplicated(chain([1], { node: 'node-2' }));
            const rows = chain([1, 2]);
            let calls = 0;
            const miss = (q, id) => /SELECT hash FROM \S+ WHERE id = /.test(q) && id === 'evt-1' && ++calls === 1;
            if (name === 'SqliteStore') {
                // The write lock rules this out, so it can only be a bug: it throws.
                const get = s._get.bind(s);
                s._get = (q, ...args) => (miss(q, args[0]) ? null : get(q, ...args));
                await assert.rejects(s.ingestReplicated(rows), /evt-1/);
                s._get = get;
            } else {
                // The node locks do not cover ids: the batch is checked again.
                const transaction = s._transaction.bind(s);
                s._transaction = (fn) => transaction((client) => fn({
                    query: (q, p) => (miss(q, p?.[0]) ? Promise.resolve({ rows: [] }) : client.query(q, p)),
                }));
                const res = await s.ingestReplicated(rows);
                s._transaction = transaction;
                assert.ok(calls >= 2);
                assert.deepEqual([res.rejectedFromSeq, res.inserted], [1, 0]);
                assert.equal(res.reason, 'row evt-1: differs from the stored row with that id');
            }
            assert.deepEqual(await stored(s), [[1, 'evt-1', 'u/1']]);
        });
    });
}

// ── Engine ─────────────────────────────────────────────────────────────────

registerCodes('ting', { TING_EVENT: { domain: 'ting', action: 'do', severity: 'info', retentionClass: 'long' } });

test('the engine ingests other nodes, refuses its own, and lists only its own rows', async () => {
    const s = new SqliteStore(':memory:');
    const e = new Engine();
    e.init({ serviceId: 'svc', nodeId: 'node-1', auditStore: s, auditStoreFailureStrategy: 'raise' });
    const write = process.stdout.write;
    process.stdout.write = (c, ...rest) => typeof c === 'string' && c.startsWith('{"shape":') ? true : write.call(process.stdout, c, ...rest);
    try {
        const own = await e.emit({ code: 'TING_EVENT', target: 'x', detail: { price: 1.5 } });
        assert.deepEqual(await e.ingestReplicated(chain([1, 2], { node: 'node-2' })),
            { inserted: 2, rejectedFromSeq: null, reason: null });
        const res = await e.ingestReplicated([seal('genesis', row(1, { id: 'evt-n1' }))]);
        assert.equal(res.rejectedFromSeq, 1);
        assert.match(res.reason, /source_node_id 'node-1' is this node/);
        const ship = await e.listUnshipped(10);
        assert.deepEqual(ship.map((r) => r.id), [own.id]);
        await e.markShipped(ship.map((r) => r.id));
        assert.deepEqual(await e.listUnshipped(10), []);
    } finally {
        process.stdout.write = write;
        await e.resetForTests();
    }
    const bare = new Engine();
    bare.init({ serviceId: 'svc', nodeId: 'node-1', auditStore: { insert() {} } });
    try {
        await assert.rejects(bare.ingestReplicated([]), (err) => err instanceof TypeError && /ingestReplicated/.test(err.message));
    } finally {
        await bare.resetForTests();
    }
});

test('the engine drops rows a store returns that this node did not originate', async () => {
    const own = { ...row(1, { id: 'evt-own' }), service_id: 'svc', source_node_id: 'node-1' };
    const rows = [
        own,
        { ...row(2, { id: 'evt-copy' }), origin_id: 'evt-elsewhere' },
        { ...row(3, { id: 'evt-n2', node: 'node-2' }) },
        { ...row(4, { id: 'evt-svc2' }), service_id: 'svc-2' },
    ];
    const seen = [];
    const e = new Engine();
    e.init({
        serviceId: 'svc', nodeId: 'node-1', auditStoreFailureStrategy: 'raise',
        auditStore: { insert() {}, listUnshipped: async (limit, opts) => { seen.push(opts); return rows; } },
    });
    try {
        assert.deepEqual((await e.listUnshipped(10)).map((r) => r.id), ['evt-own']);
        assert.deepEqual(seen, [{ serviceId: 'svc', sourceNodeId: 'node-1', exact: true }]);
    } finally {
        await e.resetForTests();
    }
});

test('the module functions use the default engine', async () => {
    const s = new SqliteStore(':memory:');
    init({ serviceId: 'svc', nodeId: 'node-m', auditStore: s, auditStoreFailureStrategy: 'raise' });
    try {
        assert.deepEqual(await ingestReplicated(chain([1], { node: 'node-x' })), { inserted: 1, rejectedFromSeq: null, reason: null });
        assert.deepEqual(await listUnshipped(), []);
        await markShipped([]);
    } finally {
        await defaultEngine.resetForTests();
    }
});

// ── Rows sealed by Python and Go ───────────────────────────────────────────

const vector = (path) => parseJson(readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8'));

// The detail column text of each stored row, by id.
async function rawDetails(s) {
    const sql = `SELECT id, detail FROM ${s._table}`;
    const rows = s instanceof SqliteStore ? s._db.prepare(sql).all() : (await s._pool.query(sql)).rows;
    return new Map(rows.map((r) => [r.id, r.detail]));
}

for (const [name, make] of BACKENDS) {
    test(`rows Python and Go sealed are ingested by ${name} as they were sealed, and verify`, { skip: name === 'PostgresStore' && !DSN }, async () => {
        for (const rows of [
            vector('spec/checkpoint-vectors.json').cases[0].rows,
            vector('spec/go-sealed-form2.json'),
            vector('spec/go-sealed-numbers.json'),
            vector('spec/rust-sealed-form2.json'),
        ]) {
            const o = await make();
            opened.push(o);
            const s = o.store;
            const res = await s.ingestReplicated(rows);
            assert.deepEqual([res.inserted, res.rejectedFromSeq], [rows.length, null], res.reason);
            const back = await s.allChainRows();
            assert.ok(verifyChain(back).ok);
            assert.deepEqual(back.map((r) => r.hash).sort(), rows.map((r) => r.hash).sort());
            // The detail column holds the sender's text, number tokens as sent.
            const raw = await rawDetails(s);
            for (const r of rows) assert.equal(raw.get(r.id), detailText(r.detail), r.id);
        }
    });
}
