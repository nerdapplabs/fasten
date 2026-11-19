// Chain checkpoints (spec §9): the file format, the file sink, loading,
// checkpointsSince, publishing from a store, and the HTTP sink.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
    Checkpoint, FileCheckpointSink, HttpCheckpointSink, PartialLastLineError,
    checkpointsSince, loadCheckpoints, publishCheckpoints, takeCheckpoints,
    seal, verifyChain, GENESIS,
} from '../src/index.js';

const HASH = 'ab'.repeat(32);
const AT = '2026-06-15T11:00:00.000000Z';
const cp = (node, seq, hash = HASH, at = AT) =>
    new Checkpoint({ source_node_id: node, monotonic_seq: seq, hash, anchored_at: at });

let dir;
before(async () => { dir = await mkdtemp(join(tmpdir(), 'fasten-cp-')); });
after(async () => { await rm(dir, { recursive: true, force: true }); });
let n = 0;
const file = () => join(dir, `cp-${++n}.jsonl`);

// Runs fn with fasten's stderr lines captured.
async function stderrOf(fn) {
    const lines = [];
    const orig = process.stderr.write;
    process.stderr.write = (chunk, ...rest) => {
        if (typeof chunk !== 'string' || !chunk.startsWith('{"shape":')) return orig.call(process.stderr, chunk, ...rest);
        lines.push(JSON.parse(chunk));
        return true;
    };
    try {
        await fn();
    } finally {
        process.stderr.write = orig;
    }
    return lines;
}

describe('format', () => {
    test('a line is the bytes Python writes', () => {
        // json.dumps(cp.to_dict(), sort_keys=True) in CPython.
        assert.equal(cp('nœud-\u{1f600}"x', 6).toLine(),
            '{"anchored_at": "2026-06-15T11:00:00.000000Z", "hash": "abababababababababababababababababababababababababababababababab", "monotonic_seq": 6, "source_node_id": "n\\u0153ud-\\ud83d\\ude00\\"x"}');
    });

    test('parse takes exactly the four fields, each of its type', () => {
        const line = cp('node-1', 6).toLine();
        assert.deepEqual(Checkpoint.parse(line), cp('node-1', 6));
        assert.deepEqual(Checkpoint.parse('{"source_node_id":"a","monotonic_seq":1,"hash":"h","anchored_at":"t","hash":"g"}').hash, 'g');
        for (const bad of [
            '[]', 'null', '{}', '{"source_node_id":"a","monotonic_seq":1,"hash":"h"}',
            '{"source_node_id":"a","monotonic_seq":1,"hash":"h","anchored_at":"t","x":1}',
            '{"Source_node_id":"a","monotonic_seq":1,"hash":"h","anchored_at":"t"}',
            '{"source_node_id":"a","monotonic_seq":1.0,"hash":"h","anchored_at":"t"}',
            '{"source_node_id":"a","monotonic_seq":-1,"hash":"h","anchored_at":"t"}',
            '{"source_node_id":"a","monotonic_seq":"1","hash":"h","anchored_at":"t"}',
            '{"source_node_id":"a","monotonic_seq":true,"hash":"h","anchored_at":"t"}',
            '{"source_node_id":1,"monotonic_seq":1,"hash":"h","anchored_at":"t"}',
            '{"source_node_id":"a","monotonic_seq":1,"hash":null,"anchored_at":"t"}',
        ]) {
            assert.throws(() => Checkpoint.parse(bad), TypeError, bad);
        }
    });

    test('the constructor needs a hash and a canonical anchored_at; parse does not', () => {
        for (const [hash, at] of [['h', AT], ['AB'.repeat(32), AT], [`${HASH}0`, AT],
            [HASH, '2026-06-15T11:00:00Z'], [HASH, '2026-06-15T11:00:00.000000+00:00'], [HASH, '2026-13-15T11:00:00.000000Z']]) {
            assert.throws(() => cp('a', 1, hash, at), TypeError, `${hash} ${at}`);
        }
        const loose = Checkpoint.parse('{"source_node_id":"a","monotonic_seq":1,"hash":"h","anchored_at":"t"}');
        assert.deepEqual([loose.hash, loose.anchored_at], ['h', 't']);
        assert.ok(loose instanceof Checkpoint);
    });
});

describe('file sink and loadCheckpoints', () => {
    test('appends lines that load back', async () => {
        const path = file();
        const sink = new FileCheckpointSink(path);
        await sink.publish([cp('a', 1), cp('b', 2)]);
        await sink.publish([]);
        await sink.publish([{ source_node_id: 'a', monotonic_seq: 3, hash: HASH, anchored_at: AT }]);
        const text = await readFile(path, 'utf8');
        assert.equal(text, [cp('a', 1), cp('b', 2), cp('a', 3)].map((c) => `${c.toLine()}\n`).join(''));
        assert.deepEqual(await loadCheckpoints(path), [cp('a', 1), cp('b', 2), cp('a', 3)]);
    });

    test('drops an unfinished last line before appending, and says so', async () => {
        const path = file();
        const cut = '{"anchored_at": "2026-06-15T11:00:00.0';
        await writeFile(path, `${cp('a', 1).toLine()}\n${cut}`);
        await assert.rejects(loadCheckpoints(path), (err) =>
            err instanceof PartialLastLineError && err.line === 2
            && err.checkpoints.length === 1 && err.checkpoints[0].monotonic_seq === 1);
        const lines = await stderrOf(() => new FileCheckpointSink(path).publish([cp('a', 2)]));
        const dropped = lines.find((l) => l.event === 'checkpoint_unfinished_line_dropped');
        assert.deepEqual([dropped.path, dropped.bytes_dropped, dropped.level], [path, cut.length, 'warn']);
        assert.deepEqual(await loadCheckpoints(path), [cp('a', 1), cp('a', 2)]);
    });

    test('adds the newline a complete last line lacks', async () => {
        const path = file();
        await writeFile(path, cp('a', 1).toLine());
        assert.deepEqual(await loadCheckpoints(path), [cp('a', 1)]);
        const lines = await stderrOf(() => new FileCheckpointSink(path).publish([cp('a', 2)]));
        assert.equal(lines.length, 0);
        assert.deepEqual(await loadCheckpoints(path), [cp('a', 1), cp('a', 2)]);
    });

    test('a file of only a cut-short line is dropped whole', async () => {
        const path = file();
        await writeFile(path, '{"anch');
        await assert.rejects(loadCheckpoints(path), (err) => err instanceof PartialLastLineError && err.checkpoints.length === 0);
        await stderrOf(() => new FileCheckpointSink(path).publish([cp('a', 1)]));
        assert.equal(await readFile(path, 'utf8'), `${cp('a', 1).toLine()}\n`);
    });

    test('a bad line in the middle, or a complete bad last line, is an error naming it', async () => {
        const path = file();
        await writeFile(path, `${cp('a', 1).toLine()}\n\n{"x": 1}\n${cp('a', 2).toLine()}\n`);
        await assert.rejects(loadCheckpoints(path), /line 3: not a checkpoint/);
        await writeFile(path, `${cp('a', 1).toLine()}\n{"x": 1}`);
        await assert.rejects(loadCheckpoints(path), (err) => !(err instanceof PartialLastLineError) && /line 2/.test(err.message));
    });

    test('refuses to truncate an unfinished last line longer than a checkpoint line', async () => {
        const path = file();
        const tail = `{"x": "${'y'.repeat(5000)}`;
        const before = `${cp('a', 1).toLine()}\n${tail}`;
        await writeFile(path, before);
        await assert.rejects(new FileCheckpointSink(path).publish([cp('a', 2)]), /not truncating it/);
        assert.equal(await readFile(path, 'utf8'), before);
    });

    test('a failed close after a failed write reports the write', async () => {
        const path = file();
        const probe = await open(path, 'a+');
        const proto = Object.getPrototypeOf(probe);
        await probe.close();
        const { appendFile, stat } = proto;
        // close is set on each handle, so it is swapped on the first call
        // the sink makes.
        proto.stat = async function (...args) {
            const close = this.close;
            this.close = async () => { await close.call(this); throw new Error('close failed'); };
            return stat.apply(this, args);
        };
        proto.appendFile = async () => { throw Object.assign(new Error('no space'), { code: 'ENOSPC' }); };
        try {
            await assert.rejects(new FileCheckpointSink(path).publish([cp('a', 1)]), { code: 'ENOSPC' });
            // With the write fine, the close's own failure is reported.
            proto.appendFile = appendFile;
            await assert.rejects(new FileCheckpointSink(path).publish([cp('a', 1)]), /close failed/);
        } finally {
            proto.appendFile = appendFile;
            proto.stat = stat;
        }
    });

    test('an unwritable path rejects, and publishCheckpoints passes the error on', async () => {
        const path = join(dir, 'missing-dir', 'cp.jsonl');
        await assert.rejects(new FileCheckpointSink(path).publish([cp('a', 1)]), { code: 'ENOENT' });
        const tips = { chainTips: async () => [{ source_node_id: 'a', monotonic_seq: 1, hash: HASH }] };
        await assert.rejects(publishCheckpoints(tips, new FileCheckpointSink(path)), { code: 'ENOENT' });
    });

    test('reads a file the Python and Go sinks wrote', async () => {
        const path = file();
        // Python: sort_keys with ", " and ": "; Go: struct order, compact.
        await writeFile(path, '{"anchored_at": "2026-06-15T11:00:00.000000Z", "hash": "' + HASH + '", "monotonic_seq": 6, "source_node_id": "node-1"}\n'
            + '{"source_node_id":"node-2","monotonic_seq":7,"hash":"' + HASH + '","anchored_at":"2026-06-15T11:00:00.000000Z"}\n');
        assert.deepEqual(await loadCheckpoints(path), [cp('node-1', 6), cp('node-2', 7)]);
    });
});

describe('checkpointsSince', () => {
    test('keeps those anchored at or after the cutoff, in order', () => {
        const list = [cp('a', 1, HASH, '2026-06-15T10:00:00.000000Z'), cp('b', 2, HASH, '2026-06-15T12:00:00.000000Z'), cp('c', 3)];
        assert.deepEqual(checkpointsSince(list, new Date('2026-06-15T11:00:00Z')).map((c) => c.source_node_id), ['b', 'c']);
        assert.deepEqual(checkpointsSince(list, '2026-06-15T11:00:00.000001Z').map((c) => c.source_node_id), ['b']);
    });

    test('rejects an anchored_at not in the canonical form', () => {
        for (const at of ['2026-06-15T10:30:45Z', '2026-06-15T10:30:45.123456+00:00', '2026-13-15T10:30:45.123456Z', '2026-06-15T10:30:60.123456Z', '']) {
            const loose = { source_node_id: 'a', monotonic_seq: 1, hash: HASH, anchored_at: at };
            assert.throws(() => checkpointsSince([loose], new Date(0)), /canonical/, at);
        }
        assert.throws(() => checkpointsSince([], '2026-06-15'), /canonical/);
    });
});

describe('publishing from a store', () => {
    // A store whose rows are in memory; every sealed row is a tip, newest
    // first, and takeCheckpoints reduces them to one per node.
    function store(rows) {
        return { chainTips: async () => rows.filter((r) => r.hash).reverse() };
    }
    function chainOf(node, n) {
        const out = [];
        for (let seq = 1; seq <= n; seq++) {
            out.push(seal(out.at(-1)?.hash ?? GENESIS, {
                id: `evt-${node}-${seq}`, origin_id: `evt-${node}-${seq}`, monotonic_seq: seq,
                timestamp: '2026-06-15T10:30:00.000000Z', code: 'C', source_node_id: node, detail: { seq },
            }));
        }
        return out;
    }

    test('one checkpoint per node, by node id, that the rows verify against', async () => {
        const rows = [...chainOf('node-\u{1f600}', 2), ...chainOf('node-\ue000', 3), { id: 'u', monotonic_seq: 9, source_node_id: 'node-x', hash: '' }];
        const path = file();
        const published = await publishCheckpoints(store(rows), new FileCheckpointSink(path));
        assert.deepEqual(published.map((c) => [c.source_node_id, c.monotonic_seq]), [['node-\ue000', 3], ['node-\u{1f600}', 2]]);
        assert.equal(new Set(published.map((c) => c.anchored_at)).size, 1);
        const checkpoints = await loadCheckpoints(path);
        assert.deepEqual(checkpoints, published);
        assert.ok(verifyChain(rows, { checkpoints }).ok);
        const cut = rows.filter((r) => r.id !== 'evt-node-\ue000-3');
        const res = verifyChain(cut, { checkpoints });
        assert.equal(res.reason, "node 'node-\ue000': chain ends at seq 2 before checkpoint at seq 3");
        assert.ok(verifyChain(cut, { checkpoints, partial: true }).ok);
        // Re-sealed from genesis: the hash at the checkpointed seq differs.
        const resealed = chainOf('node-\ue000', 3);
        assert.ok(verifyChain(resealed).ok);
        assert.equal(verifyChain(resealed, { checkpoints, partial: true }).reason,
            'row evt-node-\ue000-3: hash differs from checkpoint at seq 3');
    });

    test('takeCheckpoints keeps each node\'s highest sealed tip, whatever the order and type', async () => {
        const h = (c) => c.repeat(64);
        const tips = [
            { source_node_id: 'b', monotonic_seq: '9', hash: h('1') },
            { source_node_id: 'a', monotonic_seq: '10', hash: h('2') },
            // Stale: below a tip already seen, as text "9" > "10" would not be.
            { source_node_id: 'a', monotonic_seq: '9', hash: h('3') },
            { source_node_id: 'b', monotonic_seq: 12, hash: '' },
            { source_node_id: 'b', monotonic_seq: 11, hash: h('4') },
            { source_node_id: 'c', monotonic_seq: 3, hash: '' },
        ];
        const got = await takeCheckpoints({ chainTips: async () => tips });
        assert.deepEqual(got.map((c) => [c.source_node_id, c.monotonic_seq, c.hash]), [['a', 10, h('2')], ['b', 11, h('4')]]);
    });

    test('publishing with no sealed rows publishes nothing and warns', async () => {
        const path = file();
        let published;
        const lines = await stderrOf(async () => {
            published = await publishCheckpoints(store([{ id: 'u', monotonic_seq: 1, source_node_id: 'n', hash: '' }]), new FileCheckpointSink(path));
        });
        assert.deepEqual(published, []);
        await assert.rejects(readFile(path), { code: 'ENOENT' });
        const warned = lines.filter((l) => l.event === 'checkpoint_no_sealed_rows');
        assert.deepEqual(warned.map((l) => l.level), ['warn']);
    });

    test('nothing is published when reading the tips fails', async () => {
        const path = file();
        const failing = { chainTips: async () => { throw new Error('db down'); } };
        await assert.rejects(publishCheckpoints(failing, new FileCheckpointSink(path)), /db down/);
        await assert.rejects(readFile(path), { code: 'ENOENT' });
        assert.deepEqual(await takeCheckpoints(store([])), []);
    });
});

describe('HTTP sink', () => {
    let server;
    let base;
    const seen = [];
    let reply = 204;
    before(async () => {
        server = createServer((req, res) => {
            let body = '';
            req.on('data', (c) => { body += c; });
            req.on('end', () => {
                seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, type: req.headers['content-type'], body });
                if (req.url === '/slow') return; // never answers
                if (reply === 302) res.writeHead(302, { Location: '/elsewhere' });
                else res.writeHead(reply);
                res.end('ok');
            });
        });
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        base = `127.0.0.1:${server.address().port}`;
    });
    after(() => new Promise((r) => { server.closeAllConnections(); server.close(r); }));

    test('POSTs one JSON array, with userinfo as Basic auth and not in the url', async () => {
        reply = 204;
        seen.length = 0;
        await new HttpCheckpointSink(`http://us%40er:p%3Ass@${base}/cp?token=x`).publish([cp('a', 1), cp('b', 2)]);
        assert.equal(seen.length, 1);
        const [req] = seen;
        assert.deepEqual([req.method, req.url, req.type], ['POST', '/cp?token=x', 'application/json']);
        assert.equal(req.auth, `Basic ${Buffer.from('us@er:p:ss').toString('base64')}`);
        assert.deepEqual(JSON.parse(req.body), [cp('a', 1).toJSON(), cp('b', 2).toJSON()]);
        await new HttpCheckpointSink(`http://${base}/cp`).publish([]);
        assert.equal(seen.length, 1);
    });

    test('a 200 or 201 is a published batch', async () => {
        for (const status of [200, 201]) {
            reply = status;
            seen.length = 0;
            await new HttpCheckpointSink(`http://${base}/cp`).publish([cp('a', 1)]);
            assert.equal(seen.length, 1, String(status));
        }
    });

    test('a request past the timeout fails, naming the timeout', async () => {
        await assert.rejects(
            new HttpCheckpointSink(`http://user:secret@${base}/slow`, { timeoutMs: 100 }).publish([cp('a', 1)]),
            (err) => err.message === `checkpoint sink http://${base}/slow: TimeoutError` && err.cause?.name === 'TimeoutError');
    });

    test('anything but 2xx fails, a redirect is not followed, and errors hide userinfo and query', async () => {
        for (const status of [302, 500]) {
            reply = status;
            seen.length = 0;
            await assert.rejects(
                new HttpCheckpointSink(`http://user:secret@${base}/cp?token=s3cret`).publish([cp('a', 1)]),
                (err) => err.message === `checkpoint sink http://${base}/cp: HTTP ${status}`);
            assert.equal(seen.length, 1);
        }
        await assert.rejects(
            new HttpCheckpointSink('http://user:secret@127.0.0.1:1/cp?token=s3cret').publish([cp('a', 1)]),
            (err) => err.message.startsWith('checkpoint sink http://127.0.0.1:1/cp: ')
                && !/secret|s3cret/.test(err.message) && err.cause instanceof Error);
        assert.throws(() => new HttpCheckpointSink('ftp://user:secret@host/x?y'), (err) => !/secret/.test(err.message));
    });
});
