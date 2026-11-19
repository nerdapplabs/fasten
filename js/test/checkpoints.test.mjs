// Chain checkpoints (spec §9): the file format, the file sink, loading,
// checkpointsSince, publishing from a store, and the HTTP sink.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
            assert.throws(() => checkpointsSince([cp('a', 1, HASH, at)], new Date(0)), /canonical/, at);
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
        const rows = [...chainOf('node-\u{1f600}', 2), ...chainOf('node-', 3), { id: 'u', monotonic_seq: 9, source_node_id: 'node-x', hash: '' }];
        const path = file();
        const published = await publishCheckpoints(store(rows), new FileCheckpointSink(path));
        assert.deepEqual(published.map((c) => [c.source_node_id, c.monotonic_seq]), [['node-', 3], ['node-\u{1f600}', 2]]);
        assert.equal(new Set(published.map((c) => c.anchored_at)).size, 1);
        const checkpoints = await loadCheckpoints(path);
        assert.deepEqual(checkpoints, published);
        assert.ok(verifyChain(rows, { checkpoints }).ok);
        const cut = rows.filter((r) => r.id !== 'evt-node--3');
        const res = verifyChain(cut, { checkpoints });
        assert.equal(res.reason, "node 'node-': chain ends at seq 2 before checkpoint at seq 3");
        assert.ok(verifyChain(cut, { checkpoints, partial: true }).ok);
        // Re-sealed from genesis: the hash at the checkpointed seq differs.
        const resealed = chainOf('node-', 3);
        assert.ok(verifyChain(resealed).ok);
        assert.equal(verifyChain(resealed, { checkpoints, partial: true }).reason,
            'row evt-node--3: hash differs from checkpoint at seq 3');
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
                if (reply === 302) res.writeHead(302, { Location: '/elsewhere' });
                else res.writeHead(reply);
                res.end('ok');
            });
        });
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        base = `127.0.0.1:${server.address().port}`;
    });
    after(() => new Promise((r) => server.close(r)));

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
            (err) => err.message.startsWith('checkpoint sink http://127.0.0.1:1/cp: ') && !/secret|s3cret/.test(err.message));
        assert.throws(() => new HttpCheckpointSink('ftp://user:secret@host/x?y'), (err) => !/secret/.test(err.message));
    });
});
