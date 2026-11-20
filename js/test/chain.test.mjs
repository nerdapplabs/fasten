// Hashing, sealing and chain verification: the cross-SDK vectors in spec/
// and go/, CPython's canonical JSON, and tamper detection.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
    canonicalJSON, detailCommitment, detailText, JsonNumber, parseJson,
    pyFloatRepr, rowHash, sameEvent, seal, toChainRow, verifyChain,
    canonicalTimestamp, compareCodePoints, CURRENT_CANONICAL_FORM_ID, GENESIS, ChainError,
} from '../src/chain.js';
import { Checkpoint } from '../src/checkpoints.js';

const ROOT = new URL('../../', import.meta.url);
const load = (path) => parseJson(readFileSync(new URL(path, ROOT), 'utf8'));
const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

function assertVerifies(label, rows) {
    const res = verifyChain(rows);
    assert.ok(res.ok, `${label}: ${res.reason}`);
    assert.equal(res.totalRows, rows.length);
    assert.equal(res.firstBreakAt, null);
    assert.equal(res.firstBreakNode, null);
    return res;
}

function assertBreaksAt(rows, seq, reason, opts) {
    const res = verifyChain(rows, opts);
    assert.equal(res.ok, false, `verified, wanted a break at ${seq}`);
    assert.equal(res.firstBreakAt, seq, res.reason);
    assert.ok(res.reason.includes(reason), `reason ${JSON.stringify(res.reason)} lacks ${JSON.stringify(reason)}`);
    return res;
}

// A vector row's hash is a hash before it is checked against one.
function assertSealed(label, row) {
    assert.match(row.hash, /^[0-9a-f]{64}$/, `${label}: hash`);
}

function assertCommitment(label, row) {
    const r = toChainRow(row);
    if (r.canonical_form_id === '2' && r.detail !== null) {
        assert.equal(detailCommitment(r.detail_salt, r.detail), r.detail_commitment, `${label}: commitment`);
    }
}

function baseRow(seq, extra = {}) {
    return {
        wire_version: '1', id: `evt-${seq}`, origin_id: `evt-${seq}`, monotonic_seq: seq,
        timestamp: `2026-06-15T10:30:4${seq}.000000Z`, code: 'ORDER_PLACED', action: 'create',
        severity: 'info', service_id: 'gateway', source_node_id: 'node-1', tenant_id: null,
        actor: 'alice', actor_kind: 'user', target: `order/${seq}`, category: 'order',
        domain: 'sales', method: 'http', request_id: `req-${seq}`,
        detail: parseJson(`{"qty": ${seq}, "price": 75.0}`), ...extra,
    };
}

// A sealed chain of n rows on node-1, seq 1 to n.
function chain(n, node = 'node-1') {
    const out = [];
    for (let seq = 1; seq <= n; seq++) {
        out.push(seal(out.at(-1)?.hash ?? GENESIS, baseRow(seq, { source_node_id: node })));
    }
    return out;
}

describe('canonical JSON', () => {
    // Each expected value is json.dumps(json.loads(input), sort_keys=True,
    // separators=(',', ':')) in CPython.
    const cases = [
        ['{"b": 1, "a": {"d": [1, 2 ,3], "c": null}, "B": true}', '{"B":true,"a":{"c":null,"d":[1,2,3]},"b":1}'],
        ['{"a":0.00005,"b":"0.00005","c":-0,"d":[1e-7,7,{"e":1.0E+2}],"f":"x\\"0.1","g":-12.50,"h":12345678901234567890}',
            '{"a":5e-05,"b":"0.00005","c":0,"d":[1e-07,7,{"e":100.0}],"f":"x\\"0.1","g":-12.5,"h":12345678901234567890}'],
        ['{"a":1e400,"b":-1e400,"c":1e-400,"d":-1e-400}', '{"a":Infinity,"b":-Infinity,"c":0.0,"d":-0.0}'],
        ['{"qty":3,"price":75.0,"rate":5e-05}', '{"price":75.0,"qty":3,"rate":5e-05}'],
        ['{"n": 9007199254740993, "m": 123456789012345678901234567890}', '{"m":123456789012345678901234567890,"n":9007199254740993}'],
        ['"café ✓ \u{1f600}"', '"caf\\u00e9 \\u2713 \\ud83d\\ude00"'],
        ['"a\u007fb"', '"a\\u007fb"'],
        ['"\\u0000\\u001f\\b\\f\\n\\r\\t\\"\\\\\\/<>&\'"', '"\\u0000\\u001f\\b\\f\\n\\r\\t\\"\\\\/<>&\'"'],
        ['"\\ud83d\\ude00 \\u00e9"', '"\\ud83d\\ude00 \\u00e9"'],
        ['{"é": 1, "z": 2, "\u{1f600}": 3, "Z": 4}', '{"Z":4,"z":2,"\\u00e9":1,"\\ud83d\\ude00":3}'],
        ['{"a": 1, "a": 2}', '{"a":2}'],
        ['[]', '[]'],
        ['{}', '{}'],
    ];
    for (const [input, want] of cases) {
        test(`matches CPython for ${input.slice(0, 40)}`, () => {
            assert.equal(canonicalJSON(parseJson(input)), want);
        });
    }

    const fixture = JSON.parse(readFileSync(new URL('fixtures/cpython-numbers.json', import.meta.url), 'utf8'));

    // python/tests/test_canonical_form_2.py checks the fixture against
    // CPython; scripts/gen_cpython_numbers.py rewrites it.
    test('the CPython fixture has all its entries', () => {
        assert.equal(fixture.tokens.length, 207);
        assert.equal(fixture.js_numbers.length, 222);
    });

    test('number tokens render as CPython renders json.loads of them', () => {
        for (const [tok, want] of fixture.tokens) {
            assert.equal(canonicalJSON(new JsonNumber(tok)), want, `token ${tok}`);
        }
    });

    test('a JS number renders as CPython renders the token JS writes for it', () => {
        for (const [tok, want] of fixture.js_numbers) {
            const n = Number(tok);
            assert.equal(String(n), tok);
            assert.equal(canonicalJSON(n), want, `number ${tok}`);
            assert.equal(canonicalJSON(new JsonNumber(tok)), want);
        }
    });

    test('floats are repr()', () => {
        for (const [f, want] of [[75, '75.0'], [5e-5, '5e-05'], [1e16, '1e+16'], [-0, '-0.0'],
            [0.1 + 0.2, '0.30000000000000004'], [1e-7, '1e-07'], [123.456, '123.456']]) {
            assert.equal(pyFloatRepr(f), want);
        }
    });

    test('JS values', () => {
        const d = {
            whole: 75, half: 75.5, tiny: 1e-7, big: 2 ** 60, huge: 1e21, neg0: -0,
            exact: 12345678901234567890n, nan: NaN, inf: -Infinity, s: 'café\x7f', u: undefined,
            f() {}, list: [undefined, 1, null], when: new Date('2026-06-15T10:30:45.123Z'),
        };
        assert.equal(canonicalJSON(d),
            '{"big":1152921504606847000,"exact":12345678901234567890,"half":75.5,"huge":1e+21,'
            + '"inf":-Infinity,"list":[null,1,null],"nan":NaN,"neg0":0,"s":"caf\\u00e9\\u007f",'
            + '"tiny":1e-07,"when":"2026-06-15T10:30:45.123Z","whole":75}');
        const cyc = { a: 1 };
        cyc.self = cyc;
        assert.throws(() => canonicalJSON(cyc), /circular/);
    });

    test('the text a store writes keeps tokens and reads back the same', () => {
        const text = '{"n": 1.0E+2, "big": 123456789012345678901234567890, "z": -0, "f": 75.0}';
        const v = parseJson(text);
        assert.equal(detailText(v), '{"big":123456789012345678901234567890,"f":75.0,"n":1.0E+2,"z":-0}');
        assert.equal(canonicalJSON(parseJson(detailText(v))), canonicalJSON(v));
        // For JS values the stored text is the canonical text.
        const js = { a: 1e-7, b: [75, 'x'] };
        assert.equal(detailText(js), canonicalJSON(js));
    });

    test('keys sort by code point', () => {
        const keys = ['\ue000', '\u{1f600}', 'z', '\ud800', ''];
        assert.deepEqual(keys.sort(compareCodePoints), ['', 'z', '\ud800', '\ue000', '\u{1f600}']);
    });

    test('parse rejects what is not JSON', () => {
        for (const bad of ['', '{', '[1,]', '{"a":}', '01', '1.', '-', '1e', '"a', '"\\x"', 'nul',
            '"\u0001"', '{} x', '{a:1}', '"\\u12"', '+1', '.5', '-NaN', 'nan', 'Inf', '-Inf',
            '+Infinity', 'Infinit', 'NaNx', 'infinity']) {
            assert.throws(() => parseJson(bad), /json at offset|unexpected/, bad);
        }
        assert.throws(() => parseJson('['.repeat(200) + ']'.repeat(200)), /nested too deeply/);
    });

    test('a parsed object has no prototype, so __proto__ is a plain key', () => {
        const v = parseJson('{"__proto__": {"x": 1}, "a": 2}');
        assert.equal(Object.getPrototypeOf(v), null);
        assert.equal(canonicalJSON(v), '{"__proto__":{"x":1},"a":2}');
    });
});

// Expected text and hashes are CPython 3.12's, from python/fasten/chain.py:
// json.loads of the detail text, sealed with the salt shown.
const PY_SURROGATE_DETAIL = '{"name": "\\udcff.txt", "\\ud800": 1, "": 2, "\\ue000": 3, "\\ud83d\\ude00": 4, "pair": "\\ud83d\\ude00", "tail": "a\\udfffb"}';
const PY_SURROGATE_CANONICAL = '{"":2,"name":"\\udcff.txt","pair":"\\ud83d\\ude00","tail":"a\\udfffb","\\ud800":1,"\\ue000":3,"\\ud83d\\ude00":4}';
const PY_SURROGATE_COMMITMENT = 'd65606d442d772bd4fdf71642e7854181587978af7c27cbf22dafe9aca1ff5ce';
const PY_SURROGATE_HASH = '8a76f4a637269afe76df1686e0b533c1fe7b948b264a253e179ec2634cb07461';
const PY_NAN_DETAIL = '{"nan": NaN, "inf": Infinity, "ninf": -Infinity, "list": [NaN, 1.5]}';
const PY_NAN_CANONICAL = '{"inf":Infinity,"list":[NaN,1.5],"nan":NaN,"ninf":-Infinity}';
const PY_NAN_COMMITMENT = '595df41153437098fa85880c9820a81c52bb6063b15d628ee0b6dd708e618c8b';
const PY_NAN_HASH = 'de157b8f434d3a7495bae23bdc9b1d8f7985f4e96e2d35a2654c5e138022389c';

function pyRow(seq, detail, salt) {
    return {
        wire_version: '1', id: `evt-py-${seq}`, origin_id: `evt-py-${seq}`, monotonic_seq: seq,
        timestamp: '2026-06-15T10:30:45.123456Z', code: 'SENSOR_READ', action: 'read',
        severity: 'info', service_id: 'gateway', source_node_id: 'node-py', actor: 'plc-7',
        actor_kind: 'device', target: 'sensor/42', category: 'telemetry', domain: 'plant',
        method: 'mqtt', request_id: 'req-1', detail: parseJson(detail), detail_salt: salt,
    };
}

describe('strings and numbers Python stores that JSON.parse refuses or changes', () => {
    test('unpaired surrogates round-trip as CPython writes them', () => {
        for (const [text, canonical] of [
            ['"\\udcff"', '"\\udcff"'],
            ['"\\ud83d\\ude00"', '"\\ud83d\\ude00"'],
            ['"\\ude00\\ud83d"', '"\\ude00\\ud83d"'],
            ['{"\\ud800":1,"":2,"\\ue000":3,"\\ud83d\\ude00":4}', '{"":2,"\\ud800":1,"\\ue000":3,"\\ud83d\\ude00":4}'],
            [PY_SURROGATE_DETAIL, PY_SURROGATE_CANONICAL],
        ]) {
            const parsed = parseJson(text);
            assert.equal(canonicalJSON(parsed), canonical, text);
            assert.equal(canonicalJSON(parseJson(detailText(parsed))), canonical, text);
        }
    });

    test('a Python-sealed row with unpaired surrogates verifies', () => {
        const sealed = seal(GENESIS, pyRow(1, PY_SURROGATE_DETAIL, 'a0'.repeat(32)));
        assert.equal(sealed.detail_commitment, PY_SURROGATE_COMMITMENT);
        assert.equal(sealed.hash, PY_SURROGATE_HASH);
        assertVerifies('surrogates', [sealed]);
        const changed = { ...sealed, detail: parseJson(PY_SURROGATE_DETAIL.replace('udcff', 'udcfe')) };
        assertBreaksAt([changed], 1, 'detail does not match its commitment');
    });

    test('NaN and Infinity are numbers, as in Python', () => {
        assert.equal(canonicalJSON(parseJson('[NaN, Infinity, -Infinity]')), '[NaN,Infinity,-Infinity]');
        assert.equal(canonicalJSON(parseJson(PY_NAN_DETAIL)), PY_NAN_CANONICAL);
        const first = seal(GENESIS, pyRow(1, PY_SURROGATE_DETAIL, 'a0'.repeat(32)));
        const second = seal(first.hash, pyRow(2, PY_NAN_DETAIL, 'a1'.repeat(32)));
        assert.equal(second.detail_commitment, PY_NAN_COMMITMENT);
        assert.equal(second.hash, PY_NAN_HASH);
        assertVerifies('nan', [first, second]);
    });
});

describe('vectors sealed by Python and Go', () => {
    test('spec/python-sealed-forms.json', () => {
        const file = load('spec/python-sealed-forms.json');
        assert.equal(file.current_form, CURRENT_CANONICAL_FORM_ID);
        assert.equal(file.cases.length, 11);
        for (const { label, row } of file.cases) {
            assertSealed(label, row);
            assertVerifies(label, [row]);
            assertCommitment(label, row);
            // Form "1" rows sealed over the "Z" timestamp match only through
            // the verification fallback; the rest match their form's hash.
            const fallback = label.includes('legacy_Z') || label === 'form1_real_prefix_release';
            assert.equal(rowHash(row) === row.hash, !fallback, label);
        }
    });

    for (const [path, n] of [['spec/go-sealed-form2.json', 2], ['spec/go-sealed-numbers.json', 1]]) {
        test(path, () => {
            const rows = load(path);
            assert.equal(rows.length, n);
            for (const row of rows) {
                assertSealed(row.id, row);
                assert.equal(row.canonical_form_id, '2');
                assertCommitment(row.id, row);
                assert.equal(rowHash(row), row.hash, row.id);
            }
            assert.equal(assertVerifies(path, rows).sealedRows, n);
        });
    }

    test('go/xlang_form2.json, with tampering', () => {
        const cases = load('go/xlang_form2.json');
        assert.equal(cases.length, 4);
        for (const { label, row } of cases) {
            assertSealed(label, row);
            assertCommitment(label, row);
            assert.equal(rowHash(row), row.hash, label);
            assertVerifies(label, [row]);
            if (row.detail === null) continue;
            assertBreaksAt([{ ...row, detail: { qty: 999, sku: 'STOLEN' } }], 1, 'detail does not match its commitment');
            assertBreaksAt([{ ...row, detail_salt: null }], 1, 'detail_salt is missing');
        }
    });

    test('the two rows go/verify_test.go pins (form "1")', () => {
        const row = {
            wire_version: '1', id: 'evt-abc123', origin_id: 'evt-abc123', monotonic_seq: 1,
            timestamp: '2026-06-15T10:30:45.123456Z', code: 'ORDER_PLACED', action: 'create',
            severity: 'info', service_id: 'gateway', source_node_id: 'node-1', tenant_id: 'tenant-x',
            actor: 'alice', actor_kind: 'user', target: 'order/42', category: 'order', domain: 'sales',
            method: 'http', request_id: 'req-xyz', detail: { qty: 3, sku: 'WIDGET' }, prev_hash: 'genesis',
            hash: 'cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac',
        };
        assert.equal(rowHash(row), row.hash);
        assertVerifies('pyVectorHash', [row]);
        assertBreaksAt([{ ...row, target: 'order/9999' }], 1, 'hash mismatch');
        assertBreaksAt([{ ...row, detail: { qty: 4, sku: 'WIDGET' } }], 1, 'hash mismatch');
        const float = '{"id": "evt-float-vec", "origin_id": "evt-float-vec", "monotonic_seq": 1, "timestamp": "2026-06-15T10:30:45+00:00", "code": "SETPOINT_WRITE", "action": "write", "severity": "info", "service_id": "event-engine", "source_node_id": "node-1", "tenant_id": "acme", "actor": "event-engine", "actor_kind": "service", "target": "connector-opcua-01/ns=2;s=Valve", "category": "actuation", "domain": "control", "method": "sdk", "request_id": "req-float-1", "detail": {"setpoint": 75.0, "tolerance": 12.5, "retries": 7}, "wire_version": "1", "shipped_at": null, "canonical_form_id": "1", "prev_hash": "genesis", "hash": "512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b"}';
        assert.equal(rowHash(float), '512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b');
        assertVerifies('pyFloatVectorJSON', [float]);
        // JSON.parse turns 75.0 into 75, which is another detail.
        assert.equal(verifyChain([JSON.parse(float)]).ok, false);
    });

    test('a row with the detail values SDKs have rendered differently hashes as Python seals it', () => {
        const row = baseRow(1, {
            tenant_id: 'ténant', target: 'order/\u{1f600}', detail_salt: 'cd'.repeat(32),
            detail: parseJson('{"whole": 75.0, "tiny": 5e-5, "big": 1e16, "bigint": 12345678901234567890, "neg": -0.0, "text": "café ✓ <&>", "del": "a\\u007fb", "nested": {"l": [1, 2.5, null, true]}}'),
        });
        const sealed = seal(GENESIS, row);
        assert.equal(sealed.hash, '83308165fea44c3454672df0845679fb19d6d7878ad3ba71867dd9b2dd6e65f0');
        assertVerifies('cross-sdk row', [sealed]);
    });

    // Written by scripts/gen_js_vectors.mjs from the engine and PostgresStore.
    test('spec/js-sealed-form2.json', () => {
        const rows = load('spec/js-sealed-form2.json');
        assert.equal(rows.length, 6);
        const prev = new Map();
        rows.forEach((row) => {
            assertSealed(row.id, row);
            assert.equal(row.canonical_form_id, '2');
            const node = row.source_node_id;
            assert.equal(row.monotonic_seq.token, String((prev.get(node)?.seq ?? 0) + 1));
            assert.equal(row.prev_hash, prev.get(node)?.hash ?? GENESIS);
            prev.set(node, { seq: Number(row.monotonic_seq.token), hash: row.hash });
            assert.equal(rowHash(row), row.hash, `${row.id}: hash drifted`);
            if (row.detail === null) {
                assert.equal(row.detail_salt, null);
                assert.equal(row.detail_commitment.length, 64);
                return;
            }
            const again = seal(row.prev_hash, row);
            assert.equal(again.detail_commitment, row.detail_commitment, `${row.id}: commitment drifted`);
            assert.equal(again.hash, row.hash);
        });
        assert.deepEqual([...prev.keys()], ['node-js', 'node-js-u16']);
        assert.equal(rows.filter((r) => r.detail === null).length, 1);
        assert.equal(assertVerifies('js-sealed-form2', rows).sealedRows, 6);
        const details = rows.map((r) => detailText(r.detail)).join('');
        for (const token of ['"tiny":5e-05', '"micro":1e-06', '"e16":10000000000000000', '"p60":1152921504606847000',
            '"e21":1e+21', '"neg0":0', '"sum":0.30000000000000004', '"big":1180591620717411303424',
            '18446744073709551616', '-9007199254740993', '\\u00e9', '\\u007f', '"\\ue000":2', '"\\ud83d\\ude00":1',
            '"\\udcff.txt"', '{"list":[']) {
            assert.ok(details.includes(token), `${token} not in ${details}`);
        }
        assert.equal(rows[1].actor, 'op\u00e9\x7f\u{1f600}');
        assert.equal(rows[1].target, 'sensor/op\u00e9\x7f\u{1f600}');
        assert.equal(rows[0].tenant_id, 't\u00e9nant-\x7f-\u{1f600}');
        assertBreaksAt([{ ...rows[0], detail: { half: 76.5 } }, ...rows.slice(1)], 1, 'detail does not match its commitment');
    });

    test('spec/js-sealed-stdout.jsonl, as an ingester reads it', () => {
        const text = readFileSync(new URL('spec/js-sealed-stdout.jsonl', ROOT), 'utf8');
        const lines = text.split('\n');
        assert.equal(lines.pop(), '');
        const byId = new Map();
        for (const line of lines) {
            const row = parseJson(line);
            assert.equal(row.shape, 'audit');
            byId.set(row.id, [...(byId.get(row.id) ?? []), row]);
        }
        assert.equal(byId.size, 6);
        for (const [id, pair] of byId) {
            assert.deepEqual(pair.map((r) => r.hash !== ''), [false, true], id);
        }
        const stored = load('spec/js-sealed-form2.json');
        assert.deepEqual([...byId.keys()], stored.map((r) => r.id));
        assert.equal(assertVerifies('stdout', lines).sealedRows, 6);
    });
});

describe('checkpointsChecked', () => {
    test('counts the checkpoints that had a row at their seq', () => {
        const rows = chain(3);
        const checkpoints = [
            { source_node_id: 'node-1', monotonic_seq: 2, hash: rows[1].hash },
            { source_node_id: 'node-1', monotonic_seq: 3, hash: rows[2].hash },
            { source_node_id: 'node-1', monotonic_seq: 9, hash: rows[2].hash },
            { source_node_id: 'node-2', monotonic_seq: 1, hash: rows[0].hash },
        ];
        const res = verifyChain(rows, { checkpoints, partial: true });
        assert.deepEqual([res.ok, res.checkpointsChecked], [true, 2]);
        assert.equal(verifyChain(rows).checkpointsChecked, 0);
        // A mismatch was still checked.
        const bad = verifyChain(rows, { checkpoints: [{ ...checkpoints[0], hash: rows[0].hash }], partial: true });
        assert.deepEqual([bad.ok, bad.checkpointsChecked], [false, 1]);
    });
});

describe('checkpoint vectors', () => {
    const { cases } = load('spec/checkpoint-vectors.json');
    test('there are cases', () => assert.ok(cases.length >= 19));
    for (const c of cases) {
        test(c.label, () => {
            const checkpoints = c.checkpoints.map((cp) => Checkpoint.parse(canonicalJSON(cp)));
            const res = verifyChain(c.rows, { checkpoints, partial: c.partial });
            const want = c.expected;
            assert.equal(res.ok, want.ok);
            assert.equal(res.firstBreakAt, want.first_break_at === null ? null : Number(want.first_break_at));
            assert.equal(res.reason, want.reason);
        });
    }
});

describe('sealing', () => {
    test('seal stamps the current form and verifies', () => {
        const rows = chain(3);
        assert.equal(rows[0].prev_hash, GENESIS);
        assert.equal(rows[1].prev_hash, rows[0].hash);
        for (const row of rows) {
            assert.equal(row.canonical_form_id, '2');
            assert.equal(row.hash.length, 64);
            assert.equal(row.detail_salt.length, 64);
            assertCommitment(row.id, row);
        }
        assert.notEqual(rows[0].detail_salt, rows[1].detail_salt);
        assertVerifies('sealed chain', rows);
    });

    test('seal keeps the salt a row already has, and ignores shipped_at', () => {
        const row = baseRow(1, { detail_salt: 'ab'.repeat(32) });
        const sealed = seal(GENESIS, row);
        assert.equal(sealed.detail_salt, row.detail_salt);
        assert.equal(seal(GENESIS, row).hash, sealed.hash);
        const shipped = seal(GENESIS, { ...row, shipped_at: '2026-06-16T08:00:00.250000Z' });
        assert.equal(shipped.hash, sealed.hash);
        assertVerifies('shipped', [shipped]);
    });

    test('the timestamp is hashed in the wire form whatever its spelling', () => {
        const sealed = seal(GENESIS, baseRow(1, { detail_salt: 'ab'.repeat(32) }));
        for (const ts of ['2026-06-15T10:30:41Z', '2026-06-15T10:30:41.000+00:00', '2026-06-15T12:30:41+02:00']) {
            assertVerifies(ts, [{ ...sealed, timestamp: ts }]);
        }
        assert.equal(canonicalTimestamp('2026-06-15T12:30:45.5+02:00'), '2026-06-15T10:30:45.500000Z');
        assert.equal(canonicalTimestamp('2026-06-15T10:30:45.123456789Z'), '2026-06-15T10:30:45.123456Z');
        assert.equal(canonicalTimestamp('not a time'), 'not a time');
    });

    test('an offset that moves the time outside years 1 to 9999 is not a wire timestamp', () => {
        for (const ts of ['0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00']) {
            assert.equal(canonicalTimestamp(ts), ts);
        }
        assert.equal(canonicalTimestamp('0001-01-01T01:00:00+01:00'), '0001-01-01T00:00:00.000000Z');
        assert.equal(canonicalTimestamp('9999-12-31T22:59:59-01:00'), '9999-12-31T23:59:59.000000Z');
    });

    test('the sealed copy carries every hashed field as it was hashed', () => {
        const sealed = seal(GENESIS, { id: 'evt-min', monotonic_seq: 1, timestamp: '2026-06-15T12:30:41+02:00', extra: 'kept' });
        assert.deepEqual(
            [sealed.wire_version, sealed.prev_hash, sealed.timestamp, sealed.tenant_id, sealed.origin_id, sealed.extra],
            ['1', GENESIS, '2026-06-15T10:30:41.000000Z', null, '', 'kept']);
        assert.deepEqual(sealed.detail, {});
        const r = toChainRow(sealed);
        for (const k of Object.keys(r)) {
            if (k !== 'pii_in_detail' && k !== 'shipped_at') assert.deepEqual(sealed[k], r[k], k);
        }
        assertVerifies('minimal', [sealed]);
    });

    test('seal refuses a prevHash that is not genesis or a row hash, and a row it cannot read', () => {
        for (const bad of ['', 'GENESIS', 'ab', 'A'.repeat(64), `${'a'.repeat(63)}g`, undefined, null]) {
            assert.throws(() => seal(bad, baseRow(1)), ChainError, String(bad));
        }
        assert.throws(() => seal(GENESIS, { ...baseRow(1), actor: 42 }), ChainError);
        assert.throws(() => seal(GENESIS, { ...baseRow(1), target: 'doc/\ud83d' }), /unpaired surrogate/);
    });

    test('a row of JS values seals, and its line verifies with exact numbers', () => {
        const row = baseRow(1, { detail: { a: 75, b: 75.5, c: 1e-7, d: 12345678901234567890n, e: 'é\x7f' } });
        const sealed = seal(GENESIS, row);
        assertVerifies('js values', [sealed]);
        // The detail as a store writes it, read back.
        const back = { ...sealed, detail: parseJson(detailText(sealed.detail)) };
        assertVerifies('read back', [back]);
        assert.equal(detailCommitment(sealed.detail_salt, back.detail), sealed.detail_commitment);
    });
});

describe('tamper detection', () => {
    test('an empty chain verifies, with nothing sealed', () => {
        assert.deepEqual(verifyChain([]), {
            ok: true, totalRows: 0, sealedRows: 0, checkpointsChecked: 0, firstBreakAt: null, firstBreakNode: null, reason: null,
        });
        const res = verifyChain([baseRow(1), baseRow(2)]);
        assert.equal(res.ok, true);
        assert.equal(res.sealedRows, 0);
    });

    test('every hashed field is covered', () => {
        const edits = [
            (r) => { r.wire_version = '9'; }, (r) => { r.id = 'evt-x'; }, (r) => { r.origin_id = 'evt-x'; },
            (r) => { r.timestamp = '2026-06-15T10:30:42.000001Z'; }, (r) => { r.code = 'X'; },
            (r) => { r.action = 'x'; }, (r) => { r.severity = 'warn'; }, (r) => { r.service_id = 'x'; },
            (r) => { r.tenant_id = 'x'; }, (r) => { r.actor = 'mallory'; },
            (r) => { r.actor_kind = 'agent'; }, (r) => { r.target = 'x'; }, (r) => { r.category = 'x'; },
            (r) => { r.domain = 'x'; }, (r) => { r.method = 'cli'; }, (r) => { r.request_id = 'x'; },
            (r) => { r.prev_hash = 'x'; }, (r) => { r.detail_commitment = 'x'; },
            (r) => { r.canonical_form_id = '1'; }, (r) => { r.hash = '0'.repeat(64); },
            (r) => { r.detail = { qty: 2, price: 75 }; },
        ];
        edits.forEach((edit, i) => {
            const rows = chain(2);
            edit(rows[1]);
            const res = verifyChain(rows);
            assert.equal(res.ok, false, `edit ${i} verified`);
            assert.equal(res.firstBreakAt, 2, `edit ${i}`);
        });
    });

    test('removed, inserted and reordered rows break', () => {
        const removed = chain(4);
        removed.splice(1, 1);
        assertBreaksAt(removed, 3, 'row evt-3: prev_hash does not match preceding row evt-1');

        const inserted = chain(2);
        inserted.push(seal(inserted[0].hash, { ...baseRow(3), id: 'evt-forged', monotonic_seq: 2 }));
        assertBreaksAt(inserted, 2, "duplicate monotonic_seq 2 on node 'node-1'");

        const shuffled = chain(4);
        [shuffled[0], shuffled[3]] = [shuffled[3], shuffled[0]];
        assertVerifies('shuffled input', shuffled);
        const swapped = chain(4);
        swapped[1].monotonic_seq = 3;
        swapped[2].monotonic_seq = 2;
        assert.equal(verifyChain(swapped).firstBreakAt, 2);
    });

    test('a redacted row still verifies', () => {
        const rows = chain(3);
        rows[1] = { ...rows[1], detail: null, detail_salt: null };
        assertVerifies('redacted', rows);
        // As the stores write it: the salt as an empty string.
        rows[1].detail_salt = '';
        assertVerifies('redacted, empty salt', rows);
        rows[1].target = 'order/9999';
        assertBreaksAt(rows, 2, 'hash mismatch');
    });

    test('an unknown form is rejected', () => {
        const rows = chain(2);
        rows[1].canonical_form_id = '3';
        assertBreaksAt(rows, 2, 'row evt-2: unknown canonical_form_id "3"');
        assert.equal(rowHash(rows[1]), null);
    });

    test('chains are per node, and a break names its node', () => {
        const rows = [...chain(3), ...chain(3, 'node-2').map((r) => ({ ...r }))];
        // Same ids on two nodes are two rows.
        assertVerifies('two nodes', rows);
        const a = chain(3);
        const b = chain(4).map((r) => ({ ...r, source_node_id: 'node-b' }));
        a[2].target = 'order/999';
        let res = verifyChain([...a, ...b]);
        assert.deepEqual([res.firstBreakAt, res.firstBreakNode], [1, 'node-b']);
        res = verifyChain(a);
        assert.deepEqual([res.firstBreakAt, res.firstBreakNode], [3, 'node-1']);
    });

    test('unsealed rows are skipped only before the chain starts', () => {
        const early = { ...baseRow(1), id: 'evt-early' };
        const second = seal(GENESIS, baseRow(2));
        const third = seal(second.hash, baseRow(3));
        assertVerifies('unsealed head', [early, second, third]);
        assertBreaksAt([early, seal('f'.repeat(64), baseRow(2))], 2, 'first sealed row does not link to genesis');
        assertVerifies('purged head', chain(4).slice(2));
        assertBreaksAt([second, third, { ...baseRow(4), id: 'evt-late' }], 4, "row evt-late: no hash after the node's chain started");
        const tie = { ...baseRow(1), id: 'evt-tie' };
        assertBreaksAt([tie, ...chain(2)], 1, "no hash after the node's chain started");
        assertBreaksAt([...chain(2), tie], 1, "no hash after the node's chain started");
    });

    test('a row given twice is checked once', () => {
        const rows = chain(3);
        const res = assertVerifies('twice', [...rows, rows[1]]);
        assert.equal(res.sealedRows, 3);
        const unsealed = { ...rows[1], hash: '' };
        assertVerifies('unsealed first', [rows[0], unsealed, rows[1], rows[2]]);
        assertVerifies('unsealed last', [...rows, unsealed]);
        assertBreaksAt([...rows, { ...rows[1], hash: '0'.repeat(64) }], 2, 'row evt-2: two sealed copies with different hashes');
        assertBreaksAt([...rows, { ...rows[1], target: 'order/9999' }], 2, 'row evt-2: hash mismatch');
        const twin = chain(4);
        twin.push({ ...twin[2], id: 'evt-twin' });
        assertBreaksAt(twin, 3, 'duplicate monotonic_seq 3');
        twin[1].target = 'order/999';
        assertBreaksAt(twin, 2, 'hash mismatch');
    });

    test('a row without a form id is form "1"', () => {
        const row = load('spec/python-sealed-forms.json').cases[0].row;
        assertVerifies('no form id', [{ ...row, canonical_form_id: undefined }]);
    });

    test('toChainRow reads wire rows and reports bad fields', () => {
        assert.throws(() => toChainRow('[]'), /not an object/);
        assert.throws(() => toChainRow('{"id": "a"}'), /monotonic_seq.*missing/);
        assert.throws(() => toChainRow('{"monotonic_seq": 1.5}'), /monotonic_seq/);
        assert.throws(() => toChainRow('{"monotonic_seq": -1}'), /monotonic_seq/);
        assert.throws(() => toChainRow('{"monotonic_seq": 1, "id": 7}'), /"id": not a string/);
        assert.throws(() => toChainRow('{"id": "evt-\\udcff", "monotonic_seq": 1}'), /unpaired surrogate/);
        const row = toChainRow('{"monotonic_seq": 1, "detail_salt": "", "detail_commitment": ""}');
        assert.deepEqual([row.wire_version, row.prev_hash, row.hash, row.detail_salt, row.detail_commitment],
            ['1', 'genesis', '', null, null]);
        assert.equal(canonicalJSON(row.detail), '{}');
        assert.throws(() => verifyChain([baseRow(1), { id: 'x' }]), /rows\[1\]: .*monotonic_seq/);
    });

    test('sameEvent ignores the chain fields', () => {
        const a = baseRow(1, { detail: parseJson('{"k": 1.0}') });
        const sealed = { ...seal(GENESIS, { ...a, monotonic_seq: 7 }), shipped_at: '2026-06-16T08:00:00.250000Z', timestamp: '2026-06-15T12:30:41+02:00' };
        assert.ok(sameEvent(a, sealed) && sameEvent(sealed, a));
        assert.ok(sameEvent(a, { ...sealed, detail: null, detail_salt: null }));
        for (const other of [{ target: 'x' }, { detail: parseJson('{"k": 2.0}') }, { detail: { k: 1 } },
            { timestamp: '2026-06-15T10:30:41.000001Z' }, { tenant_id: 'acme' }]) {
            assert.ok(!sameEvent(a, { ...a, ...other }), JSON.stringify(other));
        }
    });
});

// Rows sealed the way older Go releases did: numbers as stored rather than
// as CPython renders them, and DEL written raw.
describe('older Go encodings', () => {
    // Whether the row verifies with the canonical encoding alone.
    const matchesCanonical = (row) => rowHash(row) === row.hash
        && (!row.detail_salt || detailCommitment(row.detail_salt, row.detail) === row.detail_commitment);

    function goSealed(row, { rawDel = false, form = '2' } = {}) {
        const r = toChainRow(row);
        const render = (v) => {
            const s = detailText(v);
            return rawDel ? s.replace(/\\\\|\\u007f/g, (m) => (m === '\\u007f' ? '\x7f' : m)) : s;
        };
        const fields = {
            action: r.action, actor: r.actor, actor_kind: r.actor_kind, canonical_form_id: form,
            category: r.category, code: r.code, domain: r.domain, id: r.id, method: r.method,
            monotonic_seq: r.monotonic_seq, origin_id: r.origin_id, prev_hash: r.prev_hash,
            request_id: r.request_id, service_id: r.service_id, severity: r.severity, shipped_at: null,
            source_node_id: r.source_node_id, target: r.target, tenant_id: r.tenant_id,
            timestamp: form === '1' ? r.timestamp.replace('.000000Z', '+00:00') : r.timestamp,
            wire_version: r.wire_version,
        };
        const out = { ...row, canonical_form_id: form };
        if (form === '2') {
            out.detail_salt = 'c'.repeat(64);
            out.detail_commitment = sha256(out.detail_salt + render(r.detail));
            fields.detail_commitment = out.detail_commitment;
        } else {
            fields.detail = r.detail;
        }
        out.hash = sha256(render(fields));
        return out;
    }

    test('rows sealed with Go\'s old number encoding verify', () => {
        const detail = '{"tiny": 0.00005, "tinier": 1e-7, "neg_zero": -0, "frac": 12.5}';
        for (const form of ['1', '2']) {
            const sealed = goSealed(baseRow(1, { detail: parseJson(detail) }), { form });
            assert.ok(!matchesCanonical(sealed));
            assertVerifies(`go numbers form ${form}`, [sealed]);
            assert.equal(verifyChain([{ ...sealed, detail: parseJson(detail.replace('0.00005', '0.00006')) }]).ok, false);
        }
    });

    test('rows sealed with DEL raw verify', () => {
        for (const form of ['1', '2']) {
            const inDetail = goSealed(baseRow(1, { detail: parseJson('{"k": "a\\u007fb", "n": 0.00005}') }), { rawDel: true, form });
            assert.ok(!matchesCanonical(inDetail));
            assertVerifies('raw DEL in detail', [inDetail]);
            const inTarget = goSealed(baseRow(1, { target: 'sensor/\x7f' }), { rawDel: true, form });
            assert.ok(!matchesCanonical(inTarget));
            assertVerifies('raw DEL in target', [inTarget]);
            assert.equal(verifyChain([{ ...inDetail, detail: parseJson('{"k": "a\\u007fc", "n": 0.00005}') }]).ok, false);
            assert.equal(verifyChain([{ ...inTarget, target: 'sensor/\x7fx' }]).ok, false);
        }
        // The six characters \u007f in a string are not DEL.
        assert.equal(canonicalJSON(parseJson('{"k": "a\\\\u007fb"}')), '{"k":"a\\\\u007fb"}');
    });

    test('rows sealed with shipped_at set verify', () => {
        const row = baseRow(1, { detail_salt: 'ab'.repeat(32) });
        const plain = seal(GENESIS, row);
        // Re-hash form "2" over the stored shipped_at, as releases before
        // spec 1.1 did.
        const shippedAt = '2026-06-16T08:00:00.250000Z';
        const r = toChainRow({ ...plain, shipped_at: shippedAt });
        const fields = Object.fromEntries(Object.entries(r).filter(([k]) =>
            !['detail', 'detail_salt', 'hash', 'pii_in_detail'].includes(k)));
        const sealed = { ...plain, shipped_at: shippedAt, hash: sha256(canonicalJSON(fields)) };
        assert.notEqual(rowHash(sealed), sealed.hash);
        assertVerifies('shipped', [sealed]);
        assert.equal(verifyChain([{ ...sealed, shipped_at: '2026-06-16T08:00:00.250001Z' }]).ok, false);
    });
});
