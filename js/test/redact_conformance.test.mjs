// Runs every case in spec/redact-conformance.json.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

import { coreRedact, coreRedactFull } from '../src/core.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const specPath = join(__dir, '../../spec/redact-conformance.json');
// Numbers are kept as written in the spec, so each case's input reaches
// coreRedact as the same JSON text the other runners send.
const asWritten = (_k, v, ctx) => (typeof v === 'number' ? JSON.rawJSON(ctx.source) : v);
const { cases } = JSON.parse(readFileSync(specPath, 'utf8'), asWritten);
// Compares numbers by their text: 9007199254740993 is not 9007199254740992.
const numbersAsText = (_k, v, ctx) => (typeof v === 'number' ? { number: ctx.source } : v);

describe('redact conformance', () => {
    for (const c of cases) {
        test(c.name, () => {
            const out = coreRedactFull(JSON.stringify(c.input), null, null, c.check_numbers === true);
            const got = JSON.parse(out, numbersAsText);
            const want = JSON.parse(JSON.stringify(c.expected), numbersAsText);
            assert.deepStrictEqual(got, want,
                `[${c.name}] got ${out}, want ${JSON.stringify(c.expected)}`);
        });
    }

    test('long values redact quickly', () => {
        for (const note of [
            'eyJ'.repeat(50000) + '.eyJ.x',
            '1 '.repeat(75000),
            'a://b:'.repeat(25000),
            'Bearer '.repeat(20000),
        ]) {
            const t0 = performance.now();
            coreRedact(JSON.stringify({ note }));
            const ms = performance.now() - t0;
            assert.ok(ms < 1000, `redacting ${note.length} chars took ${ms.toFixed(0)} ms`);
        }
    });

    test('a __proto__ key is kept and redacted like any other', () => {
        const out = coreRedact('{"__proto__":{"password":"hunter2","n":1},"ok":1}');
        assert.equal(out, '{"__proto__":{"password":"***","n":1},"ok":1}');
        const got = JSON.parse(out);
        assert.equal(Object.getPrototypeOf(got), Object.prototype);
        assert.equal(Object.getPrototypeOf(JSON.parse(coreRedact('{"a":1}'))), Object.prototype);
    });

    test('with checkNumbers, numbers with no fractional part follow the card rule', () => {
        const on = (json) => coreRedactFull(json, null, null, true);
        assert.equal(
            on('{"a":9704000000000000008,"b":-4111111111111111,"c":18446744073709551615}'),
            '{"a":"***CC***","b":"***CC***","c":18446744073709551615}',
        );
        assert.equal(
            on('{"f":4111111111111111.0,"e":4.111111111111111e15,"n":42,"t":true,"z":null}'),
            '{"f":"***CC***","e":"***CC***","n":42,"t":true,"z":null}',
        );
        assert.equal(
            on('{"x":4111111111111111.5,"l":1234567890123456,"m":-9.704000000000016e18}'),
            '{"x":4111111111111111.5,"l":1234567890123456,"m":"***CC***"}',
        );
    });

    test('numbers are kept with checkNumbers off', () => {
        const input = '{"card":4111111111111111,"f":4111111111111111.5,"big":9704000000000000008}';
        assert.equal(coreRedact(input), input);
        assert.equal(coreRedactFull(input, null, '[gone]'), input);
    });

    test('a number card keeps the card token with a custom replacement', () => {
        assert.equal(
            coreRedactFull('{"card":4111111111111111,"token":"x"}', null, '[gone]', true),
            '{"card":"***CC***","token":"[gone]"}',
        );
    });

    // Built at runtime so GitHub push protection doesn't flag the literal.
    test('value_stripe_live', () => {
        const key = 'sk' + '_live_' + 'A'.repeat(24);
        const got = JSON.parse(coreRedact(JSON.stringify({ note: key })));
        assert.deepStrictEqual(got, { note: '***STRIPE_KEY***' });
    });
});
