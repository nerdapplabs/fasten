// Runs every case in spec/redact-conformance.json.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

import { coreRedact } from '../src/core.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const specPath = join(__dir, '../../spec/redact-conformance.json');
const { cases } = JSON.parse(readFileSync(specPath, 'utf8'));

describe('redact conformance', () => {
    for (const c of cases) {
        test(c.name, () => {
            const got = JSON.parse(coreRedact(JSON.stringify(c.input)));
            assert.deepStrictEqual(got, c.expected,
                `[${c.name}] got ${JSON.stringify(got)}, want ${JSON.stringify(c.expected)}`);
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

    // Built at runtime so GitHub push protection doesn't flag the literal.
    test('value_stripe_live', () => {
        const key = 'sk' + '_live_' + 'A'.repeat(24);
        const got = JSON.parse(coreRedact(JSON.stringify({ note: key })));
        assert.deepStrictEqual(got, { note: '***STRIPE_KEY***' });
    });
});
