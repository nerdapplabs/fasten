/**
 * Redact conformance — loads spec/redact-conformance.json, runs every case.
 *
 * The spec is the single source of truth; fasten-core/src/redact.rs is canonical.
 * All SDKs must pass every case; failures indicate a divergence from the Rust impl.
 */
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

    // Stripe live key — constructed at runtime so the literal sk_live_<24+ chars>
    // never appears in source (GitHub push-protection false-positive).
    test('value_stripe_live', () => {
        const key = 'sk' + '_live_' + 'A'.repeat(24);
        const got = JSON.parse(coreRedact(JSON.stringify({ note: key })));
        assert.deepStrictEqual(got, { note: '***STRIPE_KEY***' });
    });
});
