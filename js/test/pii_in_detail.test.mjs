/**
 * P1-5: pii_in_detail enforcement (JS parity with Python + Go).
 *
 * 1. register() forces retentionClass=SHORT and warns when piiInDetail=true
 * 2. emit() force-redacts detail; passthrough keys survive (still scrubbed)
 * 3. row.pii_in_detail mirrors meta.piiInDetail
 */
import { test, beforeEach, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    init, emit, register, metaOf,
    REDACT_REPLACEMENT, RetentionClass,
    registry, _clearRustRegistry,
} from '../src/index.js';

function clear() {
    _clearRustRegistry();
    registry().clear();
}

// Capture console.warn calls.
function captureWarn(fn) {
    const original = console.warn;
    const calls = [];
    console.warn = (...args) => calls.push(args.join(' '));
    try { fn(); } finally { console.warn = original; }
    return calls;
}

// ── #1 force SHORT at registration ────────────────────────────────────────

describe('P1-5 register: piiInDetail forces SHORT', () => {
    beforeEach(clear);

    test('forces SHORT and warns when adopter set LONG', () => {
        const warnings = captureWarn(() => {
            register('pii', {
                PII_LONG_OVERRIDE: {
                    domain: 'pii', category: 'p', action: 'view',
                    severity: 'info', description: 'x', emitter: 't',
                    piiInDetail: true,
                    retentionClass: RetentionClass.LONG,
                },
            });
        });
        assert.equal(metaOf('PII_LONG_OVERRIDE').retentionClass, RetentionClass.SHORT);
        assert.ok(
            warnings.some(w => w.includes('PII_LONG_OVERRIDE') && w.includes('forced to SHORT')),
            `expected warning about forced override; got: ${warnings.join(' | ')}`,
        );
    });

    test('no warning when adopter already declared SHORT', () => {
        const warnings = captureWarn(() => {
            register('pii', {
                PII_ALREADY_SHORT: {
                    domain: 'pii', category: 'p', action: 'view',
                    severity: 'info', description: 'x', emitter: 't',
                    piiInDetail: true,
                    retentionClass: RetentionClass.SHORT,
                },
            });
        });
        assert.equal(
            warnings.filter(w => w.includes('PII_ALREADY_SHORT') && w.includes('forced')).length,
            0,
        );
    });

    test('non-PII code keeps adopter retentionClass', () => {
        register('pii', {
            NON_PII_LONG: {
                domain: 'pii', category: 'p', action: 'view',
                severity: 'info', description: 'x', emitter: 't',
                piiInDetail: false,
                retentionClass: RetentionClass.LONG,
            },
        });
        assert.equal(metaOf('NON_PII_LONG').retentionClass, RetentionClass.LONG);
    });
});

// ── #2 force-redact + passthrough at emit ─────────────────────────────────

describe('P1-5 emit: force-redact + passthrough', () => {
    beforeEach(() => {
        clear();
        init({ serviceId: 'svc', nodeId: 'node' });
    });

    test('whole detail is force-redacted for PII codes', () => {
        register('pii', {
            PII_FULL_REDACT: {
                domain: 'pii', category: 'p', action: 'view',
                severity: 'info', description: 'x', emitter: 't',
                piiInDetail: true,
            },
        });
        const row = emit({
            code: 'PII_FULL_REDACT', target: 'u-42',
            detail: { city: 'Mumbai', ip: '203.0.113.1' },
        });
        assert.ok(!('city' in row.detail), 'city must not survive force-redact');
        assert.ok(!('ip' in row.detail), 'ip must not survive force-redact');
        assert.equal(row.detail._redacted, REDACT_REPLACEMENT);
        assert.equal(row.detail._pii_in_detail, true);
        assert.equal(row.pii_in_detail, true);
    });

    test('passthrough keys survive', () => {
        register('pii', {
            PII_PARTIAL: {
                domain: 'pii', category: 'p', action: 'view',
                severity: 'info', description: 'x', emitter: 't',
                piiInDetail: true,
                detailPassthroughKeys: ['region'],
            },
        });
        const row = emit({
            code: 'PII_PARTIAL', target: 'u-42',
            detail: { city: 'Mumbai', region: 'MH', api_key: 'sk-secret' },
        });
        assert.equal(row.detail.region, 'MH');
        assert.ok(!('city' in row.detail));
        assert.ok(!('api_key' in row.detail), 'api_key not in passthrough → gone entirely');
        assert.equal(row.detail._redacted, REDACT_REPLACEMENT);
    });

    test('passthrough still runs secret-key redactor on the value', () => {
        register('pii', {
            PII_PASSTHROUGH_SECRET: {
                domain: 'pii', category: 'p', action: 'view',
                severity: 'info', description: 'x', emitter: 't',
                piiInDetail: true,
                detailPassthroughKeys: ['api_key'],
            },
        });
        const row = emit({
            code: 'PII_PASSTHROUGH_SECRET', target: 'u-42',
            detail: { api_key: 'sk-secret' },
        });
        assert.equal(row.detail.api_key, REDACT_REPLACEMENT);
    });

    test('non-PII code keeps detail (only secret keys redacted)', () => {
        register('nonpii', {
            NON_PII_BASIC: {
                domain: 'nonpii', category: 'p', action: 'view',
                severity: 'info', description: 'x', emitter: 't',
            },
        });
        const row = emit({
            code: 'NON_PII_BASIC', target: 'u-42',
            detail: { city: 'Mumbai', api_key: 'sk-secret' },
        });
        assert.equal(row.detail.city, 'Mumbai');
        assert.equal(row.detail.api_key, REDACT_REPLACEMENT);
        assert.ok(!('_redacted' in row.detail));
        assert.ok(!('_pii_in_detail' in row.detail));
        assert.equal(row.pii_in_detail, false);
    });
});
