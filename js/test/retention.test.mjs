import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Engine, parseDuration, piiCodes, register } from '../src/index.js';

test('parseDuration accepts s/m/h/d', () => {
    assert.equal(parseDuration('30d'), 30 * 86_400_000);
    assert.equal(parseDuration('24h'), 86_400_000);
    assert.equal(parseDuration(' 90M '), 90 * 60_000);
    assert.equal(parseDuration('3600s'), 3_600_000);
});

test('parseDuration rejects malformed input', () => {
    for (const bad of ['', 'd', '30', '30w', '0d', '-1d', '1.5h', '1d2h', 'abcd', null, 30]) {
        assert.throws(() => parseDuration(bad), Error, String(bad));
    }
});

test('piiCodes lists piiInDetail and SHORT codes', () => {
    register('ret', {
        RET_PII: { domain: 'ret', action: 'x', piiInDetail: true },
        RET_SHORT: { domain: 'ret', action: 'x', retentionClass: 'short' },
        RET_LONG: { domain: 'ret', action: 'x', retentionClass: 'long' },
    });
    const codes = piiCodes();
    assert.ok(codes.includes('RET_PII'));
    assert.ok(codes.includes('RET_SHORT'));
    assert.ok(!codes.includes('RET_LONG'));
});

test('init rejects retentionPii with a store that cannot redact', () => {
    const e = new Engine();
    assert.throws(() => e.init({
        serviceId: 's', nodeId: 'n', retentionPii: '30d', auditStore: { insert() {} },
    }), /retentionPii/);
    assert.throws(() => e.init({ serviceId: 's', nodeId: 'n', retentionPii: '30x' }), /unit/);
    e.resetForTests();
});

test('redactExpired refuses a store without the redaction methods', async () => {
    const e = new Engine();
    e.init({ serviceId: 's', nodeId: 'n', auditStore: { insert() {} } });
    await assert.rejects(e.redactExpired({ before: new Date() }), /listRedactionCandidates/);
    e.resetForTests();
});
