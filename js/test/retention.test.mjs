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

test('listRedactionCandidates canonicalises a string cutoff', async () => {
    const { PostgresStore } = await import('../src/store/postgres.js');
    const seen = [];
    const store = Object.create(PostgresStore.prototype);
    store._table = 't';
    store._ensureReady = async () => {};
    store._pool = { query: async (_sql, params) => { seen.push(params[0]); return { rows: [{ count: 0 }] }; } };
    await store.listRedactionCandidates({ before: '2026-10-01T00:00:00+05:30', codes: ['X'] });
    assert.equal(seen[0], '2026-09-30T18:30:00.000000Z');
    await assert.rejects(store.listRedactionCandidates({ before: 'not a date', codes: ['X'] }));
});

test('a re-init during a redaction pass does not redact the same row twice', async () => {
    const records = [];
    let listed = 0;
    const store = {
        insert: async (row) => { if (row.code === 'AUDIT_ROW_REDACTED') records.push(row.target); },
        listRedactionCandidates: async () => {
            listed++;
            await new Promise((r) => setTimeout(r, 50));
            return records.length ? { candidates: [], skipped: 0 }
                : { candidates: [{ id: 'evt-1', monotonicSeq: 1 }], skipped: 0 };
        },
        redactRows: async ({ ids }) => ids,
    };
    const e = new Engine();
    const opts = { serviceId: 's', nodeId: 'n', auditStore: store, retentionPii: '30d',
        auditStoreFailureStrategy: 'raise' };
    e.init(opts);
    await new Promise((r) => setTimeout(r, 10));
    e.init(opts);
    await new Promise((r) => setTimeout(r, 200));
    e.resetForTests();
    assert.equal(listed, 1);
    assert.deepEqual(records, ['evt-1']);
});
