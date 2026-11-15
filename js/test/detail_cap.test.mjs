// A detail or log line over FASTEN_MAX_DETAIL_BYTES is replaced by a
// truncation marker, as in Python and Go.
import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { register, init, emit, log, _clearCoreRegistry, registry } from '../src/index.js';

describe('detail cap', () => {
    beforeEach(() => {
        _clearCoreRegistry();
        registry().clear();
        delete process.env.FASTEN_MAX_DETAIL_BYTES;
        register('user', { USER_SEEN: { domain: 'user', action: 'read', severity: 'info' } });
        init({ serviceId: 'svc', nodeId: 'node' });
    });

    test('a detail over the cap becomes a marker', () => {
        const row = emit({ code: 'USER_SEEN', target: 'u-1', detail: { note: 'x'.repeat(70_000) } });
        assert.equal(row.detail._truncated, true);
        assert.equal(row.detail._max_detail_bytes, 65536);
        assert.ok(row.detail._truncated_bytes > 70_000);
        assert.equal(row.detail.note, undefined);
    });

    test('a detail under the cap is kept', () => {
        const row = emit({ code: 'USER_SEEN', target: 'u-1', detail: { note: 'x'.repeat(60_000) } });
        assert.equal(row.detail.note.length, 60_000);
    });

    test('FASTEN_MAX_DETAIL_BYTES sets the cap', () => {
        process.env.FASTEN_MAX_DETAIL_BYTES = '100';
        const row = emit({ code: 'USER_SEEN', target: 'u-1', detail: { note: 'x'.repeat(200) } });
        assert.equal(row.detail._truncated, true);
        assert.equal(row.detail._max_detail_bytes, 100);
    });

    test('a log line over the cap keeps its envelope beside the marker', () => {
        const lines = [];
        const orig = process.stderr.write;
        const origOut = process.stdout.write;
        const capture = (chunk) => { lines.push(String(chunk)); return true; };
        process.stderr.write = capture;
        process.stdout.write = capture;
        try {
            log.info('big_event', { blob: 'x'.repeat(70_000) });
        } finally {
            process.stderr.write = orig;
            process.stdout.write = origOut;
        }
        const line = JSON.parse(lines.find((l) => l.includes('"sys"')));
        assert.equal(line.shape, 'sys');
        assert.equal(line.event, 'big_event');
        assert.equal(line._truncated, true);
        assert.equal(line.blob, undefined);
    });
});
