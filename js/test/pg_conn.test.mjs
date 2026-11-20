// Which errors the Postgres stores take as a lost connection, and how often
// they run a call again. No database needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connectionLost, retryLost } from '../src/store/pg_conn.js';

const dbError = (code) => Object.assign(new Error(`sqlstate ${code}`), { name: 'error', severity: 'FATAL', code });

test('a lost connection is a socket error, a closed client, or class 08 or 57', () => {
    for (const err of [
        dbError('57P01'), dbError('08006'), dbError('57P03'),
        Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET', syscall: 'read' }),
        Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED', syscall: 'connect' }),
        new Error('Connection terminated unexpectedly'),
        new Error('Client has encountered a connection error and is not queryable'),
    ]) {
        assert.equal(connectionLost(err), true, err.message);
    }
    for (const err of [dbError('23505'), dbError('42P01'), dbError('40001'), new Error('row x: differs'), null]) {
        assert.equal(connectionLost(err), false, String(err?.message));
    }
});

test('retryLost runs again once per idle client and once more, and no further', async () => {
    let calls = 0;
    const lost = dbError('57P01');
    await assert.rejects(retryLost({ idleCount: 2 }, async () => {
        calls++;
        throw lost;
    }), (err) => err === lost);
    assert.equal(calls, 4);

    calls = 0;
    assert.equal(await retryLost({ idleCount: 0 }, async () => (++calls < 2 ? Promise.reject(lost) : 'ok')), 'ok');
    assert.equal(calls, 2);

    // A pool that does not count idle clients still gets one more run.
    calls = 0;
    await assert.rejects(retryLost({}, async () => {
        calls++;
        throw lost;
    }));
    assert.equal(calls, 2);
});

test('retryLost does not run again after another error or one `final` accepts', async () => {
    let calls = 0;
    await assert.rejects(retryLost({ idleCount: 5 }, async () => {
        calls++;
        throw dbError('23505');
    }));
    assert.equal(calls, 1);
    calls = 0;
    const lost = dbError('08006');
    await assert.rejects(retryLost({ idleCount: 5 }, async () => {
        calls++;
        throw lost;
    }, (err) => err === lost));
    assert.equal(calls, 1);
});
