// Minimal node:http service wired to fasten.
//
// What it shows in ~80 lines:
//
//   - fasten.init() reading env vars (FASTEN_SERVICE_ID, FASTEN_NODE_ID).
//   - One audit code (USER_CREATED) registered at startup.
//   - withRequestID() wraps each request — mints / honours X-Request-ID
//     and stashes it in AsyncLocalStorage for downstream emit / log.
//   - POST /users emits an audit row with the in-context request_id.
//   - GET  /users/<id> emits a read-side audit row + a structured sys log.
//   - On SIGINT/SIGTERM, fasten.flush() drains pending audit rows.
//
// Zero external deps — uses Node's built-in http.
//
// Run:
//   cd js/examples
//   FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 node server.mjs
//   curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
//   curl http://localhost:8080/users/u-42

import http from 'node:http';
import fasten, {
    register, withRequestID, mintID,
    Severity, RetentionClass,
} from '../src/index.js';

register('user', {
    USER_CREATED: {
        domain: 'user', category: 'account', action: 'create',
        severity: Severity.INFO,
        description: 'New user account',
        emitter: 'demo-svc',
        retentionClass: RetentionClass.LONG,
    },
    USER_VIEWED: {
        domain: 'user', category: 'account', action: 'view',
        severity: Severity.INFO,
        description: 'User profile read',
        emitter: 'demo-svc',
        retentionClass: RetentionClass.SHORT,
    },
});

// In-memory store for the demo. Real apps swap in SQLite / Postgres /
// any object with .insert(row).
const rows = [];
const auditStore = { insert(row) { rows.push(row); } };

fasten.init({
    serviceId: process.env.FASTEN_SERVICE_ID,
    nodeId:    process.env.FASTEN_NODE_ID,
    auditStore,
});

async function readBody(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try { return JSON.parse(Buffer.concat(chunks).toString() || '{}'); }
    catch { return {}; }
}

const server = http.createServer((req, res) => {
    const rid = req.headers['x-request-id'] ?? mintID();
    res.setHeader('x-request-id', rid);

    withRequestID(rid, async () => {
        const send = (status, body) => {
            res.writeHead(status, { 'content-type': 'application/json' });
            res.end(JSON.stringify(body));
        };

        if (req.method === 'POST' && req.url === '/users') {
            const body = await readBody(req);
            const userId = 'u-' + (body.email ?? '').slice(0, 4);
            fasten.emit({
                code: 'USER_CREATED', target: userId,
                actor: 'admin',
                detail: { email: body.email },
            });
            return send(200, { user_id: userId });
        }

        if (req.method === 'GET' && req.url?.startsWith('/users/')) {
            const userId = req.url.slice('/users/'.length);
            fasten.emit({ code: 'USER_VIEWED', target: userId, actor: 'admin' });
            fasten.log.info('user_lookup', { user_id: userId });
            return send(200, { user_id: userId, exists: true });
        }

        if (req.method === 'GET' && req.url === '/health') {
            return send(200, { ok: true });
        }

        send(404, { error: 'not found' });
    });
});

const port = Number(process.env.PORT ?? 8080);
server.listen(port, () => console.log(`listening on :${port}`));

for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, async () => {
        console.log('shutting down — flushing audit queue');
        await fasten.flush(5000);
        server.close(() => process.exit(0));
    });
}
