// Shared by the reader tests: an in-memory sealing audit store, an
// in-memory stream store, and a server around a reader.
import http from 'node:http';
import { GENESIS, seal } from '../src/index.js';

// Seals rows like PostgresStore and reads them like it: newest first,
// filtered, with count, search, sources and chainTail.
export class MemoryAuditStore {
    constructor() {
        this.rows = [];
    }

    seals() {
        return true;
    }

    insert(row) {
        const mine = this.rows.filter((r) => r.source_node_id === row.source_node_id);
        const sealed = seal(mine.at(-1)?.hash ?? GENESIS, { ...row, monotonic_seq: mine.length + 1 });
        this.rows.push(sealed);
        return sealed;
    }

    _match(f = {}) {
        return this.rows.filter((r) =>
            (!f.requestId || r.request_id === f.requestId)
            && (!f.code || r.code === f.code)
            && (!f.domain || r.domain === f.domain)
            && (!f.sourceNodeId || r.source_node_id === f.sourceNodeId)
            && (!f.tenantId || r.tenant_id === f.tenantId)
            && (!f.actor || r.actor === f.actor)
            && (!f.target || r.target === f.target)
            && (!f.since || r.timestamp >= f.since)
            && (!f.until || r.timestamp <= f.until));
    }

    _newest(rows) {
        return [...rows].sort((a, b) =>
            (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : b.monotonic_seq - a.monotonic_seq));
    }

    query({ limit = 100, offset = 0, afterSeq = 0, ...f } = {}) {
        let rows = this._newest(this._match(f));
        if (afterSeq > 0) rows = rows.filter((r) => r.monotonic_seq < afterSeq);
        return rows.slice(offset, offset + limit);
    }

    count(f = {}) {
        return this._match(f).length;
    }

    search({ q, since, until, limit = 50, tenantId = null }) {
        const needle = q.toLowerCase();
        return this._newest(this.rows.filter((r) =>
            r.timestamp >= since && (!until || r.timestamp <= until)
            && (tenantId == null || r.tenant_id === tenantId)
            && JSON.stringify(r.detail, (k, v) => (typeof v === 'bigint' ? String(v) : v)).toLowerCase().includes(needle))).slice(0, limit);
    }

    sources() {
        const groups = new Map();
        for (const r of this.rows) {
            const k = JSON.stringify([r.source_node_id, r.service_id, r.tenant_id]);
            const g = groups.get(k) ?? {
                source_node_id: r.source_node_id, service_id: r.service_id,
                tenant_id: r.tenant_id, rows: 0, first_seen: r.timestamp, last_seen: r.timestamp,
            };
            g.rows++;
            if (r.timestamp < g.first_seen) g.first_seen = r.timestamp;
            if (r.timestamp > g.last_seen) g.last_seen = r.timestamp;
            groups.set(k, g);
        }
        return [...groups.values()].sort((a, b) => b.rows - a.rows);
    }

    chainTail(node, limit) {
        return this.rows.filter((r) => r.source_node_id === node)
            .sort((a, b) => a.monotonic_seq - b.monotonic_seq).slice(-limit);
    }
}

// A stream store in memory, with the PostgresStreamStore methods.
export class MemoryStreamStore {
    constructor({ fail = false } = {}) {
        this.rows = [];
        this.fail = fail;
        this.writeFailures = 0;
    }

    insert(row) {
        if (this.fail) {
            return Promise.reject(Object.assign(
                new Error(`value ${JSON.stringify(row)} violates a constraint`), { name: 'NotNullViolation' }));
        }
        this.rows.unshift(JSON.parse(JSON.stringify(row)));
        return Promise.resolve();
    }

    noteWriteFailure() {
        this.writeFailures++;
    }

    get degraded() {
        return this.writeFailures > 0;
    }

    _match(f) {
        return this.rows.filter((r) =>
            (!f.level || r.level === f.level)
            && (!f.requestId || r.request_id === f.requestId)
            && (!f.serviceId || r.service_id === f.serviceId)
            && (!f.event || r.event === f.event)
            && (!f.method || r.method === f.method)
            && (!f.path || r.path === f.path)
            && (f.status == null || r.status === f.status)
            && (!f.since || (r.timestamp ?? '') >= f.since)
            && (!f.until || (r.timestamp ?? '') <= f.until));
    }

    query({ limit = 100, ...f } = {}) {
        return this._match(f).slice(0, limit);
    }

    countMatching(f = {}) {
        return this._match(f).length;
    }

    search({ q, since, until, limit = 50 }) {
        const needle = q.toLowerCase();
        return this.rows.filter((r) => (r.timestamp ?? '') >= since
            && (!until || (r.timestamp ?? '') <= until)
            && JSON.stringify(r).toLowerCase().includes(needle)).slice(0, limit);
    }

    purge({ before }) {
        if (before instanceof Date) before = before.toISOString().replace(/Z$/, '000Z');
        const n = this.rows.length;
        this.rows = this.rows.filter((r) => !(r.timestamp && r.timestamp < before));
        return n - this.rows.length;
    }
}

// Runs fn(get) against a server for `handler`; get(path, headers) resolves
// { status, body, text, headers }.
export async function serve(handler, fn) {
    const server = http.createServer((req, res) => handler(req, res));
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address();
    const get = async (path, headers = {}, method = 'GET') => {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers, method });
        const text = await res.text();
        let body = null;
        try {
            body = JSON.parse(text);
        } catch {
            // Not JSON.
        }
        return { status: res.status, body, text, headers: res.headers };
    };
    try {
        return await fn(get);
    } finally {
        await new Promise((r) => server.close(r));
    }
}

// Runs fn with fasten's stdout and stderr lines captured.
export async function captureLines(fn) {
    const out = [];
    const err = [];
    const [ow, ew] = [process.stdout.write, process.stderr.write];
    const ours = (chunk) => typeof chunk === 'string' && (chunk.startsWith('{"shape":') || chunk.startsWith('fasten: '));
    process.stdout.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ow.call(process.stdout, chunk, ...rest);
        out.push(chunk);
        rest.find((x) => typeof x === 'function')?.();
        return true;
    };
    process.stderr.write = (chunk, ...rest) => {
        if (!ours(chunk)) return ew.call(process.stderr, chunk, ...rest);
        err.push(chunk);
        rest.find((x) => typeof x === 'function')?.();
        return true;
    };
    try {
        await fn();
    } finally {
        process.stdout.write = ow;
        process.stderr.write = ew;
    }
    return { out, err };
}
