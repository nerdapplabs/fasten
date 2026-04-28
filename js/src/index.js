/**
 * fasten — audit + correlation SDK for Node.js.
 *
 * Same shape as the Python + Go references: 6 anchors (5 Ws + H) +
 * correlation, opt-in shims, pluggable store, mountable reader.
 *
 * See ../README.md for the full design.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

// --- Correlation context --------------------------------------------------

const als = new AsyncLocalStorage();

export function mintID() {
    return randomUUID().replace(/-/g, '').slice(0, 12);
}

export function currentRequestID() {
    return als.getStore()?.requestId ?? null;
}

export function withRequestID(requestId, fn) {
    return als.run({ requestId }, fn);
}

// --- Code catalog ---------------------------------------------------------

const registry = new Map();

// Domain is a plain string — adopters define their own vocabulary.
// fasten ships no built-in domain constants; use string literals in your codes module.
export const Domain = {}; // kept for import compatibility; intentionally empty

export const Severity = Object.freeze({
    DEBUG: 'debug', INFO: 'info', WARN: 'warn', ERROR: 'error', CRITICAL: 'critical',
});

export const RetentionClass = Object.freeze({
    SHORT: 'short', MEDIUM: 'medium', LONG: 'long',
});

export function register(domain, codes) {
    for (const [id, meta] of Object.entries(codes)) {
        if (registry.has(id)) throw new Error(`duplicate code: ${id}`);
        if (meta.domain !== domain) throw new Error(
            `code ${id} declares domain=${meta.domain} but registered under ${domain}`
        );
        registry.set(id, meta);
    }
}

export function metaOf(code) { return registry.get(code); }

export function dump() {
    return [...registry.values()]
        .map(m => [m.id, m.domain, m.severity])
        .sort()
        .map(([i, d, s]) => `${i},${d},${s}`)
        .join('\n');
}

// --- Init + Emit ----------------------------------------------------------

let config = { serviceId: '', nodeId: '', tenantId: null, auditStore: null, apiStore: null };
let seq = 0;

export function init(opts = {}) {
    config = {
        serviceId: opts.serviceId ?? process.env.FASTEN_SERVICE_ID ?? '',
        nodeId:    opts.nodeId    ?? process.env.FASTEN_NODE_ID    ?? '',
        tenantId:    opts.tenantId    ?? process.env.FASTEN_TENANT_ID    ?? null,
        auditStore: opts.auditStore ?? null,  // TODO: construct from FASTEN_AUDIT_DSN
        apiStore:   opts.apiStore   ?? null,
    };
    if (!config.serviceId || !config.nodeId) {
        throw new Error('fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required');
    }
}

export function emit({ code, target, actor = 'system', actorKind = 'service',
                       detail = {}, severity, method = 'http' }) {
    if (!config.serviceId) throw new Error('fasten.init() must be called before emit()');
    const meta = registry.get(code);
    if (!meta) throw new Error(`unknown audit code: ${code}`);

    const row = {
        id: `evt-${randomUUID().replace(/-/g, '').slice(0, 20)}`,
        edgeRowId: null,  // set below
        monotonicSeq: ++seq,
        timestamp: new Date().toISOString(),
        code, action: meta.action, severity: severity ?? meta.severity,
        serviceId: config.serviceId, sourceNodeId: config.nodeId, tenantId: config.tenantId,
        actor, actorKind,
        target, category: meta.category, domain: meta.domain,
        method, requestId: currentRequestID() ?? mintID(),
        detail,  // TODO: redact
    };
    row.edgeRowId = row.id;
    config.auditStore?.insert(row);
    return row;
}

export const log = {
    _emit(level, event, fields = {}) {
        const line = { shape: 'json', level, event, requestId: currentRequestID(), ...fields };
        process.stdout.write(JSON.stringify(line) + '\n');
    },
    info(event, fields) { this._emit('info', event, fields); },
    warn(event, fields) { this._emit('warn', event, fields); },
    error(event, fields) { this._emit('error', event, fields); },
    debug(event, fields) { this._emit('debug', event, fields); },
};

export default { init, emit, log, register, metaOf, dump,
                 mintID, currentRequestID, withRequestID,
                 Domain, Severity, RetentionClass };
