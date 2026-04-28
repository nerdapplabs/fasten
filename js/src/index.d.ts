/**
 * fasten — TypeScript types for the Node.js package.
 * Same shape as Python / Go / Rust / Java references.
 */

// --- Enums ---------------------------------------------------------------

export type Domain = 'node' | 'sync' | 'fleet' | 'agent';
export type Severity = 'debug' | 'info' | 'warn' | 'error' | 'critical';
export type RetentionClass = 'short' | 'medium' | 'long';
export type Method = 'http' | 'mqtt' | 'cli' | 'scheduler' | 'ui' | 'agent_tool';
export type ActorKind = 'user' | 'service' | 'schedule' | 'agent' | 'system';

// --- Catalog -------------------------------------------------------------

export interface Meta {
    id: string;
    domain: Domain;
    category: string;
    action: string;
    severity: Severity;
    description: string;
    emitter: string;
    retentionClass?: RetentionClass;
    highVolume?: boolean;
    piiInDetail?: boolean;
    declaredUnused?: boolean;
}

export function register(domain: Domain, codes: Record<string, Meta>): void;
export function metaOf(code: string): Meta | undefined;
export function dump(): string;

// --- Row -----------------------------------------------------------------

export interface Row {
    id: string;
    edgeRowId: string;
    monotonicSeq: number;
    timestamp: string;       // ISO-8601 UTC
    code: string;
    action: string;
    severity: Severity;
    serviceId: string;
    sourceNodeId: string;
    siteId?: string | null;
    actor: string;
    actorKind: ActorKind;
    target: string;
    category: string;
    domain: Domain;
    method: Method;
    requestId: string;
    detail: Record<string, unknown>;
    shippedAt?: string | null;
}

// --- Correlation ---------------------------------------------------------

export function mintID(): string;
export function currentRequestID(): string | null;
export function withRequestID<T>(requestId: string, fn: () => T | Promise<T>): T | Promise<T>;

// --- Init + Emit ---------------------------------------------------------

export interface InitOptions {
    serviceId?: string;
    nodeId?: string;
    siteId?: string | null;
    auditStore?: AuditRepository | null;
    apiStore?: AuditRepository | null;
    extraRedactKeys?: string[];
}

export function init(opts?: InitOptions): void;

export interface EmitInput {
    code: string;
    target: string;
    actor?: string;
    actorKind?: ActorKind;
    detail?: Record<string, unknown>;
    severity?: Severity;
    method?: Method;
}

export function emit(input: EmitInput): Row;

export interface Logger {
    debug(event: string, fields?: Record<string, unknown>): void;
    info(event: string, fields?: Record<string, unknown>): void;
    warn(event: string, fields?: Record<string, unknown>): void;
    error(event: string, fields?: Record<string, unknown>): void;
}

export const log: Logger;

// --- Store interfaces ----------------------------------------------------

export interface Filter {
    requestId?: string;
    code?: string;
    domain?: Domain;
    sourceNodeId?: string;
    since?: string;
    until?: string;
    limit?: number;
}

export interface AuditRepository {
    insert(row: Row): Promise<void> | void;
    query(filter: Filter): Promise<Row[]> | Row[];
    listUnshipped(limit: number): Promise<Row[]> | Row[];
    markShipped(ids: string[]): Promise<void> | void;
    purge(before: Date | string, respectUnshipped: boolean): Promise<number> | number;
}

export interface AuditOutboxRepository {
    enqueue(row: Row): Promise<void> | void;
    nextBatch(n: number): Promise<Row[]> | Row[];
    ack(ids: string[]): Promise<void> | void;
    requeue(ids: string[]): Promise<void> | void;
    depth(): Promise<number> | number;
}

// --- Default export ------------------------------------------------------

declare const _default: {
    init: typeof init;
    emit: typeof emit;
    log: Logger;
    register: typeof register;
    metaOf: typeof metaOf;
    dump: typeof dump;
    mintID: typeof mintID;
    currentRequestID: typeof currentRequestID;
    withRequestID: typeof withRequestID;
};
export default _default;
