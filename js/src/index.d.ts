// Types for fasten. Row fields are snake_case, as on the wire
// (spec/row-schema.json). Options passed to init() and emit() are camelCase.

// --- Enums ---------------------------------------------------------------

// Any string the adopter chooses (e.g. "user", "billing").
export type Domain = string;

export type Severity = "debug" | "info" | "warn" | "error" | "critical";
export type RetentionClass = "short" | "medium" | "long";
export type Method =
	| "http"
	| "mqtt"
	| "cli"
	| "scheduler"
	| "ui"
	| "agent_tool"
	| "sdk";
export type ActorKind = "user" | "service" | "schedule" | "agent";

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
	/**
	 * Detail keys that survive force-redact when piiInDetail=true.
	 * Each surviving value still passes through the secret-key redactor.
	 */
	detailPassthroughKeys?: string[];
	declaredUnused?: boolean;
}

export function register(domain: Domain, codes: Record<string, Meta>): void;
export function metaOf(code: string): Meta | undefined;
export function dump(): string;

// --- Row -----------------------------------------------------------------

// The row as emitted on stdout and stored.
export interface Row {
	id: string; // evt-<20 hex chars>
	origin_id: string; // dedup key for replication
	monotonic_seq: number;
	timestamp: string; // ISO-8601 UTC
	code: string;
	action: string;
	severity: Severity;
	service_id: string;
	source_node_id: string;
	tenant_id: string | null;
	actor: string;
	actor_kind: ActorKind;
	target: string;
	category: string;
	domain: Domain;
	method: Method;
	request_id: string; // 12-char hex
	detail: Record<string, unknown>;
	pii_in_detail?: boolean;
	shipped_at?: string | null;
}

// --- Correlation ---------------------------------------------------------

export function mintID(): string;
export function currentRequestID(): string | null;
export function withRequestID<T>(
	requestId: string,
	fn: () => T | Promise<T>,
): T | Promise<T>;

// --- Init + Emit ---------------------------------------------------------

export interface InitOptions {
	serviceId?: string;
	nodeId?: string;
	tenantId?: string | null;
	auditStore?: AuditRepository | null;
	apiStore?: AuditRepository | null;
	extraRedactKeys?: string[];
	auditStoreFailureStrategy?: "queue" | "raise";
	queueCapacity?: number;
	queueRetryInitialMs?: number;
	queueRetryMaxMs?: number;
	queueRetryJitter?: boolean;
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

// --- Store failure handling ----------------------------------------------

export class AuditStoreError extends Error {
	constructor(cause: unknown);
	cause: unknown;
}

export interface QueueStats {
	depth: number;
	capacity: number;
	high_water: number;
	drained_total: number;
	retry_count_active: number;
	in_backoff_seconds: number;
	last_error: string | null;
}

// Returns null in raise mode (no drainer running).
export function queueStats(): QueueStats | null;

// Wait for queued rows to be written. Returns false on timeout, and true
// right away in raise mode.
export function flush(timeoutMs?: number): Promise<boolean>;

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
	purge(
		before: Date | string,
		respectUnshipped: boolean,
	): Promise<number> | number;
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
	queueStats: typeof queueStats;
	flush: typeof flush;
	AuditStoreError: typeof AuditStoreError;
};
export default _default;
