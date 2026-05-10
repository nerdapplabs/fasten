/**
 * fasten — TypeScript types for the Node.js package.
 *
 * The Row interface uses **snake_case** to match the wire format
 * defined in spec/row-schema.json (the same shape Python / Go / Rust /
 * C++ emit). The earlier camelCase declarations contradicted the
 * runtime: TS adopters reading `row.serviceId` got `undefined` because
 * the runtime emits `service_id`. The call-site API surface (init,
 * emit input) stays camelCase because that is what the JS runtime
 * actually accepts.
 */

// --- Enums ---------------------------------------------------------------

// Domain is adopter-defined per spec/row-schema.json (e.g. node, user,
// billing). It is intentionally NOT a closed enum — declaring it as
// one would silently fail TS adopters whose domain string is valid at
// runtime but not in the type.
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

// Wire row — snake_case, matches spec/row-schema.json. Emitted as the
// `audit` shape on stdout; callers reading rows back from stdout NDJSON
// or from a store get this exact shape.
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
	// P1-15: audit-store failure handling.
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

// --- P1-15 audit-store failure handling ----------------------------------

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

// Block until pending audit rows drain or timeout. Returns true iff
// drained. No-op + true in raise mode.
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
