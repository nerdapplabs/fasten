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
/** Codes that declare piiInDetail or are classified SHORT, sorted. */
export function piiCodes(): string[];
/** "30d" / "24h" / "90m" / "3600s" to milliseconds. Throws on anything else. */
export function parseDuration(s: string): number;
export function dump(): string;

// --- Row -----------------------------------------------------------------

// The row as emitted on stdout and stored.
export interface Row {
	wire_version: string; // "1"
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
	/** Replaces redacted values. Also read from FASTEN_REDACT_REPLACEMENT. */
	redactReplacement?: string | null;
	auditStoreFailureStrategy?: "queue" | "raise";
	queueCapacity?: number;
	queueRetryInitialMs?: number;
	queueRetryMaxMs?: number;
	queueRetryJitter?: boolean;
	/** Attempts per row before it is dead-lettered. Defaults to 50. */
	queueDrainMaxAttempts?: number;
	/**
	 * Redact PII rows older than this ("30d", "24h"). Also read from
	 * FASTEN_RETENTION_PII. Checked on init and then hourly.
	 */
	retentionPii?: string;
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

/**
 * Returns the row. In raise mode with a store whose `insert` returns a
 * promise, returns a promise for the row that rejects with AuditStoreError.
 */
export function emit(input: EmitInput): Row | Promise<Row>;

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
	dead_lettered_total: number;
	dead_letter_depth: number;
	// emit() never blocks; capacity only sets the warning thresholds.
	capacity_semantics: "warn_only";
}

// Returns null in raise mode (no drainer running).
export function queueStats(): QueueStats | null;

// Wait for queued rows to be written. Returns false on timeout, and true
// right away in raise mode.
export function flush(timeoutMs?: number): Promise<boolean>;

// Call on shutdown: flushes for up to half of timeoutMs, then stops the
// drainer, giving queued rows one attempt. Resolves false if a row was lost
// (audit_drain_lost_at_stop). Emits after close skip the queue.
export function close(timeoutMs?: number): Promise<boolean>;

export interface RedactExpiredOptions {
	before: Date | string;
	/** Defaults to piiCodes(). */
	codes?: string[];
	/** Recorded in each AUDIT_ROW_REDACTED row. Defaults to "retention". */
	reason?: string;
}

/**
 * Sets `detail` to null on PII rows older than `before`, writing one
 * AUDIT_ROW_REDACTED row per redacted row first (spec §7). Never deletes.
 * Returns the ids redacted.
 */
export function redactExpired(opts: RedactExpiredOptions): Promise<string[]>;

// --- Store interfaces ----------------------------------------------------

export interface Filter {
	requestId?: string;
	code?: string;
	domain?: Domain;
	sourceNodeId?: string;
	tenantId?: string;
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
	// Spec §7.1; needed by redactExpired and retentionPii.
	listRedactionCandidates?(opts: {
		before: Date | string;
		codes: string[];
	}): Promise<{
		candidates: { id: string; monotonicSeq: number }[];
		skipped: number;
	}>;
	redactRows?(opts: { ids: string[] }): Promise<string[]>;
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
	close: typeof close;

	redactExpired: typeof redactExpired;
	piiCodes: typeof piiCodes;
	parseDuration: typeof parseDuration;
	AuditStoreError: typeof AuditStoreError;
};
export default _default;
