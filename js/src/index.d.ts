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
	/** null once redacted. A BigInt is an integer past 2^53. */
	detail: Record<string, unknown> | null;
	pii_in_detail?: boolean;
	shipped_at?: string | null;
	// Set when a store sealed the row (spec §1.4): "2", the previous row's
	// hash or "genesis", the row hash, and the detail salt and commitment.
	canonical_form_id?: string;
	prev_hash?: string;
	hash?: string;
	detail_salt?: string | null;
	detail_commitment?: string | null;
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
 * Returns the row. In raise mode it returns the row as the store returned it
 * (sealed, when the store seals), and with a store whose `insert` returns a
 * promise, a promise for that row that rejects with AuditStoreError. In
 * queue mode it returns the unsealed row at once.
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

/**
 * The store refused the row itself (a different row under a stored id, a
 * seq-0 row whose origin_id is not its id). The drainer dead-letters it.
 */
export class AuditRowRejectedError extends Error {
	constructor(message: string);
}

/** A row could not be sealed. The stores throw it with the cause. */
export class AuditSealError extends Error {
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
	/**
	 * Store the row, synchronously or with a promise. A store that seals
	 * returns (or resolves to) the sealed row, which the engine writes to
	 * stdout a second time (spec §8); anything else is ignored.
	 */
	insert(row: Row): unknown;
	/** True when insert() seals rows into the chain (spec §2.1). */
	seals?(): boolean;
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

/** What PostgresStore adds for the hash chain. */
export interface ChainStore {
	seals(): boolean;
	/** One node's rows by seq, with detail numbers exact, for verifyChain. */
	chainRows(sourceNodeId: string): Promise<ChainRow[]>;
	/** Every row, by node and seq: the whole chain. */
	allChainRows(): Promise<ChainRow[]>;
	chainTips(): Promise<ChainTip[]>;
	/** Store a row sealed elsewhere as it was sealed. */
	insertSealed(
		row: ChainRowInput,
		opts?: { detailText?: string },
	): Promise<void>;
}

// --- Hash chain (spec/chain-replication.md) ------------------------------

/** Form stamped by seal(): "2". */
export const CURRENT_CANONICAL_FORM_ID: "2";
/** prev_hash of a node's first sealed row. */
export const GENESIS: "genesis";

/** Text that is not JSON, or a row field of the wrong type. */
export class ChainError extends Error {
	constructor(message: string);
}

/** A JSON number as its source token, as parseJson gives it. */
export class JsonNumber {
	constructor(token: string);
	readonly token: string;
	valueOf(): number;
	toString(): string;
	toJSON(): unknown;
}

/**
 * A parsed JSON value: numbers are JsonNumber, objects have no prototype.
 */
export type JsonValue =
	| null
	| boolean
	| string
	| JsonNumber
	| JsonValue[]
	| { [key: string]: JsonValue };

/** A row as the chain functions read it (see toChainRow). */
export interface ChainRow {
	wire_version: string;
	id: string;
	origin_id: string;
	monotonic_seq: number;
	timestamp: string;
	code: string;
	action: string;
	severity: string;
	service_id: string;
	source_node_id: string;
	tenant_id: string | null;
	actor: string;
	actor_kind: string;
	target: string;
	category: string;
	domain: string;
	method: string;
	request_id: string;
	/** null once redacted. */
	detail: unknown;
	pii_in_detail: boolean;
	shipped_at: string | null;
	/** "" on a row that predates the field, which is form "1". */
	canonical_form_id: string;
	prev_hash: string;
	/** "" on an unsealed row. */
	hash: string;
	detail_salt: string | null;
	detail_commitment: string | null;
}

/** A wire-format row object, or one line of JSON text. */
export type ChainRowInput = Partial<ChainRow> | Row | string;

export interface ChainVerifyResult {
	/** No break found. Also true when nothing was sealed; see sealedRows. */
	ok: boolean;
	/** Rows passed in, repeats and unsealed rows included. */
	totalRows: number;
	/** Sealed rows checked, each (node, id) once. */
	sealedRows: number;
	firstBreakAt: number | null;
	firstBreakNode: string | null;
	reason: string | null;
}

export interface CheckpointLike {
	source_node_id: string;
	monotonic_seq: number;
	hash: string;
}

export interface VerifyOptions {
	/** Checkpoints to check the rows against (spec §9.3). */
	checkpoints?: Iterable<CheckpointLike>;
	/** The rows are a page, one node or a sample, not the whole chain. */
	partial?: boolean;
}

/** Python's json.loads: numbers keep their token, NaN and Infinity parse. */
export function parseJson(text: string): JsonValue;
/** CPython's json.dumps(v, sort_keys=True, separators=(",", ":")). */
export function canonicalJSON(value: unknown): string;
/** Compare two strings by code point, the order Python sorts them in. */
export function compareCodePoints(a: string, b: string): number;
/** sha256(salt + canonical JSON of detail) as hex (spec §1.4). */
export function detailCommitment(salt: string, detail: unknown): string;
/** The row's hash under its canonical_form_id; null for an unknown form. */
export function rowHash(row: ChainRowInput): string | null;
/** A copy of row sealed after prevHash, at the monotonic_seq it carries. */
export function seal<T extends object>(
	prevHash: string,
	row: T,
): T & {
	canonical_form_id: "2";
	prev_hash: string;
	hash: string;
	detail_salt: string;
	detail_commitment: string;
};
/** Read a wire-format row or JSON line. Throws ChainError. */
export function toChainRow(input: ChainRowInput): ChainRow;
/** Walk each node's chain and report the first break (spec §3, §9.3). */
export function verifyChain(
	rows: Iterable<ChainRowInput>,
	opts?: VerifyOptions,
): ChainVerifyResult;

// --- Checkpoints (spec §9) -----------------------------------------------

export class Checkpoint implements CheckpointLike {
	constructor(fields: {
		source_node_id: string;
		monotonic_seq: number;
		hash: string;
		anchored_at: string;
	});
	readonly source_node_id: string;
	readonly monotonic_seq: number;
	readonly hash: string;
	/** Canonical UTC time, YYYY-MM-DDTHH:MM:SS.ffffffZ. */
	readonly anchored_at: string;
	/** Parse one line of a checkpoint file. Throws TypeError. */
	static parse(line: string): Checkpoint;
	/** The file line Python's sink writes, without the newline. */
	toLine(): string;
	toJSON(): Record<string, unknown>;
}

/** A checkpoint file's last line is cut short. */
export class PartialLastLineError extends Error {
	path: string;
	/** Line number of the cut-short line, from 1. */
	line: number;
	/** The whole checkpoints before it. */
	checkpoints: Checkpoint[];
}

export interface CheckpointSink {
	publish(checkpoints: Checkpoint[]): Promise<void> | void;
}

export class FileCheckpointSink implements CheckpointSink {
	constructor(path: string);
	path: string;
	publish(checkpoints: (Checkpoint | CheckpointLike)[]): Promise<void>;
}

export class HttpCheckpointSink implements CheckpointSink {
	constructor(url: string, opts?: { timeoutMs?: number });
	publish(checkpoints: (Checkpoint | CheckpointLike)[]): Promise<void>;
}

/** A node's latest sealed row. */
export interface ChainTip {
	source_node_id: string;
	monotonic_seq: number;
	hash: string;
}

export interface CheckpointStore {
	chainTips(): Promise<ChainTip[]> | ChainTip[];
}

export function takeCheckpoints(store: CheckpointStore): Promise<Checkpoint[]>;
export function publishCheckpoints(
	store: CheckpointStore,
	sink: CheckpointSink,
): Promise<Checkpoint[]>;
export function loadCheckpoints(path: string): Promise<Checkpoint[]>;
export function checkpointsSince<T extends { anchored_at: string }>(
	checkpoints: Iterable<T>,
	cutoff: Date | string,
): T[];

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
	AuditRowRejectedError: typeof AuditRowRejectedError;
	AuditSealError: typeof AuditSealError;
	ChainError: typeof ChainError;
	CURRENT_CANONICAL_FORM_ID: typeof CURRENT_CANONICAL_FORM_ID;
	GENESIS: typeof GENESIS;
	JsonNumber: typeof JsonNumber;
	canonicalJSON: typeof canonicalJSON;
	compareCodePoints: typeof compareCodePoints;
	detailCommitment: typeof detailCommitment;
	parseJson: typeof parseJson;
	rowHash: typeof rowHash;
	seal: typeof seal;
	toChainRow: typeof toChainRow;
	verifyChain: typeof verifyChain;
	Checkpoint: typeof Checkpoint;
	PartialLastLineError: typeof PartialLastLineError;
	FileCheckpointSink: typeof FileCheckpointSink;
	HttpCheckpointSink: typeof HttpCheckpointSink;
	takeCheckpoints: typeof takeCheckpoints;
	publishCheckpoints: typeof publishCheckpoints;
	loadCheckpoints: typeof loadCheckpoints;
	checkpointsSince: typeof checkpointsSince;
};
export default _default;
