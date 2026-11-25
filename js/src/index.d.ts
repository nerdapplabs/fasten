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
	/**
	 * null once redacted. An integer a number cannot hold exactly is a
	 * BigInt, in what emit() returns and in rows PostgresStore.query()
	 * reads; JSON.stringify throws on a BigInt unless given a replacer.
	 */
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
	/**
	 * Without one, FASTEN_AUDIT_DSN opens a store: PostgresStore for
	 * postgres:// or postgresql://, SqliteStore on the DSN's path for
	 * sqlite:///rel.db, sqlite:////abs.db or a bare path (?table=, ?wal=).
	 * Another scheme, or libpq's keyword form, makes init() throw.
	 */
	auditStore?: AuditRepository | null;
	/**
	 * Persists the api stream (spec persistent-streams.md). Without one,
	 * FASTEN_API_DSN opens a store (table "api_log" unless ?table=).
	 */
	apiStore?: StreamStore | null;
	/** Persists the sys stream. Without one, FASTEN_SYSLOG_DSN ("syslog"). */
	syslogStore?: StreamStore | null;
	/**
	 * The streams expected to have a store ("api", "sys"). When set (or
	 * FASTEN_PERSIST_STREAMS, comma-separated), init() throws unless it
	 * matches the attached stores both ways.
	 */
	persistStreams?: Iterable<"api" | "sys"> | null;
	/** Free-text search (q=, /search). Also FASTEN_SEARCH_ENABLED. */
	searchEnabled?: boolean;
	/**
	 * Purge api rows older than this ("7d"). Also FASTEN_RETENTION_API.
	 * Ignored without an api store.
	 */
	retentionApi?: string;
	/**
	 * Purge sys rows older than this. Also FASTEN_RETENTION_SYSLOG. Ignored
	 * without a syslog store.
	 */
	retentionSyslog?: string;
	extraRedactKeys?: string[];
	/** Replaces redacted values. Also read from FASTEN_REDACT_REPLACEMENT. */
	redactReplacement?: string | null;
	/**
	 * Checks numbers with no fractional part (integers and whole-number
	 * floats) against the card rule: a match becomes "***CC***". When unset,
	 * read from FASTEN_REDACT_NUMBERS (1, true, yes or on). Off by default.
	 */
	redactNumbers?: boolean;
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
 * Returns the row. In raise mode it returns what the store's insert()
 * returned when that is a row with the same id (the sealed row, when the
 * store seals), else the row as built; with a store whose `insert` returns a
 * promise, a promise for it that rejects with AuditStoreError. In queue mode
 * it returns the unsealed row at once.
 *
 * Throws ChainError, in both modes and before anything is written, for a
 * `target` that is not a string, or a row field that is not a string or
 * holds an unpaired surrogate.
 */
export function emit(input: EmitInput): Row | Promise<Row>;

export interface Logger {
	debug(event: string, fields?: Record<string, unknown>): void;
	info(event: string, fields?: Record<string, unknown>): void;
	warn(event: string, fields?: Record<string, unknown>): void;
	error(event: string, fields?: Record<string, unknown>): void;
}

export const log: Logger;

// --- api and sys streams (spec persistent-streams.md) --------------------

/** An api or sys row: any JSON object. */
export type StreamRow = Record<string, unknown>;

/** Equality filters (exact match) and an inclusive timestamp window. */
export interface StreamFilter {
	level?: string | null;
	requestId?: string | null;
	serviceId?: string | null;
	event?: string | null;
	method?: string | null;
	path?: string | null;
	status?: number | string | null;
	since?: string | null;
	until?: string | null;
}

/**
 * A store for one stream: PostgresStreamStore, SqliteStreamStore, or your
 * own on the same table layout. Methods may return values or promises.
 */
export interface StreamStore {
	/** Create the table. The bundled stores also do it on first use. */
	init?(): Promise<void>;
	insert(row: StreamRow): void | Promise<void>;
	/**
	 * Called for each failed or dropped write. The stream counts them too,
	 * so a store without it still reads as degraded.
	 */
	noteWriteFailure?(): void;
	/** True marks the stream degraded, as its own failure count does. */
	readonly degraded?: boolean;
	query(
		opts?: StreamFilter & { limit?: number },
	): StreamRow[] | Promise<StreamRow[]>;
	countMatching(filters?: StreamFilter): number | Promise<number>;
	search(opts: {
		q: string;
		since: string;
		until?: string | null;
		limit?: number;
	}): StreamRow[] | Promise<StreamRow[]>;
	purge?(opts: { before: Date | string }): number | Promise<number>;
	close?(): void | Promise<void>;
}

/**
 * Record a sys row from the app's own logger: redacted, kept in memory and
 * stored if a syslog store is attached. It writes no stdout line.
 */
export function pushSyslog(row: StreamRow): void;
/**
 * Record an api row: redacted, kept, stored if an api store is attached,
 * and written to stdout with shape "api".
 */
export function writeApi(row: StreamRow): void;
/** writeApi() without the stdout line. */
export function pushApi(row: StreamRow): void;

export interface ApiLoggerOptions {
	/** Paths not recorded, as sent, e.g. "/healthz". */
	skip?: Iterable<string>;
	engine?: Engine;
	/**
	 * The path to store for the request. Without it the path is stored as
	 * sent (without the query string), ids and tokens in it included.
	 */
	path?: (req: import("node:http").IncomingMessage) => string;
}

/**
 * Middleware recording one api row per request (method, path, status,
 * duration_ms, request_id, timestamp), for Express/Connect or
 * http.createServer. Sets X-Request-ID and makes the id current for the
 * request. A client's X-Request-ID is taken as sent, not authenticated,
 * unless it looks like a sentinel. A request whose connection closed before
 * the response finished gets status 499 and `aborted: true`.
 */
export function apiLogger(
	opts?: ApiLoggerOptions,
): (
	req: import("node:http").IncomingMessage,
	res: import("node:http").ServerResponse,
	next: () => unknown,
) => unknown;

export type SentinelKind = "boot" | "sched" | "bg" | "lib" | "orphan";
/** A sentinel request_id such as "bg-svc-ab12cd34ef56". */
export function mintSentinel(kind: SentinelKind, serviceId?: string): string;
export function isSentinel(requestId: unknown): boolean;

export class Engine {
	init(opts?: InitOptions): void;
	emit(input: EmitInput): Row | Promise<Row>;
	readonly log: Logger;
	queueStats(): QueueStats | null;
	flush(timeoutMs?: number): Promise<boolean>;
	close(timeoutMs?: number): Promise<boolean>;
	redactExpired(opts: RedactExpiredOptions): Promise<string[]>;
	/** See the module function listUnshipped. */
	listUnshipped(limit?: number): Promise<ChainRow[]>;
	markShipped(ids: string[]): Promise<void>;
	ingestReplicated(rows: Iterable<ChainRowInput>): Promise<IngestResult>;
	pushSyslog(row: StreamRow): void;
	writeApi(row: StreamRow): void;
	pushApi(row: StreamRow): void;
	/** Streams with a store attached. */
	persistedStreams(): Set<"audit" | "api" | "sys">;
	searchEnabled(): boolean;
	auditStore(): AuditRepository | null;
}

export const defaultEngine: Engine;

// --- Store failure handling ----------------------------------------------

export class AuditStoreError extends Error {
	constructor(cause: unknown);
	cause: unknown;
}

/**
 * The store refused the row itself (a different row under a stored id, a
 * seq-0 row whose origin_id is not its id, a seq another row holds, a row
 * field it cannot seal). The drainer dead-letters it.
 */
export class AuditRowRejectedError extends Error {
	constructor(message: string);
}

/**
 * A row could not be sealed for a reason other than its content (the random
 * source, a malformed stored prev hash). The drainer retries it.
 */
export class AuditSealError extends Error {
	constructor(cause: unknown);
	cause: unknown;
}

/**
 * The store's COMMIT failed and the row could not be read back, so whether
 * it is stored is unknown. Storing it again under the same id is safe; a
 * new emit() could store it twice. The drainer retries it.
 */
export class AuditOutcomeUnknownError extends Error {
	constructor(id: string, cause: unknown);
	cause: unknown;
}

export interface QueueStats {
	depth: number;
	capacity: number;
	high_water: number;
	drained_total: number;
	retry_count_active: number;
	in_backoff_seconds: number;
	/** The type of the latest failure ("DatabaseError"), null when healthy. */
	last_error: string | null;
	dead_lettered_total: number;
	dead_letter_depth: number;
	// emit() never blocks; capacity only sets the warning thresholds.
	capacity_semantics: "warn_only";
}

// Returns null in raise mode (no drainer running).
export function queueStats(): QueueStats | null;

// Wait for queued audit rows and running api and sys store writes, those
// of streams a re-init replaced included. Returns false on timeout; with
// no queue and no stream writes, true at once.
export function flush(timeoutMs?: number): Promise<boolean>;

// Call on shutdown: flushes for up to half of timeoutMs, then stops the
// drainer, giving queued rows one attempt, waits for api and sys store
// writes, and closes the stores opened from FASTEN_*_DSN. Resolves false
// if a row was lost (audit_drain_lost_at_stop) or the stream writes did not
// finish in time. Emits after close skip the queue.
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

/**
 * Rows the default engine's service and node originated that are not
 * shipped yet, oldest first, as the store's listUnshipped returns them with
 * exact set. Rows ingested from other nodes are left out (spec §4): any row
 * the store returns whose origin_id is not its id, or whose node or service
 * is not the engine's, is dropped. Throws TypeError without a store that
 * has listUnshipped.
 */
export function listUnshipped(limit?: number): Promise<ChainRow[]>;
/** Mark rows shipped upstream, by id, in the default engine's store. */
export function markShipped(ids: string[]): Promise<void>;
/**
 * Verify a replicated batch and store its verified prefix in the default
 * engine's store (spec §4). The batch stops at the first row from the
 * engine's node id. A chain break does not throw; it is in the result.
 */
export function ingestReplicated(
	rows: Iterable<ChainRowInput>,
): Promise<IngestResult>;

// --- Store interfaces ----------------------------------------------------

export interface Filter {
	requestId?: string;
	code?: string;
	domain?: Domain;
	sourceNodeId?: string;
	tenantId?: string;
	actor?: string;
	target?: string;
	since?: string;
	until?: string;
	limit?: number;
	offset?: number;
	/** Rows with a lower monotonic_seq only, for cursor paging. */
	afterSeq?: number;
}

export interface AuditRepository {
	/**
	 * Store the row, synchronously or with a promise. The engine uses the
	 * returned row only when it has the same `id` as the row given: emit()
	 * in raise mode returns it, and when it has a non-empty `hash` the
	 * engine writes it to stdout a second time (spec §8). Anything else
	 * (undefined, another id) is ignored and the row given is used.
	 */
	// biome-ignore lint/suspicious/noConfusingVoidType: insert() may return nothing
	insert(row: Row): Row | void | Promise<Row | void>;
	/**
	 * True when insert() seals rows into the chain (spec §2.1). Such a store
	 * returns the sealed row; if it does not, the engine logs
	 * audit_chain_row_unsealed once.
	 */
	seals?(): boolean;
	query(filter: Filter): Promise<Row[]> | Row[];
	/** Rows matching the filter; the reader's totals and doctor use it. */
	count?(
		filter?: Omit<Filter, "limit" | "offset" | "afterSeq">,
	): Promise<number> | number;
	/** /search on audit. Must honour tenantId. */
	search?(opts: {
		q: string;
		since: string;
		until?: string | null;
		limit?: number;
		tenantId?: string | null;
	}): Promise<Row[]> | Row[];
	/** /topology. Rows use the row column names, so they are snake_case. */
	sources?(opts?: {
		since?: string;
		until?: string;
	}): Promise<SourceRow[]> | SourceRow[];
	/** The doctor's chain sample: the node's newest rows by seq, oldest first. */
	chainTail?(
		sourceNodeId: string,
		limit: number,
	): Promise<ChainRow[]> | ChainRow[];
	/**
	 * Unshipped rows, oldest seq first. Engine.listUnshipped passes
	 * serviceId, sourceNodeId and exact: the store must honour them (only
	 * rows that identity originated, origin_id = id), or rows ingested from
	 * other nodes would be shipped again. The engine drops any other row
	 * it gets back.
	 */
	listUnshipped(
		limit: number,
		opts?: ListUnshippedOptions,
	): Promise<Row[] | ChainRow[]> | Row[] | ChainRow[];
	markShipped(ids: string[]): Promise<void> | void;
	purge(opts: {
		/** A Date or a timestamp; the bundled stores canonicalise it. */
		before: Date | string;
		respectUnshipped?: boolean;
	}): Promise<number> | number;
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

/** One (node, service, tenant) group from sources(). */
export interface SourceRow {
	source_node_id: string;
	service_id: string;
	tenant_id: string | null;
	rows: number;
	first_seen: string;
	last_seen: string;
}

export interface AuditOutboxRepository {
	enqueue(row: Row): Promise<void> | void;
	nextBatch(n: number): Promise<Row[]> | Row[];
	ack(ids: string[]): Promise<void> | void;
	requeue(ids: string[]): Promise<void> | void;
	depth(): Promise<number> | number;
}

/** What PostgresStore and SqliteStore add for the hash chain. */
export interface ChainStore {
	seals(): boolean;
	/**
	 * One node's rows by seq, with detail numbers exact, for verifyChain.
	 * Throws ChainError naming a row it cannot read.
	 */
	chainRows(sourceNodeId: string): Promise<ChainRow[]>;
	/** Every row, by node and seq: the whole chain. */
	allChainRows(): Promise<ChainRow[]>;
	chainTips(): Promise<ChainTip[]>;
	/**
	 * Store a row sealed elsewhere as it was sealed. Throws
	 * AuditRowRejectedError for a row it cannot read, an unsealed row, a
	 * different row under a stored id or a seq another row holds;
	 * AuditOutcomeUnknownError when the COMMIT failed and the row could not
	 * be read back; an Error when the row was neither inserted nor found.
	 */
	insertSealed(
		row: ChainRowInput,
		opts?: { detailText?: string },
	): Promise<void>;
}

export interface ListUnshippedOptions {
	/**
	 * With sourceNodeId: only rows this identity originated (origin_id = id).
	 * The bundled stores throw when only one of the two is given.
	 */
	serviceId?: string;
	sourceNodeId?: string;
	/** Rows as chainRows reads them, detail numbers as hashed, for shipping. */
	exact?: boolean;
}

export interface IngestOptions {
	/** The receiving node's id: the batch stops at its first row from it. */
	localNodeId?: string;
}

/**
 * What ingestReplicated did (spec §4). The same fields as Python's and Go's
 * IngestResult: inserted (Python inserted, Go Inserted), rejectedFromSeq
 * (rejected_from_seq, RejectedFromSeq), reason (reason, Reason).
 */
export interface IngestResult {
	/** Rows of the verified prefix passed to the insert, re-deliveries included. */
	inserted: number;
	/** monotonic_seq of the first broken row, to resend from; null when none. */
	rejectedFromSeq: number | null;
	/** Why the batch broke there; null when it did not. */
	reason: string | null;
}

/** What PostgresStore and SqliteStore add for replication. */
export interface ReplicationStore {
	insertReplicated(
		row: ChainRowInput,
		opts?: { detailText?: string },
	): Promise<void>;
	ingestReplicated(
		rows: Iterable<ChainRowInput>,
		opts?: IngestOptions,
	): Promise<IngestResult>;
}

// --- Hash chain (spec/chain-replication.md) ------------------------------

/** Form stamped by seal(), "2" in this release. */
export const CURRENT_CANONICAL_FORM_ID: string;
/** prev_hash of a node's first sealed row. */
export const GENESIS: "genesis";

/**
 * Input the chain functions cannot read: text that is not JSON (or nested
 * deeper than 128), a row that is not an object, a row field that is not a
 * string or holds an unpaired surrogate, a missing or bad monotonic_seq, a
 * circular value or one JSON cannot hold, a bad prevHash given to seal(), a
 * stored row a store cannot read back, and a row emit() cannot build.
 */
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
	/**
	 * No break found in what was checked: sealedRows rows and
	 * checkpointsChecked checkpoints. Also true when nothing was checked.
	 */
	ok: boolean;
	/** Rows passed in, repeats and unsealed rows included. */
	totalRows: number;
	/** Sealed rows checked, each (node, id) once. */
	sealedRows: number;
	/** Checkpoints that had a row at their seq to compare with. */
	checkpointsChecked: number;
	firstBreakAt: number | null;
	firstBreakNode: string | null;
	reason: string | null;
}

export interface VerifyOptions {
	/** Checkpoints to check the rows against (spec §9.3). */
	checkpoints?: Iterable<ChainTip>;
	/** The rows are a page, one node or a sample, not the whole chain. */
	partial?: boolean;
}

/** Python's json.loads: numbers keep their token, NaN and Infinity parse. */
export function parseJson(text: string): JsonValue;
/** CPython's json.dumps(v, sort_keys=True, separators=(",", ":")). */
export function canonicalJSON(value: unknown): string;
/** sha256(salt + canonical JSON of detail) as hex (spec §1.4). */
export function detailCommitment(salt: string, detail: unknown): string;
/**
 * A copy of row sealed after prevHash ("genesis" or 64 lowercase hex), at
 * the monotonic_seq it carries. The copy carries every hashed field as it
 * was hashed. Throws ChainError for a bad prevHash or a row toChainRow
 * cannot read.
 */
export function seal<T extends { monotonic_seq: number | bigint }>(
	prevHash: string,
	row: T,
): T & {
	wire_version: string;
	canonical_form_id: string;
	prev_hash: string;
	hash: string;
	detail_salt: string;
	detail_commitment: string;
};
/** Read a wire-format row or JSON line. Throws ChainError. */
export function toChainRow(input: ChainRowInput): ChainRow;
/**
 * Walk each node's chain and report the first break (spec §3, §9.3).
 *
 * Without checkpoints it cannot detect rows deleted from the end of a
 * node's chain, the start of a chain deleted (it looks like a purge), or a
 * whole chain sealed again from genesis.
 *
 * Throws ChainError for a row toChainRow cannot read, naming its index.
 */
export function verifyChain(
	rows: Iterable<ChainRowInput>,
	opts?: VerifyOptions,
): ChainVerifyResult;

// --- Checkpoints (spec §9) -----------------------------------------------

/** A node's latest sealed row at anchored_at. */
export class Checkpoint implements ChainTip {
	/**
	 * Throws TypeError unless hash is 64 lowercase hex digits and
	 * anchored_at is in the canonical form.
	 */
	constructor(fields: CheckpointFields);
	readonly source_node_id: string;
	readonly monotonic_seq: number;
	readonly hash: string;
	/** Canonical UTC time, YYYY-MM-DDTHH:MM:SS.ffffffZ. */
	readonly anchored_at: string;
	/**
	 * Parse one line of a checkpoint file. Checks the fields' types only,
	 * not the hash or anchored_at form. Throws TypeError.
	 */
	static parse(line: string): Checkpoint;
	/** The file line Python's sink writes, without the newline. */
	toLine(): string;
	toJSON(): Record<string, unknown>;
}

/** A checkpoint file's last line is cut short. */
export class PartialLastLineError extends Error {
	constructor(path: string, line: number, checkpoints: Checkpoint[]);
	path: string;
	/** Line number of the cut-short line, from 1. */
	line: number;
	/** The whole checkpoints before it. */
	checkpoints: Checkpoint[];
}

export interface CheckpointSink {
	publish(checkpoints: Checkpoint[]): Promise<void> | void;
}

/**
 * Appends one line per checkpoint and fsyncs. Truncates an unfinished last
 * line of up to 4 KiB first; throws, leaving the file as it is, on a longer
 * one.
 */
export class FileCheckpointSink implements CheckpointSink {
	constructor(path: string);
	path: string;
	publish(checkpoints: (Checkpoint | CheckpointFields)[]): Promise<void>;
}

/** POSTs the checkpoints as one JSON array. */
export class HttpCheckpointSink implements CheckpointSink {
	constructor(url: string, opts?: { timeoutMs?: number });
	publish(checkpoints: (Checkpoint | CheckpointFields)[]): Promise<void>;
}

/** A node's latest sealed row. */
export interface ChainTip {
	source_node_id: string;
	monotonic_seq: number;
	hash: string;
}

/** The fields of a checkpoint: a tip and when it was taken. */
export interface CheckpointFields extends ChainTip {
	/** Canonical UTC time, YYYY-MM-DDTHH:MM:SS.ffffffZ. */
	anchored_at: string;
}

export interface CheckpointStore {
	chainTips(): Promise<ChainTip[]> | ChainTip[];
}

export function takeCheckpoints(store: CheckpointStore): Promise<Checkpoint[]>;
/** Logs checkpoint_no_sealed_rows when there is nothing to publish. */
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
	Engine: typeof Engine;
	defaultEngine: typeof defaultEngine;

	redactExpired: typeof redactExpired;
	listUnshipped: typeof listUnshipped;
	markShipped: typeof markShipped;
	ingestReplicated: typeof ingestReplicated;
	piiCodes: typeof piiCodes;
	parseDuration: typeof parseDuration;
	AuditStoreError: typeof AuditStoreError;
	AuditOutcomeUnknownError: typeof AuditOutcomeUnknownError;
	AuditRowRejectedError: typeof AuditRowRejectedError;
	AuditSealError: typeof AuditSealError;
	ChainError: typeof ChainError;
	CURRENT_CANONICAL_FORM_ID: typeof CURRENT_CANONICAL_FORM_ID;
	GENESIS: typeof GENESIS;
	JsonNumber: typeof JsonNumber;
	canonicalJSON: typeof canonicalJSON;
	detailCommitment: typeof detailCommitment;
	parseJson: typeof parseJson;
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
	pushSyslog: typeof pushSyslog;
	writeApi: typeof writeApi;
	pushApi: typeof pushApi;
	apiLogger: typeof apiLogger;
	mintSentinel: typeof mintSentinel;
	isSentinel: typeof isSentinel;
};
export default _default;
