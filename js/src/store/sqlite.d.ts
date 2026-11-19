// Types for fasten-sdk/store/sqlite.
import type {
	AuditRepository,
	ChainRow,
	ChainRowInput,
	ChainStore,
	ChainTip,
	Filter,
	IngestOptions,
	IngestResult,
	ListUnshippedOptions,
	ReplicationStore,
	Row,
} from "../index.js";

export interface SqliteStoreOptions {
	/** Table name, a plain SQL identifier. Defaults to "audit_log". */
	table?: string;
	/** WAL journal mode. Defaults to true; ignored for ":memory:". */
	wal?: boolean;
	/** How long to wait for another connection's write lock. Defaults to 5000. */
	busyTimeoutMs?: number;
}

/**
 * AuditRepository on SQLite (node:sqlite, built into Node). Seals rows with
 * seq 0 into their node's hash chain on insert (spec §2.1), and behaves as
 * PostgresStore does. node:sqlite is synchronous: each call blocks the
 * event loop until it is done.
 */
export class SqliteStore
	implements AuditRepository, ChainStore, ReplicationStore
{
	/**
	 * Open the database at path (a new file is created owner-only), or
	 * ":memory:".
	 */
	constructor(path: string, opts?: SqliteStoreOptions);
	/** Create the table, its indexes and any column it lacks. Idempotent. */
	init(): Promise<void>;
	/**
	 * Insert one row and return it as stored. A row with monotonic_seq 0 is
	 * sealed; a row whose id is already stored returns the stored row.
	 * Throws AuditRowRejectedError for a row it refuses, AuditSealError when
	 * sealing fails for another reason, and AuditOutcomeUnknownError when
	 * the COMMIT failed and the row could not be read back.
	 */
	insert(row: Row | Record<string, unknown>): Promise<Row>;
	insertSealed(
		row: ChainRowInput,
		opts?: { detailText?: string },
	): Promise<void>;
	/** insertSealed, for a row replicated from another node (spec §5). */
	insertReplicated(
		row: ChainRowInput,
		opts?: { detailText?: string },
	): Promise<void>;
	/**
	 * Verify a replicated batch and store its verified prefix in one
	 * transaction (spec §4). A chain break does not throw; it is in the
	 * result. Throws ChainError for a row it cannot read.
	 */
	ingestReplicated(
		rows: Iterable<ChainRowInput>,
		opts?: IngestOptions,
	): Promise<IngestResult>;
	seals(): true;
	chainRows(sourceNodeId: string): Promise<ChainRow[]>;
	allChainRows(): Promise<ChainRow[]>;
	chainTips(): Promise<ChainTip[]>;
	/**
	 * Rows newest first, snake_case like Row. detail is parsed with
	 * JSON.parse: 75.0 reads as 75, and an integer past 2^53 is a BigInt.
	 */
	query(filter?: Filter): Promise<Row[]>;
	count(filter?: Omit<Filter, "limit" | "offset">): Promise<number>;
	/**
	 * Unshipped rows, oldest seq first, in the shape query() returns; with
	 * exact, as chainRows reads them.
	 */
	listUnshipped(
		limit?: number,
		opts?: ListUnshippedOptions & { exact?: false },
	): Promise<Row[]>;
	listUnshipped(
		limit: number | undefined,
		opts: ListUnshippedOptions & { exact: true },
	): Promise<ChainRow[]>;
	markShipped(ids: string[]): Promise<void>;
	/** Delete, per node, a seq prefix of rows older than before (spec §2.3). */
	purge(opts: { before: string; respectUnshipped?: boolean }): Promise<number>;
	listRedactionCandidates(opts: {
		before: Date | string;
		codes: string[];
	}): Promise<{
		candidates: { id: string; monotonicSeq: number }[];
		skipped: number;
	}>;
	redactRows(opts: { ids: string[] }): Promise<string[]>;
	close(): Promise<void>;
}
