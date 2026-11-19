// Types for fasten-sdk/store/postgres.
import type {
	AuditRepository,
	ChainRow,
	ChainStore,
	ChainTip,
	Filter,
	Row,
} from "../index.js";

/**
 * AuditRepository on PostgreSQL (node-postgres, a peer dependency). Seals
 * rows with seq 0 into their node's hash chain on insert (spec §2.1).
 */
export class PostgresStore implements AuditRepository, ChainStore {
	/**
	 * @param connectionString A libpq DSN or connection URL.
	 * @param opts.table Table name, optionally schema-qualified. Defaults to
	 *   "audit_log".
	 */
	constructor(connectionString: string, opts?: { table?: string });
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
		row: Parameters<ChainStore["insertSealed"]>[0],
		opts?: { detailText?: string },
	): Promise<void>;
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
	/** Unshipped rows, oldest seq first, in the shape query() returns. */
	listUnshipped(limit?: number): Promise<Row[]>;
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
