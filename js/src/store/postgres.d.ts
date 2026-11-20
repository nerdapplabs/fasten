// Types for fasten-sdk/store/postgres.
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

/**
 * AuditRepository on PostgreSQL (node-postgres, a peer dependency). Seals
 * rows with seq 0 into their node's hash chain on insert (spec §2.1).
 */
export class PostgresStore
	implements AuditRepository, ChainStore, ReplicationStore
{
	/**
	 * Nothing connects until init() or the first call.
	 * @param connection A postgres:// connection URL (pg does not read
	 *   libpq's keyword form), or a pg Pool to use, for example one shared
	 *   with PostgresStreamStore; close() leaves a pool it was given open.
	 * @param opts.table Table name, optionally schema-qualified. Defaults to
	 *   "audit_log".
	 */
	constructor(
		connection:
			| string
			| {
					query: (...args: unknown[]) => unknown;
					connect: (...args: unknown[]) => unknown;
			  },
		opts?: { table?: string },
	);
	/**
	 * Create the table, its indexes and any column it lacks. Idempotent;
	 * the first call runs it otherwise.
	 */
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
	count(
		filter?: Omit<Filter, "limit" | "offset" | "afterSeq">,
	): Promise<number>;
	/**
	 * Case-insensitive substring search of the detail JSON within
	 * [since, until], newest first, optionally for one tenant.
	 */
	search(opts: {
		q: string;
		since: string;
		until?: string | null;
		limit?: number;
		tenantId?: string | null;
	}): Promise<Row[]>;
	/** Row count and first and last timestamp per node, service and tenant. */
	sources(opts?: { since?: string; until?: string }): Promise<
		{
			source_node_id: string;
			service_id: string;
			tenant_id: string | null;
			rows: number;
			first_seen: string;
			last_seen: string;
		}[]
	>;
	/** The node's newest `limit` rows by seq, oldest first, as chainRows reads them. */
	chainTail(sourceNodeId: string, limit: number): Promise<ChainRow[]>;
	/**
	 * Unshipped rows, oldest seq first, in the shape query() returns; with
	 * exact, as chainRows reads them. With serviceId and sourceNodeId, only
	 * the rows that identity originated; throws TypeError when only one is
	 * given.
	 */
	listUnshipped(
		limit?: number,
		opts?: ListUnshippedOptions & { exact?: false },
	): Promise<Row[]>;
	listUnshipped(
		limit: number | undefined,
		opts: ListUnshippedOptions & { exact: true },
	): Promise<ChainRow[]>;
	listUnshipped(
		limit?: number,
		opts?: ListUnshippedOptions,
	): Promise<Row[] | ChainRow[]>;
	markShipped(ids: string[]): Promise<void>;
	/**
	 * Delete, per node, a seq prefix of rows older than before (spec §2.3).
	 * before is a Date or a timestamp in any offset, canonicalised.
	 */
	purge(opts: {
		before: Date | string;
		respectUnshipped?: boolean;
	}): Promise<number>;
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
