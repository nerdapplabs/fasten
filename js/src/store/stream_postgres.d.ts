// Types for fasten-sdk/store/stream_postgres.
import type { StreamFilter, StreamRow, StreamStore } from "../index.js";

/**
 * Store for the api or sys stream on PostgreSQL (node-postgres, a peer
 * dependency), on the table Python's and Go's stream stores use.
 */
export class PostgresStreamStore implements StreamStore {
	/**
	 * @param connection A libpq DSN or connection URL, or a pg Pool (close()
	 *   leaves a pool it was given open).
	 * @param opts.table Required, optionally schema-qualified: "api_log",
	 *   "syslog".
	 */
	constructor(
		connection: string | { query: (...args: unknown[]) => unknown },
		opts: { table: string },
	);
	init(): Promise<void>;
	/** Inserts run in the order they were called. */
	insert(row: StreamRow): Promise<void>;
	noteWriteFailure(): void;
	readonly writeFailures: number;
	readonly degraded: boolean;
	query(opts?: StreamFilter & { limit?: number }): Promise<StreamRow[]>;
	countMatching(filters?: StreamFilter): Promise<number>;
	count(): Promise<number>;
	search(opts: {
		q: string;
		since: string;
		until?: string | null;
		limit?: number;
	}): Promise<StreamRow[]>;
	purge(opts: { before: Date | string }): Promise<number>;
	close(): Promise<void>;
}
