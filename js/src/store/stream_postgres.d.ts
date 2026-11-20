// Types for fasten-sdk/store/stream_postgres.
import type { StreamFilter, StreamRow, StreamStore } from "../index.js";

/**
 * Store for the api or sys stream on PostgreSQL (node-postgres, a peer
 * dependency), on the table Python's and Go's stream stores use.
 */
export class PostgresStreamStore implements StreamStore {
	/**
	 * Nothing connects until init() or the first call.
	 * @param connection A postgres:// connection URL, or a pg Pool, for
	 *   example one shared with PostgresStore (close() leaves a pool it was
	 *   given open).
	 * @param opts.table Required, optionally schema-qualified: "api_log",
	 *   "syslog".
	 */
	constructor(
		connection: string | { query: (...args: unknown[]) => unknown },
		opts: { table: string },
	);
	init(): Promise<void>;
	/**
	 * Inserts run in the order they were called. An insert that meets a
	 * lost connection fails rather than running again, so a row is never
	 * stored twice.
	 */
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
	/** before is a Date or a timestamp in any offset, canonicalised. */
	purge(opts: { before: Date | string }): Promise<number>;
	close(): Promise<void>;
}
