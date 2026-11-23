// Types for fasten-sdk/store/stream_sqlite.
import type { StreamFilter, StreamRow, StreamStore } from "../index.js";

/**
 * Store for the api or sys stream on node:sqlite, on the table Python's and
 * Go's SQLite stream stores use. node:sqlite is synchronous: each call
 * blocks the event loop until it is done. The methods return promises, as
 * PostgresStreamStore's do.
 */
export class SqliteStreamStore implements StreamStore {
	/**
	 * Opens the file; the table is created by init() or the first call.
	 * @param path Database file (created 0600) or ":memory:".
	 * @param opts.table Required: "api_log", "syslog".
	 * @param opts.wal WAL with synchronous=NORMAL, so a commit does not
	 *   fsync. Defaults to true.
	 * @param opts.busyTimeoutMs How long a write waits for another
	 *   connection's write lock. Defaults to 5000.
	 */
	constructor(
		path: string,
		opts: { table: string; wal?: boolean; busyTimeoutMs?: number },
	);
	init(): Promise<void>;
	/** The row is written when the call returns; the promise is settled. */
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
