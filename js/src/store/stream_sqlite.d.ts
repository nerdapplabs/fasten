// Types for fasten-sdk/store/stream_sqlite.
import type { StreamFilter, StreamRow, StreamStore } from "../index.js";

/**
 * Store for the api or sys stream on node:sqlite, on the table Python's and
 * Go's SQLite stream stores use. Every call is synchronous.
 */
export class SqliteStreamStore implements StreamStore {
	/**
	 * @param path Database file (created 0600) or ":memory:".
	 * @param opts.table Required: "api_log", "syslog".
	 * @param opts.wal WAL with synchronous=NORMAL. Defaults to true.
	 */
	constructor(path: string, opts: { table: string; wal?: boolean });
	insert(row: StreamRow): void;
	noteWriteFailure(): void;
	readonly writeFailures: number;
	readonly degraded: boolean;
	query(opts?: StreamFilter & { limit?: number }): StreamRow[];
	countMatching(filters?: StreamFilter): number;
	count(): number;
	search(opts: {
		q: string;
		since: string;
		until?: string | null;
		limit?: number;
	}): StreamRow[];
	purge(opts: { before: Date | string }): number;
	close(): void;
}
