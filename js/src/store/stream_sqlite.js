// @ts-check
/**
 * SQLite store for the api or sys stream, on node:sqlite (built into Node
 * 24). The same table as the Python and Go SQLite stream stores
 * (spec persistent-streams.md §2). The file uses WAL with
 * synchronous=NORMAL, so a commit does not fsync. node:sqlite is
 * synchronous: each call blocks the event loop until it is done, including
 * a wait for another connection's write lock (up to the busy timeout). The
 * methods return promises, as PostgresStreamStore's do.
 *
 *   import { SqliteStreamStore } from 'fasten-sdk/store/stream_sqlite';
 *   const syslogStore = new SqliteStreamStore('/var/lib/app/streams.db', { table: 'syslog' });
 */
import { closeSync, openSync } from "node:fs";
import {
	FILTER_COLUMNS,
	liftedValues,
	likeEscape,
	parsePayload,
	payloadText,
	statusFilter,
} from "../streams.js";
import { cutoffTS } from "./rows.js";

// Loaded on first use, as in sqlite.js.
const _sqlite = () => process.getBuiltinModule("node:sqlite");

const _SAFE_TABLE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// How long a writer waits for the write lock, as in SqliteStore.
const BUSY_TIMEOUT_MS = 5000;

/** @param {string} t */
function _ddl(t) {
	return `
CREATE TABLE IF NOT EXISTS ${t} (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_${t}_req ON ${t}(request_id);
CREATE INDEX IF NOT EXISTS idx_${t}_ts  ON ${t}(timestamp);
CREATE INDEX IF NOT EXISTS idx_${t}_lvl ON ${t}(level);
CREATE INDEX IF NOT EXISTS idx_${t}_svc ON ${t}(service_id);
CREATE INDEX IF NOT EXISTS idx_${t}_evt ON ${t}(event);
CREATE INDEX IF NOT EXISTS idx_${t}_mth ON ${t}(method);
CREATE INDEX IF NOT EXISTS idx_${t}_pth ON ${t}(path);
CREATE INDEX IF NOT EXISTS idx_${t}_sts ON ${t}(status);`;
}

/**
 * @param {Record<string, any>} f
 * @returns {{ where: string, params: any[] }}
 */
function _where(f) {
	const conds = [];
	const params = [];
	for (const [opt, col] of Object.entries(FILTER_COLUMNS)) {
		if (f[opt]) {
			conds.push(`${col} = ?`);
			params.push(f[opt]);
		}
	}
	const status = statusFilter(f.status);
	if (status !== null) {
		conds.push("status = ?");
		params.push(status);
	}
	if (f.since) {
		conds.push("COALESCE(timestamp, '') >= ?");
		params.push(f.since);
	}
	if (f.until) {
		conds.push("COALESCE(timestamp, '') <= ?");
		params.push(f.until);
	}
	return {
		where: conds.length ? ` WHERE ${conds.join(" AND ")}` : "",
		params,
	};
}

export class SqliteStreamStore {
	/**
	 * Open the database. The table is created by init() or on first use.
	 * @param {string} path database file, or ":memory:". A new file is
	 *   created owner-only (0600).
	 * @param {{ table: string, wal?: boolean, busyTimeoutMs?: number }} opts
	 */
	constructor(
		path,
		{
			table,
			wal = true,
			busyTimeoutMs = BUSY_TIMEOUT_MS,
		} = /** @type {any} */ ({}),
	) {
		if (!table) {
			throw new Error(
				'fasten SqliteStreamStore: table name is required (no default: pass "api_log" or "syslog")',
			);
		}
		if (!_SAFE_TABLE.test(table)) {
			throw new Error(
				`fasten SqliteStreamStore: table name ${JSON.stringify(table)} is not a valid SQL identifier. Use only letters, digits, and underscores.`,
			);
		}
		if (path !== ":memory:" && !path.startsWith("file:")) {
			closeSync(openSync(path, "a", 0o600));
		}
		this._table = table;
		this._db = new (_sqlite().DatabaseSync)(path, { timeout: busyTimeoutMs });
		if (wal && path !== ":memory:") {
			this._db.exec("PRAGMA journal_mode=WAL");
			this._db.exec("PRAGMA synchronous=NORMAL");
		}
		/** @type {any} */
		this._insert = null;
		this._writeFailures = 0;
	}

	/**
	 * Create the table and its indexes. Idempotent; called on first use.
	 * @returns {Promise<void>}
	 */
	async init() {
		this._ensureReady();
	}

	_ensureReady() {
		if (this._insert) return;
		this._db.exec(_ddl(this._table));
		this._insert = this._db.prepare(
			`INSERT INTO ${this._table} (request_id,timestamp,level,service_id,event,method,path,status,payload) VALUES (?,?,?,?,?,?,?,?,?)`,
		);
	}

	/**
	 * Store one row. The write is done when the call returns.
	 * @param {Record<string, unknown>} row
	 * @returns {Promise<void>}
	 */
	async insert(row) {
		this._ensureReady();
		this._insert.run(...liftedValues(row), payloadText(row));
	}

	noteWriteFailure() {
		this._writeFailures++;
	}

	get writeFailures() {
		return this._writeFailures;
	}

	get degraded() {
		return this._writeFailures > 0;
	}

	/**
	 * Up to `limit` rows, newest first. Filters as PostgresStreamStore.
	 * @param {Record<string, any>} [opts]
	 * @returns {Promise<Record<string, unknown>[]>}
	 */
	async query({ limit = 100, ...filters } = {}) {
		this._ensureReady();
		const { where, params } = _where(filters);
		return this._db
			.prepare(
				`SELECT payload FROM ${this._table}${where} ORDER BY seq DESC LIMIT ?`,
			)
			.all(...params, limit)
			.map((r) => parsePayload(r.payload));
	}

	/**
	 * @param {Record<string, any>} [filters]
	 * @returns {Promise<number>}
	 */
	async countMatching(filters = {}) {
		this._ensureReady();
		const { where, params } = _where(filters);
		const r = this._db
			.prepare(`SELECT COUNT(*) AS n FROM ${this._table}${where}`)
			.get(...params);
		return Number(r?.n ?? 0);
	}

	/** @returns {Promise<number>} */
	async count() {
		return this.countMatching();
	}

	/**
	 * Case-insensitive substring search of the stored JSON within
	 * [since, until], newest first. A linear LIKE scan; %, _ and \ in q
	 * match literally.
	 * @param {{ q: string, since: string, until?: string | null, limit?: number }} opts
	 * @returns {Promise<Record<string, unknown>[]>}
	 */
	async search({ q, since, until = null, limit = 50 }) {
		this._ensureReady();
		const conds = [
			"COALESCE(timestamp, '') >= ?",
			"lower(payload) LIKE ? ESCAPE '\\'",
		];
		const params = [since, `%${likeEscape(q.toLowerCase())}%`];
		if (until) {
			conds.push("COALESCE(timestamp, '') <= ?");
			params.push(until);
		}
		return this._db
			.prepare(
				`SELECT payload FROM ${this._table} WHERE ${conds.join(" AND ")} ORDER BY seq DESC LIMIT ?`,
			)
			.all(...params, limit)
			.map((r) => parsePayload(r.payload));
	}

	/**
	 * Delete rows older than `before` (a Date or a timestamp, canonicalised)
	 * and return how many. Rows without a timestamp are kept. One DELETE,
	 * which blocks the event loop until it is done.
	 * @param {{ before: Date | string }} opts
	 * @returns {Promise<number>}
	 */
	async purge({ before }) {
		const cutoff = cutoffTS("SqliteStreamStore", before);
		this._ensureReady();
		const r = this._db
			.prepare(`DELETE FROM ${this._table} WHERE timestamp < ?`)
			.run(cutoff);
		return Number(r.changes);
	}

	/** @returns {Promise<void>} */
	async close() {
		if (this._db.isOpen) this._db.close();
	}
}
