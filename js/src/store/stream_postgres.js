// @ts-check
/**
 * PostgreSQL store for the api or sys stream (node-postgres, a peer
 * dependency). The same table as the Python and Go stream stores
 * (spec persistent-streams.md §2), so any SDK can read what another wrote.
 *
 *   import { PostgresStreamStore } from 'fasten-sdk/store/stream_postgres';
 *   const apiStore = new PostgresStreamStore(dsn, { table: 'api_log' });
 *   const syslogStore = new PostgresStreamStore(dsn, { table: 'syslog' });
 *   fasten.init({ apiStore, syslogStore, persistStreams: ['api', 'sys'] });
 */
import { canonicalTS } from "../canonical_ts.js";
import {
	FILTER_COLUMNS,
	liftedValues,
	likeEscape,
	parsePayload,
	payloadText,
	SAFE_STREAM_TABLE,
	statusFilter,
} from "../streams.js";
import { checkout, release, retryLost, watchPool } from "./pg_conn.js";

/**
 * @param {string} t full table name
 * @param {string} p table name without schema, for index names
 */
function _ddl(t, p) {
	return [
		`CREATE TABLE IF NOT EXISTS ${t} (
    seq          BIGSERIAL PRIMARY KEY,
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_req ON ${t}(request_id)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_ts  ON ${t}(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_lvl ON ${t}(level)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_svc ON ${t}(service_id)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_evt ON ${t}(event)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_mth ON ${t}(method)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_pth ON ${t}(path)`,
		`CREATE INDEX IF NOT EXISTS idx_${p}_sts ON ${t}(status)`,
	];
}

/**
 * WHERE clause for query() and countMatching(): exact matches and an
 * inclusive [since, until] window on the timestamp text.
 * @param {Record<string, any>} f
 * @returns {{ where: string, params: unknown[] }}
 */
function _where(f) {
	const conds = [];
	const params = [];
	for (const [opt, col] of Object.entries(FILTER_COLUMNS)) {
		if (f[opt]) {
			params.push(f[opt]);
			conds.push(`${col} = $${params.length}`);
		}
	}
	const status = statusFilter(f.status);
	if (status !== null) {
		params.push(status);
		conds.push(`status = $${params.length}`);
	}
	if (f.since) {
		params.push(f.since);
		conds.push(`COALESCE(timestamp, '') >= $${params.length}`);
	}
	if (f.until) {
		params.push(f.until);
		conds.push(`COALESCE(timestamp, '') <= $${params.length}`);
	}
	return {
		where: conds.length ? ` WHERE ${conds.join(" AND ")}` : "",
		params,
	};
}

export class PostgresStreamStore {
	/**
	 * @param {string | { query: Function }} connection A libpq DSN or
	 *   connection URL, or a pg Pool to use (close() leaves it open).
	 * @param {{ table: string }} opts table name, optionally schema-qualified.
	 *   Required, so api rows cannot land in the syslog table.
	 */
	constructor(connection, { table } = /** @type {any} */ ({})) {
		if (!table) {
			throw new Error(
				'fasten PostgresStreamStore: table name is required (no default: pass "api_log" or "syslog")',
			);
		}
		if (!SAFE_STREAM_TABLE.test(table)) {
			throw new Error(
				`fasten PostgresStreamStore: table name ${JSON.stringify(table)} is not a valid SQL identifier. Use only letters, digits, underscores, and an optional 'schema.' prefix.`,
			);
		}
		this._table = table;
		this._idx = /** @type {string} */ (table.split(".").pop());
		this._schema = table.includes(".") ? table.split(".")[0] : null;
		this._ownPool = typeof connection === "string";
		this._connectionString = this._ownPool ? connection : null;
		/** @type {any} */
		this._pool = this._ownPool ? null : connection;
		/** @type {Promise<void> | null} */
		this._ready = null;
		// Inserts run one after another, so seq follows the order rows came.
		/** @type {Promise<unknown>} */
		this._tail = Promise.resolve();
		this._writeFailures = 0;
	}

	/** Create the table and its indexes. Idempotent. */
	async init() {
		if (!this._pool) {
			const mod = await import("pg");
			const pg = mod.default ?? mod;
			this._pool = watchPool(
				new pg.Pool({ connectionString: this._connectionString }),
			);
		}
		await retryLost(this._pool, () => this._bootstrap());
	}

	async _bootstrap() {
		const client = await checkout(this._pool);
		let broken;
		try {
			await client.query("BEGIN");
			// Stores starting together on a new table race on CREATE TABLE.
			await client.query(
				"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
				[`fasten.bootstrap.${this._table}`],
			);
			if (this._schema) {
				await client.query(`CREATE SCHEMA IF NOT EXISTS ${this._schema}`);
			}
			for (const sql of _ddl(this._table, this._idx)) await client.query(sql);
			await client.query("COMMIT");
		} catch (err) {
			// A client whose ROLLBACK failed is released with the error, so
			// the pool drops it.
			await client.query("ROLLBACK").catch((e) => {
				broken = e;
			});
			throw err;
		} finally {
			release(client, broken);
		}
	}

	async _ensureReady() {
		if (!this._ready) {
			this._ready = this.init().catch((err) => {
				this._ready = null;
				throw err;
			});
		}
		return this._ready;
	}

	/**
	 * Store one row: the whole row as JSON in `payload`, the lifted fields in
	 * their columns.
	 * @param {Record<string, unknown>} row
	 * @returns {Promise<void>}
	 */
	insert(row) {
		const payload = payloadText(row);
		const values = liftedValues(row);
		const run = async () => {
			await this._ensureReady();
			await this._query(
				`INSERT INTO ${this._table} (request_id,timestamp,level,service_id,event,method,path,status,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				[...values, payload],
			);
		};
		const p = this._tail.then(run, run);
		this._tail = p.catch(() => {});
		return p;
	}

	// pool.query, run again on a lost connection, as the Python store
	// does.
	async _query(sql, params) {
		return retryLost(this._pool, () => this._pool.query(sql, params));
	}

	/** Count a failed insert that was dropped; any makes the store degraded. */
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
	 * Up to `limit` rows, newest first, as stored. Every filter is an exact
	 * match; since and until compare the canonical timestamp text.
	 * @param {Record<string, any>} [opts]
	 * @returns {Promise<Record<string, unknown>[]>}
	 */
	async query({ limit = 100, ...filters } = {}) {
		const { where, params } = _where(filters);
		await this._ensureReady();
		const res = await this._query(
			`SELECT payload FROM ${this._table}${where} ORDER BY seq DESC LIMIT $${params.length + 1}`,
			[...params, limit],
		);
		return res.rows.map((/** @type {any} */ r) => parsePayload(r.payload));
	}

	/**
	 * Rows matching the filters query() takes, with no limit.
	 * @param {Record<string, any>} [filters]
	 * @returns {Promise<number>}
	 */
	async countMatching(filters = {}) {
		const { where, params } = _where(filters);
		await this._ensureReady();
		const res = await this._query(
			`SELECT COUNT(*) AS n FROM ${this._table}${where}`,
			params,
		);
		return Number(res.rows[0].n);
	}

	/** @returns {Promise<number>} */
	async count() {
		return this.countMatching();
	}

	/**
	 * Case-insensitive substring search (ILIKE) of the stored JSON within
	 * [since, until], newest first. %, _ and \ in q match literally.
	 * @param {{ q: string, since: string, until?: string | null, limit?: number }} opts
	 * @returns {Promise<Record<string, unknown>[]>}
	 */
	async search({ q, since, until = null, limit = 50 }) {
		const params = [since, `%${likeEscape(q)}%`];
		// E'\\' is one backslash whatever standard_conforming_strings says.
		const conds = [
			"COALESCE(timestamp, '') >= $1",
			"payload ILIKE $2 ESCAPE E'\\\\'",
		];
		if (until) {
			params.push(until);
			conds.push(`COALESCE(timestamp, '') <= $${params.length}`);
		}
		params.push(limit);
		await this._ensureReady();
		const res = await this._query(
			`SELECT payload FROM ${this._table} WHERE ${conds.join(" AND ")} ORDER BY seq DESC LIMIT $${params.length}`,
			params,
		);
		return res.rows.map((/** @type {any} */ r) => parsePayload(r.payload));
	}

	/**
	 * Delete rows older than `before` (a Date or canonical timestamp) and
	 * return how many. Rows without a timestamp are kept.
	 * @param {{ before: Date | string }} opts
	 * @returns {Promise<number>}
	 */
	async purge({ before }) {
		const cutoff = before instanceof Date ? canonicalTS(before) : before;
		await this._ensureReady();
		const res = await this._query(
			`DELETE FROM ${this._table} WHERE timestamp < $1`,
			[cutoff],
		);
		return res.rowCount ?? 0;
	}

	/** Wait for pending inserts, then close the pool if this store made it. */
	async close() {
		await this._tail;
		if (this._ownPool) await this._pool?.end();
	}
}
