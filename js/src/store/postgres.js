// @ts-check
/**
 * PostgreSQL-backed AuditRepository for fasten (node-postgres / pg).
 *
 * Peer dep: pg >= 8  (install separately: npm install pg)
 *
 * Usage:
 *   import { PostgresStore } from '@nerdapplabs/fasten/store/postgres';
 *   const store = new PostgresStore(process.env.DATABASE_URL);
 *   await store.init();          // run DDL once
 *   fasten.init({ auditStore: store });
 */
import { canonicalTS } from "../canonical_ts.js";

// pg is an optional peer dep — lazy import so the module loads without it installed.
let _Pool = null;
async function _getPool(connectionString) {
	if (!_Pool) {
		const mod = await import("pg");
		_Pool = mod.default.Pool ?? mod.Pool;
	}
	return new _Pool({ connectionString });
}

// Bare name ("audit_log") or schema-qualified ("fasten.audit_log").
const _SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

/**
 * Build a DDL string for the audit table and its indexes.
 * @param {string} table  Full table reference (may include schema prefix).
 * @param {string} idx    Bare table name used for index identifiers.
 * @returns {string[]}
 */
function _ddlStatements(table, idx) {
	return [
		`CREATE TABLE IF NOT EXISTS ${table} (
    id             TEXT PRIMARY KEY,
    origin_id      TEXT NOT NULL,
    monotonic_seq  BIGINT NOT NULL,
    timestamp      TEXT NOT NULL,
    code           TEXT NOT NULL,
    action         TEXT NOT NULL,
    severity       TEXT NOT NULL,
    service_id     TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    tenant_id      TEXT,
    actor          TEXT NOT NULL,
    actor_kind     TEXT NOT NULL,
    target         TEXT NOT NULL,
    category       TEXT NOT NULL,
    domain         TEXT NOT NULL,
    method         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    detail         TEXT NOT NULL,
    shipped_at     TEXT,
    prev_hash      TEXT NOT NULL DEFAULT 'genesis',
    hash           TEXT NOT NULL DEFAULT '',
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt       TEXT,
    detail_commitment TEXT,
    pii_in_detail  SMALLINT NOT NULL DEFAULT 0
)`,
		// The column order matches Python's table, which the Python store
		// reads by position; pii_in_detail comes last, where the ALTER below
		// puts it on a table Python created. The ALTERs add the columns the
		// Python and Go stores have to a table an older JS store created.
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS pii_in_detail SMALLINT NOT NULL DEFAULT 0`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT 'genesis'`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS canonical_form_id TEXT NOT NULL DEFAULT '1'`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS detail_salt TEXT`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS detail_commitment TEXT`,
		`CREATE INDEX IF NOT EXISTS idx_${idx}_req       ON ${table}(request_id)`,
		`CREATE INDEX IF NOT EXISTS idx_${idx}_code      ON ${table}(code)`,
		`CREATE INDEX IF NOT EXISTS idx_${idx}_ts        ON ${table}(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_${idx}_unshipped ON ${table}(shipped_at) WHERE shipped_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_${idx}_pii       ON ${table}(pii_in_detail) WHERE pii_in_detail = 1`,
	];
}

/**
 * Map a pg result row (array or object) to a plain JS object with camelCase
 * keys, parsing the `detail` JSON string and normalising `piiInDetail`.
 * @param {Record<string,unknown>} r
 * @returns {Record<string,unknown>}
 */
function _ts(v) {
	// A Go-created table stores TIMESTAMPTZ, which pg returns as a Date.
	return v instanceof Date ? canonicalTS(v) : (v ?? null);
}

function _mapRow(r) {
	return {
		id: r.id,
		originId: r.origin_id,
		monotonicSeq: Number(r.monotonic_seq),
		timestamp: _ts(r.timestamp),
		code: r.code,
		action: r.action,
		severity: r.severity,
		serviceId: r.service_id,
		sourceNodeId: r.source_node_id,
		tenantId: r.tenant_id ?? null,
		actor: r.actor,
		actorKind: r.actor_kind,
		target: r.target,
		category: r.category,
		domain: r.domain,
		method: r.method,
		requestId: r.request_id,
		detail: typeof r.detail === "string" ? JSON.parse(r.detail) : r.detail,
		piiInDetail: Number(r.pii_in_detail) === 1,
		shippedAt: _ts(r.shipped_at),
		prevHash: r.prev_hash ?? "",
		hash: r.hash ?? "",
	};
}

/**
 * Build a parameterised WHERE clause from filter options.
 * Returns { where, params } where params is already accumulated.
 *
 * @param {{ requestId?, code?, domain?, sourceNodeId?, tenantId?, actor?, target?, since?, until? }} filters
 * @returns {{ where: string, params: unknown[] }}
 */
function _buildWhere(filters) {
	const conds = [];
	const params = [];
	const {
		requestId,
		code,
		domain,
		sourceNodeId,
		tenantId,
		actor,
		target,
		since,
		until,
	} = filters;

	if (requestId) {
		params.push(requestId);
		conds.push(`request_id = $${params.length}`);
	}
	if (code) {
		params.push(code);
		conds.push(`code = $${params.length}`);
	}
	if (domain) {
		params.push(domain);
		conds.push(`domain = $${params.length}`);
	}
	if (sourceNodeId) {
		params.push(sourceNodeId);
		conds.push(`source_node_id = $${params.length}`);
	}
	if (tenantId) {
		params.push(tenantId);
		conds.push(`tenant_id = $${params.length}`);
	}
	if (actor) {
		params.push(actor);
		conds.push(`actor = $${params.length}`);
	}
	if (target) {
		params.push(target);
		conds.push(`target = $${params.length}`);
	}
	if (since) {
		params.push(since);
		conds.push(`timestamp >= $${params.length}`);
	}
	if (until) {
		params.push(until);
		conds.push(`timestamp <= $${params.length}`);
	}

	const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
	return { where, params };
}

export class PostgresStore {
	/**
	 * @param {string} connectionString  libpq-compatible DSN or connection URL.
	 * @param {{ table?: string }} [opts]
	 */
	constructor(connectionString, { table = "audit_log" } = {}) {
		if (!_SAFE_IDENTIFIER.test(table)) {
			throw new Error(
				`fasten PostgresStore: table name ${JSON.stringify(table)} is not a valid SQL identifier. Use only letters, digits, underscores, and an optional 'schema.' prefix.`,
			);
		}
		this._connectionString = connectionString;
		this._table = table;
		// Bare name for index identifiers — dots not allowed there.
		this._idx = table.includes(".") ? table.split(".").pop() : table;
		// Optional schema prefix.
		this._schema = table.includes(".")
			? table.split(".").slice(0, -1).join(".")
			: null;
		this._pool = null;
		// Lazy DDL: resolved on first operation.
		this._ready = null;
	}

	/**
	 * Run CREATE TABLE + indexes. Safe to call multiple times (IF NOT EXISTS).
	 * Called automatically on first use via `_ensureReady()`.
	 * @returns {Promise<void>}
	 */
	async init() {
		if (!this._pool) this._pool = await _getPool(this._connectionString);
		const client = await this._pool.connect();
		try {
			await client.query("BEGIN");
			// Stores starting together on a new table race on CREATE TABLE.
			// Same key as the Python store's bootstrap lock.
			await client.query(
				"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
				[`fasten.bootstrap.${this._table}`],
			);
			if (this._schema) {
				await client.query(`CREATE SCHEMA IF NOT EXISTS ${this._schema}`);
			}
			for (const sql of _ddlStatements(this._table, this._idx)) {
				await client.query(sql);
			}
			await client.query("COMMIT");
		} catch (err) {
			await client.query("ROLLBACK");
			throw err;
		} finally {
			client.release();
		}
	}

	/** Ensure DDL has run exactly once, lazily. */
	async _ensureReady() {
		if (!this._ready) {
			this._ready = this.init();
		}
		return this._ready;
	}

	/**
	 * Insert one audit row.  Ignores duplicate IDs (ON CONFLICT DO NOTHING).
	 * This is the method the fasten drainer calls.
	 *
	 * A row with `monotonic_seq` 0 (what `emit()` returns) gets the node's next
	 * seq, allocated in the insert's transaction under the same per-node lock
	 * as the Python and Go stores (spec §2.1). The row is not sealed: `hash`
	 * and `prev_hash` are empty.
	 *
	 * @param {Record<string,unknown>} row  Raw row object from `fasten.emit()`.
	 * @returns {Promise<void>}
	 */
	async insert(row) {
		await this._ensureReady();
		const node = row.source_node_id ?? row.sourceNodeId;
		const detailStr =
			typeof row.detail === "string"
				? row.detail
				: JSON.stringify(row.detail ?? {});
		const params = [
			row.id,
			row.origin_id ?? row.originId,
			Number(row.monotonic_seq ?? row.monotonicSeq ?? 0),
			row.timestamp instanceof Date
				? canonicalTS(row.timestamp)
				: row.timestamp,
			row.code,
			row.action,
			row.severity,
			row.service_id ?? row.serviceId,
			node,
			row.tenant_id ?? row.tenantId ?? null,
			row.actor,
			row.actor_kind ?? row.actorKind,
			row.target,
			row.category,
			row.domain,
			row.method,
			row.request_id ?? row.requestId,
			detailStr,
			row.pii_in_detail || row.piiInDetail ? 1 : 0,
			row.shipped_at ?? row.shippedAt ?? null,
		];
		const client = await this._pool.connect();
		try {
			await client.query("BEGIN");
			if (!params[2]) {
				await client.query(
					"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
					[node],
				);
				const res = await client.query(
					`SELECT COALESCE(MAX(monotonic_seq), 0) + 1 AS seq FROM ${this._table} WHERE source_node_id = $1`,
					[node],
				);
				params[2] = Number(res.rows[0].seq);
			}
			await client.query(
				`INSERT INTO ${this._table} (id, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, method, request_id, detail, pii_in_detail, shipped_at, prev_hash, hash, detail_salt, detail_commitment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,'','','','') ON CONFLICT (id) DO NOTHING`,
				params,
			);
			await client.query("COMMIT");
		} catch (err) {
			await client.query("ROLLBACK").catch(() => {});
			throw err;
		} finally {
			client.release();
		}
	}

	/**
	 * Query rows with optional filters, ordered newest-first.
	 *
	 * @param {{
	 *   requestId?: string, code?: string, domain?: string,
	 *   sourceNodeId?: string, tenantId?: string, actor?: string, target?: string,
	 *   since?: string, until?: string,
	 *   limit?: number, offset?: number
	 * }} [opts]
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async query({
		requestId,
		code,
		domain,
		sourceNodeId,
		tenantId,
		actor,
		target,
		since,
		until,
		limit = 100,
		offset = 0,
	} = {}) {
		await this._ensureReady();
		const { where, params } = _buildWhere({
			requestId,
			code,
			domain,
			sourceNodeId,
			tenantId,
			actor,
			target,
			since,
			until,
		});
		const n = params.length;
		params.push(limit, offset);
		const sql = `SELECT * FROM ${this._table} ${where} ORDER BY timestamp DESC, monotonic_seq DESC LIMIT $${n + 1} OFFSET $${n + 2}`;
		const res = await this._pool.query(sql, params);
		return res.rows.map(_mapRow);
	}

	/**
	 * Count rows matching optional filters.
	 *
	 * @param {{
	 *   requestId?: string, code?: string, domain?: string,
	 *   sourceNodeId?: string, tenantId?: string, actor?: string, target?: string,
	 *   since?: string, until?: string
	 * }} [opts]
	 * @returns {Promise<number>}
	 */
	async count({
		requestId,
		code,
		domain,
		sourceNodeId,
		tenantId,
		actor,
		target,
		since,
		until,
	} = {}) {
		await this._ensureReady();
		const { where, params } = _buildWhere({
			requestId,
			code,
			domain,
			sourceNodeId,
			tenantId,
			actor,
			target,
			since,
			until,
		});
		const sql = `SELECT COUNT(*) FROM ${this._table} ${where}`;
		const res = await this._pool.query(sql, params);
		return Number(res.rows[0].count);
	}

	/**
	 * List rows that have not been shipped yet (shipped_at IS NULL),
	 * ordered oldest-first (monotonic_seq ASC).
	 *
	 * @param {number} [limit]
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async listUnshipped(limit = 100) {
		await this._ensureReady();
		const res = await this._pool.query(
			`SELECT * FROM ${this._table} WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT $1`,
			[limit],
		);
		return res.rows.map(_mapRow);
	}

	/**
	 * Mark rows as shipped by setting shipped_at to the current time, in the
	 * canonical form the other SDKs parse (spec §4.3).
	 *
	 * @param {string[]} ids
	 * @returns {Promise<void>}
	 */
	async markShipped(ids) {
		if (!ids || ids.length === 0) return;
		await this._ensureReady();
		await this._pool.query(
			`UPDATE ${this._table} SET shipped_at = $2 WHERE id = ANY($1)`,
			[ids, canonicalTS()],
		);
	}

	/**
	 * Delete rows whose timestamp is before `before`.
	 * When respectUnshipped is true (default), only shipped rows are purged.
	 *
	 * @param {{ before: string, respectUnshipped?: boolean }} opts
	 * @returns {Promise<number>}  Number of rows deleted.
	 */
	async purge({ before, respectUnshipped = true }) {
		await this._ensureReady();
		let sql = `DELETE FROM ${this._table} WHERE timestamp < $1`;
		if (respectUnshipped) sql += " AND shipped_at IS NOT NULL";
		const res = await this._pool.query(sql, [before]);
		return res.rowCount ?? 0;
	}

	/**
	 * Rows of `codes` older than `before` that redaction would clear (spec §7.1),
	 * oldest seq first. A row is redactable when it is unsealed (`hash` empty,
	 * as every JS row is) or sealed under form "2". `skipped` counts sealed
	 * form-"1" rows past the cutoff: their detail is hashed, so they stay.
	 *
	 * @param {{ before: Date | string, codes: string[] }} opts
	 * @returns {Promise<{ candidates: { id: string, monotonicSeq: number }[], skipped: number }>}
	 */
	async listRedactionCandidates({ before, codes }) {
		if (!codes || codes.length === 0) return { candidates: [], skipped: 0 };
		await this._ensureReady();
		const cutoff = before instanceof Date ? canonicalTS(before) : before;
		const skippedRes = await this._pool.query(
			`SELECT COUNT(*) FROM ${this._table} WHERE timestamp < $1 AND code = ANY($2) AND detail <> 'null' AND hash <> '' AND canonical_form_id <> '2'`,
			[cutoff, codes],
		);
		const res = await this._pool.query(
			`SELECT id, monotonic_seq FROM ${this._table} WHERE timestamp < $1 AND code = ANY($2) AND detail <> 'null' AND (hash = '' OR canonical_form_id = '2') ORDER BY monotonic_seq`,
			[cutoff, codes],
		);
		return {
			candidates: res.rows.map((r) => ({
				id: r.id,
				monotonicSeq: Number(r.monotonic_seq),
			})),
			skipped: Number(skippedRes.rows[0].count),
		};
	}

	/**
	 * Clear `detail` (to the JSON literal `null`) and `detail_salt` on the
	 * given rows. Never deletes. Returns the ids that are redacted now,
	 * including ones an earlier call already redacted, so a retry returns the
	 * same list.
	 *
	 * @param {{ ids: string[] }} opts
	 * @returns {Promise<string[]>}
	 */
	async redactRows({ ids }) {
		if (!ids || ids.length === 0) return [];
		await this._ensureReady();
		// '' rather than NULL: Go's table and the Go reader need a string, and
		// Python treats '' as no salt.
		const res = await this._pool.query(
			`UPDATE ${this._table} SET detail = 'null', detail_salt = '' WHERE id = ANY($1) AND (hash = '' OR canonical_form_id = '2') RETURNING id`,
			[ids],
		);
		return res.rows.map((r) => r.id);
	}

	/**
	 * Close the underlying connection pool.
	 * @returns {Promise<void>}
	 */
	async close() {
		await this._pool.end();
	}
}
