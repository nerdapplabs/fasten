// @ts-check
/**
 * PostgreSQL-backed AuditRepository for fasten (node-postgres / pg).
 *
 * Peer dep: pg >= 8  (install separately: npm install pg)
 *
 * Usage:
 *   import { PostgresStore } from 'fasten-sdk/store/postgres';
 *   const store = new PostgresStore(process.env.DATABASE_URL);
 *   await store.init();          // run DDL once
 *   fasten.init({ auditStore: store });
 */
import { AuditRowRejectedError } from "../audit_queue.js";
import { canonicalTS } from "../canonical_ts.js";
import {
	AuditSealError,
	bigintReviver,
	canonicalTimestamp,
	detailText,
	GENESIS,
	parseJson,
	sameEvent,
	seal,
	toChainRow,
} from "../chain.js";

// pg is an optional peer dependency, so import it only when first needed.
let _Pool = null;
let _types = null;
async function _getPool(connectionString) {
	if (!_Pool) {
		const mod = await import("pg");
		const pg = mod.default ?? mod;
		_Pool = pg.Pool;
		const base = pg.types;
		// timestamptz (1184) and timestamp (1114) as text: a Date keeps only
		// milliseconds, so a Go-written .123456 would come back as .123000.
		// Set on this pool only, not on pg globally.
		_types = {
			getTypeParser: (oid, format) =>
				oid === 1184 || oid === 1114
					? _pgTimestamp
					: base.getTypeParser(oid, format),
		};
	}
	return new _Pool({ connectionString, types: _types });
}

// "2026-08-21 10:00:00.123456+05:30" → "2026-08-21T04:30:00.123456Z".
// A timestamp with no offset is UTC.
function _pgTimestamp(v) {
	const m =
		/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:([+-]\d{2})(?::?(\d{2}))?)?$/.exec(
			v,
		);
	if (!m) return v;
	const [, date, time, frac = "", offH, offM = "00"] = m;
	const offset = offH ? `${offH}:${offM}` : "Z";
	const secs = new Date(`${date}T${time}${offset}`).toISOString().slice(0, 19);
	return `${secs}.${frac.padEnd(6, "0")}Z`;
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
    pii_in_detail  SMALLINT NOT NULL DEFAULT 0,
    wire_version   TEXT NOT NULL DEFAULT '1'
)`,
		// The column order matches the Python and Rust stores' tables;
		// pii_in_detail and wire_version, which Python lacks, come last,
		// where the ALTERs below put them on a table Python created. The
		// ALTERs also add the chain columns to a table an older JS store
		// created.
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS pii_in_detail SMALLINT NOT NULL DEFAULT 0`,
		`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS wire_version TEXT NOT NULL DEFAULT '1'`,
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
		// For the seq allocation in insert(). Not unique: rows from the old
		// per-process counter repeat seqs.
		`CREATE INDEX IF NOT EXISTS idx_${idx}_node_seq  ON ${table}(source_node_id, monotonic_seq)`,
	];
}

/**
 * Map a pg result row (array or object) to a plain JS object with camelCase
 * keys, parsing the `detail` JSON string and normalising `piiInDetail`.
 * @param {Record<string,unknown>} r
 * @returns {Record<string,unknown>}
 */
function _mapRow(r) {
	return {
		id: r.id,
		originId: r.origin_id,
		monotonicSeq: Number(r.monotonic_seq),
		timestamp: r.timestamp,
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
		detail:
			typeof r.detail === "string"
				? JSON.parse(r.detail, bigintReviver)
				: r.detail,
		piiInDetail: Number(r.pii_in_detail) === 1,
		shippedAt: r.shipped_at ?? null,
		prevHash: r.prev_hash ?? "",
		hash: r.hash ?? "",
		canonicalFormId: r.canonical_form_id ?? "1",
		detailSalt: r.detail_salt || null,
		detailCommitment: r.detail_commitment || null,
	};
}

// The columns a chain row is read from. Timestamps come back canonical
// through the pool's type parser when the column is TIMESTAMPTZ (a table
// the Go store created).
const _CHAIN_COLUMNS =
	"id, wire_version, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, method, request_id, detail, shipped_at, canonical_form_id, prev_hash, hash, detail_salt, detail_commitment, pii_in_detail";

// A row selected as _CHAIN_COLUMNS, with detail parsed from the column
// text, so its numbers are the tokens that were hashed.
function _chainRow(r) {
	let detail;
	try {
		detail = parseJson(r.detail);
	} catch (err) {
		throw new Error(
			`fasten PostgresStore: row ${r.id}: detail: ${err.message}`,
		);
	}
	return toChainRow({
		...r,
		monotonic_seq: Number(r.monotonic_seq),
		detail,
		pii_in_detail: Number(r.pii_in_detail) === 1,
	});
}

// Each node's latest sealed row, one walk of the (source_node_id,
// monotonic_seq) index per node. The same query as the Rust and Python
// stores.
function _chainTipsSQL(t) {
	return (
		`SELECT source_node_id, monotonic_seq, hash FROM ${t} JOIN (` +
		`WITH RECURSIVE nodes(node) AS (SELECT MIN(source_node_id) FROM ${t} UNION ALL ` +
		`SELECT (SELECT MIN(source_node_id) FROM ${t} WHERE source_node_id > node) ` +
		`FROM nodes WHERE node IS NOT NULL) ` +
		`SELECT node, (SELECT monotonic_seq FROM ${t} WHERE source_node_id = node ` +
		`AND hash <> '' ORDER BY monotonic_seq DESC LIMIT 1) AS seq ` +
		`FROM nodes WHERE node IS NOT NULL) AS tip ` +
		`ON source_node_id = tip.node AND monotonic_seq = tip.seq ` +
		`WHERE hash <> '' ORDER BY source_node_id, id`
	);
}

const _NODE_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";

// A row from emit() (snake_case) or with camelCase keys, as snake_case.
function _snake(row) {
	const ts = row.timestamp;
	return {
		wire_version: row.wire_version ?? row.wireVersion ?? "1",
		id: row.id,
		origin_id: row.origin_id ?? row.originId,
		monotonic_seq: Number(row.monotonic_seq ?? row.monotonicSeq ?? 0),
		timestamp: ts instanceof Date ? canonicalTS(ts) : ts,
		code: row.code,
		action: row.action,
		severity: row.severity,
		service_id: row.service_id ?? row.serviceId,
		source_node_id: row.source_node_id ?? row.sourceNodeId,
		tenant_id: row.tenant_id ?? row.tenantId ?? null,
		actor: row.actor,
		actor_kind: row.actor_kind ?? row.actorKind,
		target: row.target,
		category: row.category,
		domain: row.domain,
		method: row.method,
		request_id: row.request_id ?? row.requestId,
		detail: row.detail ?? {},
		pii_in_detail: !!(row.pii_in_detail || row.piiInDetail),
		shipped_at: row.shipped_at ?? row.shippedAt ?? null,
		canonical_form_id: row.canonical_form_id ?? row.canonicalFormId ?? "",
		prev_hash: row.prev_hash ?? row.prevHash ?? "",
		hash: row.hash ?? "",
		detail_salt: row.detail_salt ?? row.detailSalt ?? null,
		detail_commitment: row.detail_commitment ?? row.detailCommitment ?? null,
	};
}

function _differs(id) {
	return new AuditRowRejectedError(
		`row ${id}: differs from the stored row with that id`,
	);
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
		// Index names can't contain the schema prefix.
		this._idx = table.includes(".") ? table.split(".").pop() : table;
		this._schema = table.includes(".")
			? table.split(".").slice(0, -1).join(".")
			: null;
		this._pool = null;
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
			// Drop a failed init so the next call retries once Postgres is up.
			this._ready = this.init().catch((err) => {
				this._ready = null;
				throw err;
			});
		}
		return this._ready;
	}

	/**
	 * Insert one audit row and return it as stored. This is the method the
	 * fasten drainer calls.
	 *
	 * A row with `monotonic_seq` 0 (what `emit()` returns) is sealed into its
	 * node's hash chain inside the insert transaction, under the per-node
	 * advisory lock every SDK takes (spec §2.1): it gets the node's next seq,
	 * `prev_hash` from the node's latest sealed row (or "genesis"), a detail
	 * salt and commitment, and its hash. The detail column holds the
	 * canonical JSON that was hashed. Such a row must have
	 * `origin_id === id`.
	 *
	 * A row with a seq of its own is stored as given: unsealed unless it
	 * carries a hash. An unsealed row at or above a node's sealed rows makes
	 * verifyChain fail for that node, so do not write rows with their own
	 * seqs on a node id this store seals for. Use `insertSealed` for a
	 * sealed row from elsewhere.
	 *
	 * Storing a row whose id is already stored returns the stored row's seq
	 * and chain fields, so a retry does not take a new seq. A different row
	 * under that id throws AuditRowRejectedError, and so does a seq-0 row
	 * whose origin_id is not its id. A failure to seal throws AuditSealError.
	 *
	 * @param {Record<string,unknown>} row  Raw row object from `fasten.emit()`.
	 * @returns {Promise<Record<string,unknown>>}
	 */
	async insert(row) {
		await this._ensureReady();
		const r = _snake(row);
		// The row as given, with the seq and chain fields of the row stored
		// under its id, once that is checked to be the same event (and, for a
		// row with its own seq, at that seq with that hash).
		const asHeld = (held) => {
			const same =
				sameEvent(held, r) &&
				(r.monotonic_seq === 0 ||
					(r.monotonic_seq === held.monotonic_seq && r.hash === held.hash));
			if (!same) throw _differs(r.id);
			return {
				...r,
				monotonic_seq: held.monotonic_seq,
				canonical_form_id: held.canonical_form_id,
				prev_hash: held.prev_hash,
				hash: held.hash,
				detail_salt: held.detail_salt,
				detail_commitment: held.detail_commitment,
			};
		};
		return this._transaction(async (client) => {
			// A row with its own seq takes the lock too, or it could take the
			// seq a seq-0 insert has just picked.
			await client.query(_NODE_LOCK, [r.source_node_id]);
			// A retry of a row that already landed must not take a new seq.
			const held = await this._held(client, r.id);
			if (held) return asHeld(held);
			let stored = r;
			if (r.monotonic_seq === 0) {
				// Sealed here, so it must be a row this node originated, as
				// the Python and Go stores require.
				if (r.origin_id !== r.id) {
					throw new AuditRowRejectedError(
						`row ${r.id}: a row with seq 0 needs origin_id === id (got origin_id ${JSON.stringify(r.origin_id)})`,
					);
				}
				// The seq counts every row on the node, sealed or not;
				// prev_hash comes from the node's last sealed row.
				const next = await client.query(
					`SELECT COALESCE(MAX(monotonic_seq), 0) + 1 AS seq FROM ${this._table} WHERE source_node_id = $1`,
					[r.source_node_id],
				);
				const tip = await client.query(
					`SELECT hash FROM ${this._table} WHERE source_node_id = $1 AND hash <> '' ORDER BY monotonic_seq DESC LIMIT 1`,
					[r.source_node_id],
				);
				try {
					stored = seal(tip.rows[0]?.hash ?? GENESIS, {
						...r,
						monotonic_seq: Number(next.rows[0].seq),
					});
				} catch (err) {
					throw new AuditSealError(err);
				}
			}
			if (
				(await this._insertRow(client, stored, detailText(stored.detail))) === 0
			) {
				// The id was stored under another node's lock meanwhile.
				const now = await this._held(client, r.id);
				if (!now) throw new Error(`row ${r.id}: not inserted and not stored`);
				return asHeld(now);
			}
			return stored;
		});
	}

	/**
	 * Store a sealed row from elsewhere exactly as it was sealed. `row` is a
	 * wire-format row object or one line of JSON text; its detail is written
	 * with its number tokens as they are, so it reads back as it was hashed.
	 * Pass `detailText` to write that text to the detail column byte for byte
	 * instead. `pii_in_detail` is the row's flag.
	 *
	 * The row must have a hash and a non-zero `monotonic_seq`. Its hash is
	 * not checked here: run verifyChain over the batch first. Storing the
	 * same row again is a no-op; a different row under a stored id throws
	 * AuditRowRejectedError.
	 *
	 * @param {Record<string,unknown>|string} row
	 * @param {{ detailText?: string }} [opts]
	 * @returns {Promise<void>}
	 */
	async insertSealed(row, { detailText: text } = {}) {
		let r;
		try {
			r = toChainRow(row);
			if (text !== undefined) parseJson(text);
		} catch (err) {
			throw new AuditRowRejectedError(`insertSealed: ${err.message}`);
		}
		if (!r.hash || r.monotonic_seq === 0) {
			throw new AuditRowRejectedError(
				`row ${r.id}: insertSealed needs a sealed row (a hash and a non-zero monotonic_seq)`,
			);
		}
		await this._ensureReady();
		const held = await this._transaction(async (client) => {
			await client.query(_NODE_LOCK, [r.source_node_id]);
			const before = await this._held(client, r.id);
			if (before) return before;
			if (
				(await this._insertRow(client, r, text ?? detailText(r.detail))) === 0
			) {
				return this._held(client, r.id);
			}
			return null;
		});
		if (held && held.hash !== r.hash) throw _differs(r.id);
	}

	/** The store seals rows with seq 0 (spec §2.1); the engine checks this. */
	seals() {
		return true;
	}

	/**
	 * The rows of `sourceNodeId`, ordered by `monotonic_seq`, for
	 * verifyChain. Each row's detail is parsed from the stored text, so its
	 * numbers are the tokens that were hashed, whichever SDK wrote the row.
	 * Every row of the node is read into memory in one query.
	 *
	 * @param {string} sourceNodeId
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async chainRows(sourceNodeId) {
		await this._ensureReady();
		const res = await this._pool.query(
			`SELECT ${_CHAIN_COLUMNS} FROM ${this._table} WHERE source_node_id = $1 ORDER BY monotonic_seq`,
			[sourceNodeId],
		);
		return res.rows.map(_chainRow);
	}

	/**
	 * Every row in the table, ordered by node and `monotonic_seq`: the whole
	 * chain, for verifyChain with checkpoints. The whole table is read into
	 * memory in one query; on a large table verify one node at a time with
	 * chainRows and `partial: true`.
	 *
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async allChainRows() {
		await this._ensureReady();
		const res = await this._pool.query(
			`SELECT ${_CHAIN_COLUMNS} FROM ${this._table} ORDER BY source_node_id, monotonic_seq`,
		);
		return res.rows.map(_chainRow);
	}

	/**
	 * Each node's latest sealed row (node id, seq and hash), for
	 * takeCheckpoints and publishCheckpoints.
	 *
	 * @returns {Promise<{ source_node_id: string, monotonic_seq: number, hash: string }[]>}
	 */
	async chainTips() {
		await this._ensureReady();
		const res = await this._pool.query(_chainTipsSQL(this._table));
		return res.rows.map((r) => ({
			source_node_id: r.source_node_id,
			monotonic_seq: Number(r.monotonic_seq),
			hash: r.hash,
		}));
	}

	// Run fn(client) in a transaction and return what it returns.
	async _transaction(fn) {
		const client = await this._pool.connect();
		try {
			await client.query("BEGIN");
			const out = await fn(client);
			await client.query("COMMIT");
			return out;
		} catch (err) {
			await client.query("ROLLBACK").catch(() => {});
			throw err;
		} finally {
			client.release();
		}
	}

	// The row stored under `id`, as a chain row, or null.
	async _held(client, id) {
		const res = await client.query(
			`SELECT ${_CHAIN_COLUMNS} FROM ${this._table} WHERE id = $1`,
			[id],
		);
		return res.rows.length ? _chainRow(res.rows[0]) : null;
	}

	// Insert snake_case row `r` with `detail` as the detail column text.
	// Returns the rows written: 0 when the id was already stored.
	async _insertRow(client, r, detail) {
		const res = await client.query(
			`INSERT INTO ${this._table} (id, wire_version, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, method, request_id, detail, pii_in_detail, shipped_at, prev_hash, hash, canonical_form_id, detail_salt, detail_commitment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) ON CONFLICT (id) DO NOTHING`,
			[
				r.id,
				r.wire_version || "1",
				r.origin_id,
				r.monotonic_seq,
				canonicalTimestamp(r.timestamp),
				r.code,
				r.action,
				r.severity,
				r.service_id,
				r.source_node_id,
				r.tenant_id ?? null,
				r.actor,
				r.actor_kind,
				r.target,
				r.category,
				r.domain,
				r.method,
				r.request_id,
				detail,
				r.pii_in_detail ? 1 : 0,
				r.shipped_at == null ? null : canonicalTimestamp(r.shipped_at),
				r.prev_hash ?? "",
				r.hash ?? "",
				r.canonical_form_id || "1",
				// '' rather than NULL: a table the Go store created declares
				// them NOT NULL.
				r.detail_salt ?? "",
				r.detail_commitment ?? "",
			],
		);
		return res.rowCount ?? 0;
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
	 * Delete rows whose timestamp is before `before`, per node only a seq
	 * prefix (spec §2.3): rows above a kept row stay, so the rows left still
	 * verify. When respectUnshipped is true (default), unshipped rows are kept,
	 * and so are the rows above them.
	 *
	 * @param {{ before: string, respectUnshipped?: boolean }} opts
	 * @returns {Promise<number>}  Number of rows deleted.
	 */
	async purge({ before, respectUnshipped = true }) {
		await this._ensureReady();
		// Rows at seq 0 are not chained and go by age alone. Each node's
		// lowest kept seq is one walk up the (source_node_id, monotonic_seq)
		// index; the LIMIT keeps the planner from repeating it per row.
		const t = this._table;
		const keep = `timestamp >= $1${respectUnshipped ? " OR shipped_at IS NULL" : ""}`;
		const shipped = respectUnshipped ? " AND d.shipped_at IS NOT NULL" : "";
		const max = "9223372036854775807";
		const sql =
			`WITH RECURSIVE nodes(node) AS (SELECT MIN(source_node_id) FROM ${t} UNION ALL ` +
			`SELECT (SELECT MIN(source_node_id) FROM ${t} WHERE source_node_id > node) FROM nodes WHERE node IS NOT NULL), ` +
			`bound AS (SELECT node, COALESCE((SELECT monotonic_seq FROM ${t} WHERE source_node_id = node AND monotonic_seq > 0 AND (${keep}) ORDER BY monotonic_seq LIMIT 1), ${max}) AS keep_from FROM nodes WHERE node IS NOT NULL LIMIT ${max}) ` +
			`DELETE FROM ${t} AS d USING bound WHERE d.source_node_id = bound.node AND d.monotonic_seq < bound.keep_from AND d.timestamp < $1${shipped}`;
		const res = await this._pool.query(sql, [before]);
		return res.rowCount ?? 0;
	}

	/**
	 * Rows of `codes` older than `before` that redaction would clear (spec §7.1),
	 * oldest seq first. A row is redactable when it is unsealed (`hash`
	 * empty) or sealed under form "2". `skipped` counts sealed
	 * form-"1" rows past the cutoff: their detail is hashed, so they stay.
	 *
	 * @param {{ before: Date | string, codes: string[] }} opts
	 * @returns {Promise<{ candidates: { id: string, monotonicSeq: number }[], skipped: number }>}
	 */
	async listRedactionCandidates({ before, codes }) {
		if (!codes || codes.length === 0) return { candidates: [], skipped: 0 };
		await this._ensureReady();
		// timestamp is compared as text, so the cutoff must be canonical too.
		const d = before instanceof Date ? before : new Date(before);
		if (Number.isNaN(d.getTime())) {
			throw new Error(
				`fasten PostgresStore: bad before ${JSON.stringify(before)}`,
			);
		}
		const cutoff = canonicalTS(d);
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
	 * given rows, keeping the hash and commitment, so the chain still
	 * verifies (spec §7.1). Never deletes. Returns the ids that are redacted now,
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
