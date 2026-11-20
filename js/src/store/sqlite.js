// @ts-check
/**
 * SQLite-backed AuditRepository for fasten, on Node's built-in node:sqlite.
 *
 * Usage:
 *   import { SqliteStore } from 'fasten-sdk/store/sqlite';
 *   const store = new SqliteStore('./audit.db');
 *   fasten.init({ auditStore: store });
 *
 * node:sqlite is synchronous: every call runs to the end before it returns,
 * blocking the event loop meanwhile, including while it waits for another
 * connection's write lock (up to the busy timeout). The methods return
 * promises so the store has the same interface as PostgresStore.
 */
import { closeSync, constants, openSync } from "node:fs";
import {
	AuditOutcomeUnknownError,
	AuditRowRejectedError,
} from "../audit_queue.js";
import { canonicalTS } from "../canonical_ts.js";
import {
	AuditSealError,
	canonicalJSON,
	canonicalTimestamp,
	detailText,
	GENESIS,
	parseJson,
	sameEvent,
	seal,
	toChainRow,
} from "../chain.js";
import {
	conflictSync,
	cutAtConflict,
	ingestWithoutLocalNode,
	readBatch,
	skippedUnsealed,
	verifiedPrefix,
} from "../replication.js";
import { likeEscape } from "../streams.js";
import {
	CHAIN_COLUMNS,
	chainRow,
	chainTipsSQL,
	differs,
	mapRow,
	seqHeld,
	snakeRow,
} from "./rows.js";

const _SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

// How long a writer waits for the write lock, as in the Python, Go and Rust
// stores.
const BUSY_TIMEOUT_MS = 5000;

// The columns of a new table, in the order of the Python store's table;
// pii_in_detail and wire_version, which Python lacks, come last, where
// init() adds them to a table Python created.
const _COLUMNS = [
	["id", "TEXT PRIMARY KEY"],
	["origin_id", "TEXT NOT NULL"],
	["monotonic_seq", "INTEGER NOT NULL"],
	["timestamp", "TEXT NOT NULL"],
	["code", "TEXT NOT NULL"],
	["action", "TEXT NOT NULL"],
	["severity", "TEXT NOT NULL"],
	["service_id", "TEXT NOT NULL"],
	["source_node_id", "TEXT NOT NULL"],
	["tenant_id", "TEXT"],
	["actor", "TEXT NOT NULL"],
	["actor_kind", "TEXT NOT NULL"],
	["target", "TEXT NOT NULL"],
	["category", "TEXT NOT NULL"],
	["domain", "TEXT NOT NULL"],
	["method", "TEXT NOT NULL"],
	["request_id", "TEXT NOT NULL"],
	["detail", "TEXT NOT NULL"],
	["shipped_at", "TEXT"],
	["canonical_form_id", "TEXT NOT NULL DEFAULT '1'"],
	// NOT NULL, as in the Go store's table: the Go store reads them as
	// strings. '' is no salt.
	["detail_salt", "TEXT NOT NULL DEFAULT ''"],
	["detail_commitment", "TEXT NOT NULL DEFAULT ''"],
	["prev_hash", "TEXT NOT NULL DEFAULT 'genesis'"],
	["hash", "TEXT NOT NULL DEFAULT ''"],
	["pii_in_detail", "INTEGER NOT NULL DEFAULT 0"],
	["wire_version", "TEXT NOT NULL DEFAULT '1'"],
];

// The columns another SDK's table may lack, as ALTER TABLE adds them. The
// salt and commitment are nullable here: ADD COLUMN cannot fill old rows.
const _ADDED = {
	pii_in_detail: "INTEGER NOT NULL DEFAULT 0",
	wire_version: "TEXT NOT NULL DEFAULT '1'",
	prev_hash: "TEXT NOT NULL DEFAULT 'genesis'",
	hash: "TEXT NOT NULL DEFAULT ''",
	canonical_form_id: "TEXT NOT NULL DEFAULT '1'",
	detail_salt: "TEXT",
	detail_commitment: "TEXT",
};

const _INSERT_COLUMNS =
	"id, wire_version, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, method, request_id, detail, pii_in_detail, shipped_at, prev_hash, hash, canonical_form_id, detail_salt, detail_commitment";

// A failed COMMIT, after which the row may or may not be stored.
class _CommitError extends Error {
	constructor(cause) {
		super(cause?.message ?? String(cause));
		this.cause = cause;
	}
}

// Create a missing database file owner-only (0600), as the Python and Rust
// stores do, so SQLite does not create it with the umask. An existing file
// keeps its mode; a path that cannot be opened is left for SQLite to report.
function _createOwnerOnly(path) {
	if (path === "" || path === ":memory:" || path.startsWith("file:")) return;
	try {
		closeSync(openSync(path, constants.O_CREAT | constants.O_WRONLY, 0o600));
	} catch {
		// SQLite reports it.
	}
}

/**
 * Build a WHERE clause with ? placeholders from filter options.
 * @param {Record<string, any>} filters
 * @returns {{ where: string, params: any[] }}
 */
function _buildWhere(filters) {
	const conds = [];
	const params = [];
	const add = (cond, v) => {
		conds.push(cond);
		params.push(v);
	};
	const f = filters;
	if (f.requestId) add("request_id = ?", f.requestId);
	if (f.code) add("code = ?", f.code);
	if (f.domain) add("domain = ?", f.domain);
	// Unary +: without statistics SQLite would pick the (node, seq) index and
	// sort the node's whole history instead of walking the timestamp index.
	if (f.sourceNodeId) add("+source_node_id = ?", f.sourceNodeId);
	if (f.tenantId) add("tenant_id = ?", f.tenantId);
	if (f.actor) add("actor = ?", f.actor);
	if (f.target) add("target = ?", f.target);
	if (f.since) add("timestamp >= ?", f.since);
	if (f.until) add("timestamp <= ?", f.until);
	return { where: conds.length ? `WHERE ${conds.join(" AND ")}` : "", params };
}

const _chainRow = (r) => chainRow("SqliteStore", r);

// node:sqlite is loaded on first use: the engine imports this module to
// open a store from FASTEN_AUDIT_DSN, and before Node 24.15 loading
// node:sqlite prints an experimental warning.
const _sqlite = () => process.getBuiltinModule("node:sqlite");

export class SqliteStore {
	/**
	 * Open (and create, owner-only) the database at `path`. `":memory:"`
	 * is a database of this store's own.
	 *
	 * @param {string} path  A file path, or ":memory:".
	 * @param {{ table?: string, wal?: boolean, busyTimeoutMs?: number }} [opts]
	 */
	constructor(
		path,
		{ table = "audit_log", wal = true, busyTimeoutMs = BUSY_TIMEOUT_MS } = {},
	) {
		if (!_SAFE_IDENTIFIER.test(table)) {
			throw new Error(
				`fasten SqliteStore: table name ${JSON.stringify(table)} is not a valid SQL identifier. Use only letters, digits and underscores.`,
			);
		}
		this._table = table;
		_createOwnerOnly(path);
		this._db = new (_sqlite().DatabaseSync)(path, { timeout: busyTimeoutMs });
		if (wal && path !== ":memory:") this._db.exec("PRAGMA journal_mode=WAL");
		this._ready = false;
		this._stmts = new Map();
	}

	/**
	 * Create the table and its indexes, and add the columns a table another
	 * SDK created lacks. Idempotent; called on first use.
	 * @returns {Promise<void>}
	 */
	async init() {
		this._ensureReady();
	}

	_ensureReady() {
		if (this._ready) return;
		const t = this._table;
		// One write transaction, so a second process opening the same old
		// table waits here, then sees what this one added.
		this._write(() => {
			const have = new Set(
				this._db
					.prepare("SELECT name FROM pragma_table_info(?)")
					.all(t)
					.map((r) => r.name),
			);
			if (have.size === 0) {
				const cols = _COLUMNS.map(([n, d]) => `${n} ${d}`).join(",\n    ");
				this._db.exec(`CREATE TABLE ${t} (\n    ${cols}\n)`);
				// One node, one chain (spec §2): a second row at a seq fails on
				// insert. The same index the Go store creates.
				this._db.exec(
					`CREATE UNIQUE INDEX IF NOT EXISTS uq_${t}_node_seq ON ${t}(source_node_id, monotonic_seq)`,
				);
			} else {
				for (const [name, def] of Object.entries(_ADDED)) {
					if (!have.has(name)) {
						this._db.exec(`ALTER TABLE ${t} ADD COLUMN ${name} ${def}`);
					}
				}
				// A table that may already repeat a seq on a node (Python's
				// unchained rows all sit at seq 0) gets a plain index, for the
				// seq allocation, unless it has one on these columns.
				if (!this._hasNodeSeqIndex()) {
					this._db.exec(
						`CREATE INDEX IF NOT EXISTS idx_${t}_node_seq ON ${t}(source_node_id, monotonic_seq)`,
					);
				}
			}
			for (const sql of [
				`CREATE INDEX IF NOT EXISTS idx_${t}_req ON ${t}(request_id)`,
				`CREATE INDEX IF NOT EXISTS idx_${t}_code ON ${t}(code)`,
				`CREATE INDEX IF NOT EXISTS idx_${t}_ts ON ${t}(timestamp)`,
				`CREATE INDEX IF NOT EXISTS idx_${t}_unshipped ON ${t}(shipped_at) WHERE shipped_at IS NULL`,
				`CREATE INDEX IF NOT EXISTS idx_${t}_pii ON ${t}(pii_in_detail) WHERE pii_in_detail = 1`,
			]) {
				this._db.exec(sql);
			}
		});
		this._ready = true;
	}

	// Whether an index on the table starts with (source_node_id, monotonic_seq).
	_hasNodeSeqIndex() {
		const rows = this._db
			.prepare(
				`SELECT
				   (SELECT name FROM pragma_index_info(l.name) WHERE seqno = 0) AS c0,
				   (SELECT name FROM pragma_index_info(l.name) WHERE seqno = 1) AS c1
				 FROM pragma_index_list(?) AS l`,
			)
			.all(this._table);
		return rows.some(
			(r) => r.c0 === "source_node_id" && r.c1 === "monotonic_seq",
		);
	}

	_stmt(sql) {
		let s = this._stmts.get(sql);
		if (!s) {
			s = this._db.prepare(sql);
			this._stmts.set(sql, s);
		}
		return s;
	}

	_get(sql, ...params) {
		return this._stmt(sql).get(...params) ?? null;
	}

	_all(sql, ...params) {
		return this._stmt(sql).all(...params);
	}

	// Run fn() in a BEGIN IMMEDIATE transaction, which takes the write lock
	// before the first read, and return what it returns. A failed COMMIT
	// throws _CommitError, after a ROLLBACK.
	_write(fn) {
		this._db.exec("BEGIN IMMEDIATE");
		let out;
		try {
			out = fn();
		} catch (err) {
			this._rollback();
			throw err;
		}
		try {
			this._db.exec("COMMIT");
		} catch (err) {
			this._rollback();
			throw new _CommitError(err);
		}
		return out;
	}

	_rollback() {
		if (this._db.isTransaction) this._db.exec("ROLLBACK");
	}

	/**
	 * Insert one audit row and return it as stored. This is the method the
	 * fasten drainer calls; it behaves as PostgresStore.insert does.
	 *
	 * A row with `monotonic_seq` 0 (what `emit()` returns) is sealed into its
	 * node's hash chain in a BEGIN IMMEDIATE transaction (spec §2.1): it gets
	 * the node's next seq (counting unsealed rows), `prev_hash` from the
	 * node's latest sealed row (or "genesis"), a new detail salt and
	 * commitment, and its hash. The detail column holds the canonical JSON
	 * that was hashed. Such a row must have `origin_id === id`.
	 *
	 * A row with a seq of its own is stored as given: unsealed unless it
	 * carries a hash. Its seq must be free on its node. Use `insertSealed`
	 * for a sealed row from elsewhere.
	 *
	 * A string `detail` is read as JSON text and must be an object. A row
	 * whose id is already stored returns the stored row, so a retry does not
	 * take a new seq. When the COMMIT fails the row is read back once: if it
	 * is stored, it is returned.
	 *
	 * Throws AuditRowRejectedError for a row it refuses: a different row
	 * under a stored id, a seq-0 row whose origin_id is not its id, a seq
	 * another row holds, a row field that is not a string or holds an
	 * unpaired surrogate, a detail that is not JSON. Throws AuditSealError
	 * when sealing fails for another reason, and AuditOutcomeUnknownError
	 * when the COMMIT failed and the row could not be read back. Other
	 * errors are node:sqlite's.
	 *
	 * @param {Record<string,unknown>} row  Raw row object from `fasten.emit()`.
	 * @returns {Promise<Record<string,unknown>>}
	 */
	async insert(row) {
		this._ensureReady();
		const r = snakeRow(row);
		try {
			toChainRow(r);
			canonicalJSON(r.detail);
		} catch (err) {
			throw new AuditRowRejectedError(`row ${r.id}: ${err.message}`);
		}
		if (r.monotonic_seq === 0 && r.origin_id !== r.id) {
			throw new AuditRowRejectedError(
				`row ${r.id}: a row with seq 0 needs origin_id === id (got origin_id ${JSON.stringify(r.origin_id)})`,
			);
		}
		const asHeld = (held) => {
			const same =
				sameEvent(held, r) &&
				(r.monotonic_seq === 0 ||
					(r.monotonic_seq === held.monotonic_seq && r.hash === held.hash));
			if (!same) throw differs(r.id);
			return held;
		};
		const t = this._table;
		try {
			return this._write(() => {
				const held = this._held(r.id);
				if (held) return asHeld(held);
				let stored = r;
				let text;
				if (r.monotonic_seq === 0) {
					// The seq counts every row on the node, sealed or not;
					// prev_hash comes from the node's last sealed row.
					const next = this._get(
						`SELECT COALESCE(MAX(monotonic_seq), 0) + 1 AS seq FROM ${t} WHERE source_node_id = ?`,
						r.source_node_id,
					);
					const tip = this._get(
						`SELECT hash FROM ${t} WHERE source_node_id = ? AND hash <> '' ORDER BY monotonic_seq DESC LIMIT 1`,
						r.source_node_id,
					);
					try {
						stored = seal(tip?.hash ?? GENESIS, {
							...r,
							monotonic_seq: Number(next.seq),
							detail_salt: null,
						});
					} catch (err) {
						throw new AuditSealError(err);
					}
					text = canonicalJSON(stored.detail);
				} else {
					this._checkSeqFree(r);
					text = detailText(r.detail);
				}
				if (this._insertRow(stored, text) === 0) {
					throw new Error(`row ${r.id}: not inserted and not stored`);
				}
				return stored;
			});
		} catch (err) {
			if (!(err instanceof _CommitError)) throw err;
			return this._afterFailedCommit(r.id, err.cause, asHeld);
		}
	}

	/**
	 * Store a sealed row from elsewhere exactly as it was sealed, as
	 * PostgresStore.insertSealed does. `row` is a wire-format row object or
	 * one line of JSON text; its detail is written with its number tokens as
	 * they are. Pass `detailText` to write that text to the detail column
	 * byte for byte instead.
	 *
	 * The row must have a hash and a non-zero `monotonic_seq`. Its hash is
	 * not checked here: run verifyChain over the batch first, or use
	 * `ingestReplicated`. Storing the same row again is a no-op.
	 *
	 * Throws AuditRowRejectedError for a row it cannot read, an unsealed row,
	 * a different row (another hash) under a stored id, or a seq another row
	 * holds on the node; AuditOutcomeUnknownError when the COMMIT failed and
	 * the row could not be read back.
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
		this._ensureReady();
		const check = (held) => {
			if (held.hash !== r.hash) throw differs(r.id);
		};
		try {
			this._write(() => {
				const before = this._held(r.id);
				if (before) return check(before);
				this._checkSeqFree(r);
				if (this._insertRow(r, text ?? detailText(r.detail)) === 0) {
					throw new Error(`row ${r.id}: not inserted and not stored`);
				}
			});
		} catch (err) {
			if (!(err instanceof _CommitError)) throw err;
			this._afterFailedCommit(r.id, err.cause, check);
		}
	}

	/**
	 * Store one sealed row replicated from another node (spec §5). The same
	 * as `insertSealed`; `ingestReplicated` verifies a batch first.
	 *
	 * @param {Record<string,unknown>|string} row
	 * @param {{ detailText?: string }} [opts]
	 * @returns {Promise<void>}
	 */
	async insertReplicated(row, opts) {
		return this.insertSealed(row, opts);
	}

	/**
	 * Verify a batch of rows replicated from other nodes and store its
	 * verified prefix in one BEGIN IMMEDIATE transaction (spec §4), as
	 * PostgresStore.ingestReplicated does: the same checks, the same result.
	 *
	 * @param {Iterable<Record<string,unknown>|string>} rows
	 * @param {{ localNodeId?: string }} [opts]
	 * @returns {Promise<{ inserted: number, rejectedFromSeq: number | null, reason: string | null }>}
	 */
	async ingestReplicated(rows, { localNodeId } = {}) {
		const batch = readBatch(rows);
		return ingestWithoutLocalNode(
			async (rs) => this._ingest(rs),
			batch,
			localNodeId,
		);
	}

	_ingest(batch) {
		const verified = verifiedPrefix(batch);
		const unsealed = skippedUnsealed(batch, verified.rejectedFromSeq);
		if (verified.prefix.length === 0 && unsealed.length === 0) {
			return {
				inserted: 0,
				rejectedFromSeq: verified.rejectedFromSeq,
				reason: verified.reason || null,
			};
		}
		this._ensureReady();
		const t = this._table;
		const look = {
			byId: (id) =>
				this._get(`SELECT hash FROM ${t} WHERE id = ?`, id)?.hash ?? null,
			atSeq: (node, seq) =>
				this._get(
					`SELECT id, hash, prev_hash FROM ${t} WHERE source_node_id = ? AND monotonic_seq = ? LIMIT 1`,
					node,
					seq,
				),
			sealedBelow: (node, seq) =>
				this._get(
					`SELECT 1 AS one FROM ${t} WHERE source_node_id = ? AND monotonic_seq < ? AND hash <> '' LIMIT 1`,
					node,
					seq,
				) !== null,
		};
		try {
			return this._write(() => {
				const v = cutAtConflict(
					verified,
					conflictSync(verified.prefix, unsealed, look),
				);
				for (const row of v.prefix) {
					// BEGIN IMMEDIATE holds off other writers, so a skipped
					// insert means the checks missed something: fail, don't
					// drop it.
					if (
						this._insertRow(row, detailText(row.detail)) === 0 &&
						look.byId(row.id) !== row.hash
					) {
						throw new Error(`row ${row.id}: not inserted and not stored`);
					}
				}
				return {
					inserted: v.prefix.length,
					rejectedFromSeq: v.rejectedFromSeq,
					reason: v.reason || null,
				};
			});
		} catch (err) {
			throw err instanceof _CommitError ? err.cause : err;
		}
	}

	/** The store seals rows with seq 0 (spec §2.1); the engine checks this. */
	seals() {
		return true;
	}

	/**
	 * The rows of `sourceNodeId`, ordered by `monotonic_seq`, for
	 * verifyChain, with detail numbers as the tokens that were hashed.
	 *
	 * @param {string} sourceNodeId
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async chainRows(sourceNodeId) {
		this._ensureReady();
		return this._all(
			`SELECT ${CHAIN_COLUMNS} FROM ${this._table} WHERE source_node_id = ? ORDER BY monotonic_seq`,
			sourceNodeId,
		).map(_chainRow);
	}

	/**
	 * Every row in the table, ordered by node and `monotonic_seq`: the whole
	 * chain, for verifyChain with checkpoints. Reads the whole table into
	 * memory.
	 *
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async allChainRows() {
		this._ensureReady();
		return this._all(
			`SELECT ${CHAIN_COLUMNS} FROM ${this._table} ORDER BY source_node_id, monotonic_seq`,
		).map(_chainRow);
	}

	/**
	 * Each node's latest sealed row (node id, seq and hash), for
	 * takeCheckpoints and publishCheckpoints.
	 *
	 * @returns {Promise<{ source_node_id: string, monotonic_seq: number, hash: string }[]>}
	 */
	async chainTips() {
		this._ensureReady();
		return this._all(chainTipsSQL(this._table)).map((r) => ({
			source_node_id: r.source_node_id,
			monotonic_seq: Number(r.monotonic_seq),
			hash: r.hash,
		}));
	}

	// After a failed COMMIT, read the row stored under `id` once. Returns
	// check(row) when it is stored; throws `err` when it is not, and
	// AuditOutcomeUnknownError when it cannot be read.
	_afterFailedCommit(id, err, check) {
		let held;
		try {
			held = this._held(id);
		} catch (readErr) {
			throw new AuditOutcomeUnknownError(id, err ?? readErr);
		}
		if (!held) throw err;
		return check(held);
	}

	// A row with its own seq: no other row may hold that seq on its node.
	// The (node, seq) index is not unique on every table, so this is checked
	// here, inside the write transaction.
	_checkSeqFree(r) {
		const other = this._get(
			`SELECT id FROM ${this._table} WHERE source_node_id = ? AND monotonic_seq = ? LIMIT 1`,
			r.source_node_id,
			r.monotonic_seq,
		);
		if (other) throw seqHeld(r, other.id);
	}

	// The row stored under `id`, as a chain row, or null.
	_held(id) {
		const r = this._get(
			`SELECT ${CHAIN_COLUMNS} FROM ${this._table} WHERE id = ?`,
			id,
		);
		return r ? _chainRow(r) : null;
	}

	// Insert snake_case row `r` with `detail` as the detail column text.
	// Returns the rows written: 0 when the id was already stored.
	_insertRow(r, detail) {
		const res = this._stmt(
			`INSERT INTO ${this._table} (${_INSERT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING`,
		).run(
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
			// '' rather than NULL: a table the Go store created declares them
			// NOT NULL.
			r.detail_salt ?? "",
			r.detail_commitment ?? "",
		);
		return Number(res.changes);
	}

	/**
	 * Query rows with optional filters, newest first, in the shape
	 * PostgresStore.query returns: snake_case keys, detail parsed with
	 * JSON.parse (read rows for verifyChain with `chainRows`).
	 *
	 * @param {{
	 *   requestId?: string, code?: string, domain?: string,
	 *   sourceNodeId?: string, tenantId?: string, actor?: string, target?: string,
	 *   since?: string, until?: string,
	 *   limit?: number, offset?: number, afterSeq?: number
	 * }} [opts]
	 * `afterSeq` keeps rows with a lower `monotonic_seq`, for paging on from
	 * the last row of a page.
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async query({ limit = 100, offset = 0, afterSeq = 0, ...filters } = {}) {
		this._ensureReady();
		const { where: base, params } = _buildWhere(filters);
		let where = base;
		if (afterSeq > 0) {
			params.push(afterSeq);
			where = where
				? `${where} AND monotonic_seq < ?`
				: "WHERE monotonic_seq < ?";
		}
		return this._all(
			`SELECT * FROM ${this._table} ${where} ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ? OFFSET ?`,
			...params,
			limit,
			offset,
		).map(mapRow);
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
		limit: _limit,
		offset: _offset,
		afterSeq: _afterSeq,
		...filters
	} = {}) {
		this._ensureReady();
		const { where, params } = _buildWhere(filters);
		return Number(
			this._get(`SELECT COUNT(*) AS n FROM ${this._table} ${where}`, ...params)
				.n,
		);
	}

	/**
	 * Case-insensitive substring search of the detail JSON within
	 * [since, until], newest first, in the shape `query()` returns. `%`, `_`
	 * and `\` in q match literally. `tenantId` limits it to one tenant. As in
	 * the Python and Go SQLite stores, q is lowercased in full and the
	 * detail text by SQLite's lower(), which folds only ASCII letters.
	 *
	 * @param {{ q: string, since: string, until?: string | null, limit?: number, tenantId?: string | null }} opts
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async search({ q, since, until = null, limit = 50, tenantId = null }) {
		this._ensureReady();
		const conds = [
			"COALESCE(timestamp, '') >= ?",
			"lower(detail) LIKE ? ESCAPE '\\'",
		];
		const params = [since, `%${likeEscape(q.toLowerCase())}%`];
		if (until) {
			conds.push("COALESCE(timestamp, '') <= ?");
			params.push(until);
		}
		if (tenantId != null) {
			conds.push("tenant_id = ?");
			params.push(tenantId);
		}
		return this._all(
			`SELECT * FROM ${this._table} WHERE ${conds.join(" AND ")} ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ?`,
			...params,
			limit,
		).map(mapRow);
	}

	/**
	 * Row count and first and last timestamp per (source_node_id,
	 * service_id, tenant_id), busiest first.
	 *
	 * @param {{ since?: string, until?: string }} [opts]
	 * @returns {Promise<{ source_node_id: string, service_id: string, tenant_id: string | null, rows: number, first_seen: string, last_seen: string }[]>}
	 */
	async sources({ since, until } = {}) {
		this._ensureReady();
		const { where, params } = _buildWhere({ since, until });
		return this._all(
			`SELECT source_node_id, service_id, tenant_id, COUNT(*) AS n, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen FROM ${this._table} ${where} GROUP BY source_node_id, service_id, tenant_id ORDER BY n DESC`,
			...params,
		).map((r) => ({
			source_node_id: /** @type {string} */ (r.source_node_id),
			service_id: /** @type {string} */ (r.service_id),
			tenant_id: /** @type {string | null} */ (r.tenant_id ?? null),
			rows: Number(r.n),
			first_seen: /** @type {string} */ (r.first_seen),
			last_seen: /** @type {string} */ (r.last_seen),
		}));
	}

	/**
	 * The node's newest `limit` rows by `monotonic_seq`, oldest first, read
	 * as `chainRows` reads them, for verifyChain.
	 *
	 * @param {string} sourceNodeId
	 * @param {number} limit
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async chainTail(sourceNodeId, limit) {
		this._ensureReady();
		return this._all(
			`SELECT ${CHAIN_COLUMNS} FROM ${this._table} WHERE source_node_id = ? ORDER BY monotonic_seq DESC LIMIT ?`,
			sourceNodeId,
			limit,
		)
			.reverse()
			.map(_chainRow);
	}

	/**
	 * Rows not shipped yet, oldest seq first, as PostgresStore.listUnshipped
	 * returns them: with both `serviceId` and `sourceNodeId`, only the rows
	 * that identity originated; with `exact`, rows as `chainRows` reads them.
	 *
	 * @param {number} [limit]
	 * @param {{ serviceId?: string, sourceNodeId?: string, exact?: boolean }} [opts]
	 * @returns {Promise<Record<string,unknown>[]>}
	 */
	async listUnshipped(limit = 100, { serviceId, sourceNodeId, exact } = {}) {
		this._ensureReady();
		const cols = exact ? CHAIN_COLUMNS : "*";
		const rows =
			serviceId != null && sourceNodeId != null
				? // Unary + keeps SQLite off the (node, seq) index, which would
					// walk the node's whole history; the unshipped index is smaller.
					this._all(
						`SELECT ${cols} FROM ${this._table} WHERE shipped_at IS NULL AND service_id = ? AND +source_node_id = ? AND origin_id = id ORDER BY monotonic_seq ASC LIMIT ?`,
						serviceId,
						sourceNodeId,
						limit,
					)
				: this._all(
						`SELECT ${cols} FROM ${this._table} WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT ?`,
						limit,
					);
		return rows.map(exact ? _chainRow : mapRow);
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
		this._ensureReady();
		const now = canonicalTS();
		const sql = `UPDATE ${this._table} SET shipped_at = ? WHERE id = ?`;
		this._write(() => {
			for (const id of ids) this._stmt(sql).run(now, id);
		});
	}

	/**
	 * Delete rows whose timestamp is before `before`, per node only a seq
	 * prefix (spec §2.3), as PostgresStore.purge does.
	 *
	 * @param {{ before: string, respectUnshipped?: boolean }} opts
	 * @returns {Promise<number>}  Number of rows deleted.
	 */
	async purge({ before, respectUnshipped = true }) {
		this._ensureReady();
		// SQLite has no DELETE ... USING, so the rows are matched by id.
		const t = this._table;
		const keep = `timestamp >= ?1${respectUnshipped ? " OR shipped_at IS NULL" : ""}`;
		const shipped = respectUnshipped ? " AND d.shipped_at IS NOT NULL" : "";
		const max = "9223372036854775807";
		const sql =
			`DELETE FROM ${t} WHERE id IN (` +
			`WITH RECURSIVE nodes(node) AS (SELECT MIN(source_node_id) FROM ${t} UNION ALL ` +
			`SELECT (SELECT MIN(source_node_id) FROM ${t} WHERE source_node_id > node) FROM nodes WHERE node IS NOT NULL), ` +
			`bound AS (SELECT node, COALESCE((SELECT monotonic_seq FROM ${t} WHERE source_node_id = node AND monotonic_seq > 0 AND (${keep}) ORDER BY monotonic_seq LIMIT 1), ${max}) AS keep_from FROM nodes WHERE node IS NOT NULL LIMIT ${max}) ` +
			`SELECT d.id FROM bound, ${t} AS d WHERE d.source_node_id = bound.node AND d.monotonic_seq < bound.keep_from AND d.timestamp < ?1${shipped})`;
		return Number(this._db.prepare(sql).run(before).changes);
	}

	/**
	 * Rows of `codes` older than `before` that redaction would clear (spec
	 * §7.1), oldest seq first, as PostgresStore.listRedactionCandidates
	 * returns them.
	 *
	 * @param {{ before: Date | string, codes: string[] }} opts
	 * @returns {Promise<{ candidates: { id: string, monotonicSeq: number }[], skipped: number }>}
	 */
	async listRedactionCandidates({ before, codes }) {
		if (!codes || codes.length === 0) return { candidates: [], skipped: 0 };
		this._ensureReady();
		const d = before instanceof Date ? before : new Date(before);
		if (Number.isNaN(d.getTime())) {
			throw new Error(
				`fasten SqliteStore: bad before ${JSON.stringify(before)}`,
			);
		}
		const cutoff = canonicalTS(d);
		const inCodes = `code IN (${codes.map(() => "?").join(",")})`;
		const t = this._table;
		const skipped = this._db
			.prepare(
				`SELECT COUNT(*) AS n FROM ${t} WHERE timestamp < ? AND ${inCodes} AND detail <> 'null' AND hash <> '' AND canonical_form_id <> '2'`,
			)
			.get(cutoff, ...codes);
		const rows = this._db
			.prepare(
				`SELECT id, monotonic_seq FROM ${t} WHERE timestamp < ? AND ${inCodes} AND detail <> 'null' AND (hash = '' OR canonical_form_id = '2') ORDER BY monotonic_seq`,
			)
			.all(cutoff, ...codes);
		return {
			candidates: rows.map((r) => ({
				id: /** @type {string} */ (r.id),
				monotonicSeq: Number(r.monotonic_seq),
			})),
			skipped: Number(skipped?.n ?? 0),
		};
	}

	/**
	 * Clear `detail` (to the JSON literal `null`) and `detail_salt` on the
	 * given rows, keeping the hash and commitment, so the chain still
	 * verifies (spec §7.1). Returns the ids that are redacted now, including
	 * ones an earlier call redacted, so a retry returns the same list.
	 *
	 * @param {{ ids: string[] }} opts
	 * @returns {Promise<string[]>}
	 */
	async redactRows({ ids }) {
		if (!ids || ids.length === 0) return [];
		this._ensureReady();
		// '' rather than NULL: Go's table and the Go reader need a string, and
		// Python treats '' as no salt.
		const sql = `UPDATE ${this._table} SET detail = 'null', detail_salt = '' WHERE id = ? AND (hash = '' OR canonical_form_id = '2') RETURNING id`;
		return this._write(() =>
			ids.flatMap((id) =>
				this._stmt(sql)
					.all(id)
					.map((r) => r.id),
			),
		);
	}

	/**
	 * Close the database connection.
	 * @returns {Promise<void>}
	 */
	async close() {
		if (this._db.isOpen) this._db.close();
	}
}
