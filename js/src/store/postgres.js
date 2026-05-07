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
import pg from 'pg';
const { Pool } = pg;

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
    pii_in_detail  SMALLINT NOT NULL DEFAULT 0,
    shipped_at     TEXT
)`,
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
        detail: typeof r.detail === 'string' ? JSON.parse(r.detail) : r.detail,
        piiInDetail: Number(r.pii_in_detail) === 1,
        shippedAt: r.shipped_at ?? null,
    };
}

/**
 * Build a parameterised WHERE clause from filter options.
 * Returns { where, params } where params is already accumulated.
 *
 * @param {{ requestId?, code?, domain?, sourceNodeId?, actor?, target?, since?, until? }} filters
 * @returns {{ where: string, params: unknown[] }}
 */
function _buildWhere(filters) {
    const conds = [];
    const params = [];
    const {
        requestId, code, domain, sourceNodeId, actor, target, since, until,
    } = filters;

    if (requestId) { params.push(requestId); conds.push(`request_id = $${params.length}`); }
    if (code)      { params.push(code);      conds.push(`code = $${params.length}`); }
    if (domain)    { params.push(domain);    conds.push(`domain = $${params.length}`); }
    if (sourceNodeId) { params.push(sourceNodeId); conds.push(`source_node_id = $${params.length}`); }
    if (actor)     { params.push(actor);     conds.push(`actor = $${params.length}`); }
    if (target)    { params.push(target);    conds.push(`target = $${params.length}`); }
    if (since)     { params.push(since);     conds.push(`timestamp >= $${params.length}`); }
    if (until)     { params.push(until);     conds.push(`timestamp <= $${params.length}`); }

    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    return { where, params };
}

export class PostgresStore {
    /**
     * @param {string} connectionString  libpq-compatible DSN or connection URL.
     * @param {{ table?: string }} [opts]
     */
    constructor(connectionString, { table = 'audit_log' } = {}) {
        if (!_SAFE_IDENTIFIER.test(table)) {
            throw new Error(
                `fasten PostgresStore: table name ${JSON.stringify(table)} is not a valid SQL identifier. ` +
                "Use only letters, digits, underscores, and an optional 'schema.' prefix.",
            );
        }
        this._table = table;
        // Bare name for index identifiers — dots not allowed there.
        this._idx = table.includes('.') ? table.split('.').pop() : table;
        // Optional schema prefix.
        this._schema = table.includes('.') ? table.split('.').slice(0, -1).join('.') : null;
        this._pool = new Pool({ connectionString });
        // Lazy DDL: resolved on first operation.
        this._ready = null;
    }

    /**
     * Run CREATE TABLE + indexes. Safe to call multiple times (IF NOT EXISTS).
     * Called automatically on first use via `_ensureReady()`.
     * @returns {Promise<void>}
     */
    async init() {
        const client = await this._pool.connect();
        try {
            await client.query('BEGIN');
            if (this._schema) {
                await client.query(`CREATE SCHEMA IF NOT EXISTS ${this._schema}`);
            }
            for (const sql of _ddlStatements(this._table, this._idx)) {
                await client.query(sql);
            }
            await client.query('COMMIT');
        } catch (err) {
            await client.query('ROLLBACK');
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
     * @param {Record<string,unknown>} row  Raw row object from `fasten.emit()`.
     * @returns {Promise<void>}
     */
    async insert(row) {
        await this._ensureReady();
        const piiFlag = row.pii_in_detail || row.piiInDetail ? 1 : 0;
        const detailStr = typeof row.detail === 'string'
            ? row.detail
            : JSON.stringify(row.detail ?? {});
        const params = [
            row.id,
            row.origin_id ?? row.originId,
            row.monotonic_seq ?? row.monotonicSeq,
            row.timestamp instanceof Date
                ? row.timestamp.toISOString()
                : row.timestamp,
            row.code,
            row.action,
            row.severity,
            row.service_id ?? row.serviceId,
            row.source_node_id ?? row.sourceNodeId,
            row.tenant_id ?? row.tenantId ?? null,
            row.actor,
            row.actor_kind ?? row.actorKind,
            row.target,
            row.category,
            row.domain,
            row.method,
            row.request_id ?? row.requestId,
            detailStr,
            piiFlag,
            row.shipped_at ?? row.shippedAt ?? null,
        ];
        await this._pool.query(
            `INSERT INTO ${this._table} VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) ` +
            'ON CONFLICT (id) DO NOTHING',
            params,
        );
    }

    /**
     * Query rows with optional filters, ordered newest-first.
     *
     * @param {{
     *   requestId?: string, code?: string, domain?: string,
     *   sourceNodeId?: string, actor?: string, target?: string,
     *   since?: string, until?: string,
     *   limit?: number, offset?: number
     * }} [opts]
     * @returns {Promise<Record<string,unknown>[]>}
     */
    async query({
        requestId, code, domain, sourceNodeId, actor, target,
        since, until, limit = 100, offset = 0,
    } = {}) {
        await this._ensureReady();
        const { where, params } = _buildWhere({ requestId, code, domain, sourceNodeId, actor, target, since, until });
        const n = params.length;
        params.push(limit, offset);
        const sql = `SELECT * FROM ${this._table} ${where} ORDER BY monotonic_seq DESC LIMIT $${n + 1} OFFSET $${n + 2}`;
        const res = await this._pool.query(sql, params);
        return res.rows.map(_mapRow);
    }

    /**
     * Count rows matching optional filters.
     *
     * @param {{
     *   requestId?: string, code?: string, domain?: string,
     *   sourceNodeId?: string, actor?: string, target?: string,
     *   since?: string, until?: string
     * }} [opts]
     * @returns {Promise<number>}
     */
    async count({
        requestId, code, domain, sourceNodeId, actor, target, since, until,
    } = {}) {
        await this._ensureReady();
        const { where, params } = _buildWhere({ requestId, code, domain, sourceNodeId, actor, target, since, until });
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
     * Mark rows as shipped by setting shipped_at to the current UTC time.
     *
     * @param {string[]} ids
     * @returns {Promise<void>}
     */
    async markShipped(ids) {
        if (!ids || ids.length === 0) return;
        await this._ensureReady();
        await this._pool.query(
            `UPDATE ${this._table} SET shipped_at = NOW() WHERE id = ANY($1)`,
            [ids],
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
        if (respectUnshipped) sql += ' AND shipped_at IS NOT NULL';
        const res = await this._pool.query(sql, [before]);
        return res.rowCount ?? 0;
    }

    /**
     * Close the underlying connection pool.
     * @returns {Promise<void>}
     */
    async close() {
        await this._pool.end();
    }
}
