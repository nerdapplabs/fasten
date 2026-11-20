// @ts-check
// Row shapes and SQL shared by the bundled stores.
import { AuditRowRejectedError } from "../audit_queue.js";
import { canonicalTS } from "../canonical_ts.js";
import {
	bigintReviver,
	ChainError,
	canonicalTimestamp,
	parseJson,
	toChainRow,
} from "../chain.js";

const _CANONICAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

/**
 * A purge or redaction cutoff as the canonical timestamp text the stored
 * timestamps are compared with: a Date, or a timestamp string in any
 * offset (or any text Date parses). Throws for anything else.
 * @param {string} store
 * @param {Date | string} before
 * @returns {string}
 */
export function cutoffTS(store, before) {
	if (typeof before === "string") {
		const c = canonicalTimestamp(before);
		if (_CANONICAL.test(c)) return c;
	}
	const d =
		before instanceof Date
			? before
			: typeof before === "string"
				? new Date(before)
				: new Date(Number.NaN);
	if (Number.isNaN(d.getTime())) {
		throw new Error(`fasten ${store}: bad before ${JSON.stringify(before)}`);
	}
	return canonicalTS(d);
}

/**
 * A result row as a row object with the wire's snake_case keys: `detail`
 * parsed from its JSON text (an integer a number cannot hold exactly is a
 * BigInt, null once redacted), `pii_in_detail` a boolean, an empty salt or
 * commitment null.
 * @param {Record<string,unknown>} r
 * @returns {Record<string,unknown>}
 */
export function mapRow(r) {
	return {
		wire_version: r.wire_version || "1",
		id: r.id,
		origin_id: r.origin_id,
		monotonic_seq: Number(r.monotonic_seq),
		timestamp: r.timestamp,
		code: r.code,
		action: r.action,
		severity: r.severity,
		service_id: r.service_id,
		source_node_id: r.source_node_id,
		tenant_id: r.tenant_id ?? null,
		actor: r.actor,
		actor_kind: r.actor_kind,
		target: r.target,
		category: r.category,
		domain: r.domain,
		method: r.method,
		request_id: r.request_id,
		detail:
			typeof r.detail === "string"
				? JSON.parse(r.detail, bigintReviver)
				: r.detail,
		pii_in_detail: Number(r.pii_in_detail) === 1,
		shipped_at: r.shipped_at ?? null,
		canonical_form_id: r.canonical_form_id || "1",
		prev_hash: r.prev_hash ?? "",
		hash: r.hash ?? "",
		detail_salt: r.detail_salt || null,
		detail_commitment: r.detail_commitment || null,
	};
}

// The columns a chain row is read from.
export const CHAIN_COLUMNS =
	"id, wire_version, origin_id, monotonic_seq, timestamp, code, action, severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, method, request_id, detail, shipped_at, canonical_form_id, prev_hash, hash, detail_salt, detail_commitment, pii_in_detail";

/**
 * A row selected as CHAIN_COLUMNS, with detail parsed from the column text,
 * so its numbers are the tokens that were hashed. Throws ChainError naming
 * the store and the row when it cannot be read.
 * @param {string} store
 * @param {Record<string,unknown>} r
 */
export function chainRow(store, r) {
	try {
		return toChainRow({
			...r,
			monotonic_seq: Number(r.monotonic_seq),
			detail: parseJson(r.detail),
			pii_in_detail: Number(r.pii_in_detail) === 1,
		});
	} catch (err) {
		throw new ChainError(`fasten ${store}: row ${r.id}: ${err.message}`);
	}
}

/**
 * Each node's latest sealed row, one walk of the (source_node_id,
 * monotonic_seq) index per node. The same query as the Rust and Python
 * stores, in Postgres and SQLite.
 * @param {string} t
 */
export function chainTipsSQL(t) {
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

// A row's detail: an object as it is, a string read as JSON text (it must
// be an object), a missing one {}.
function _detail(row) {
	const d = row.detail;
	if (typeof d !== "string") return d ?? {};
	let v;
	try {
		v = parseJson(d);
	} catch (err) {
		throw new AuditRowRejectedError(`row ${row.id}: detail: ${err.message}`);
	}
	// parseJson gives objects no prototype; a number is a JsonNumber.
	if (
		v === null ||
		typeof v !== "object" ||
		Object.getPrototypeOf(v) !== null
	) {
		throw new AuditRowRejectedError(
			`row ${row.id}: detail text is not a JSON object`,
		);
	}
	return v;
}

/**
 * A row from emit() (snake_case) or with camelCase keys, as snake_case.
 * @param {Record<string,any>} row
 */
export function snakeRow(row) {
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
		detail: _detail(row),
		pii_in_detail: !!(row.pii_in_detail || row.piiInDetail),
		shipped_at: row.shipped_at ?? row.shippedAt ?? null,
		canonical_form_id: row.canonical_form_id ?? row.canonicalFormId ?? "",
		prev_hash: row.prev_hash ?? row.prevHash ?? "",
		hash: row.hash ?? "",
		detail_salt: row.detail_salt ?? row.detailSalt ?? null,
		detail_commitment: row.detail_commitment ?? row.detailCommitment ?? null,
	};
}

/** @param {string} id */
export function differs(id) {
	return new AuditRowRejectedError(
		`row ${id}: differs from the stored row with that id`,
	);
}

/** @param {{ id: string, monotonic_seq: number, source_node_id: string }} r @param {string} holder */
export function seqHeld(r, holder) {
	return new AuditRowRejectedError(
		`row ${r.id}: seq ${r.monotonic_seq} on node ${JSON.stringify(r.source_node_id)} is held by row ${holder}`,
	);
}

/**
 * listUnshipped's identity: both of serviceId and sourceNodeId, or neither.
 * @param {unknown} serviceId
 * @param {unknown} sourceNodeId
 */
export function unshippedIdentity(serviceId, sourceNodeId) {
	if ((serviceId == null) !== (sourceNodeId == null)) {
		throw new TypeError(
			"listUnshipped: pass both serviceId and sourceNodeId, or neither",
		);
	}
}
