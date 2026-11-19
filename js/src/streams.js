// The api and sys streams: in-memory rings, the store write-through, and
// what the stream stores share (spec persistent-streams.md).
import { randomUUID } from "node:crypto";
import { bigintReplacer, bigintReviver } from "./chain.js";

export const SENTINEL_KINDS = Object.freeze([
	"boot",
	"sched",
	"bg",
	"lib",
	"orphan",
]);

/**
 * A sentinel request_id such as "orphan-svc-ab12cd34ef56" (spec §7), for
 * rows written outside a request.
 */
export function mintSentinel(kind, serviceId = "") {
	if (!SENTINEL_KINDS.includes(kind)) {
		throw new Error(
			`unknown sentinel kind ${JSON.stringify(kind)}; expected one of ${SENTINEL_KINDS.join(", ")}`,
		);
	}
	const id = randomUUID().replace(/-/g, "").slice(0, 12);
	return `${kind}-${serviceId || "svc"}-${id}`;
}

/** True when requestId starts with a sentinel prefix such as "boot-". */
export function isSentinel(requestId) {
	return (
		typeof requestId === "string" &&
		SENTINEL_KINDS.some((k) => requestId.startsWith(`${k}-`))
	);
}

// Bare name ("syslog") or schema-qualified ("fasten.syslog").
export const SAFE_STREAM_TABLE =
	/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

// The lifted columns, schema form "1" (spec §2.1), in table order.
export const INDEXED_FIELDS = Object.freeze([
	"request_id",
	"timestamp",
	"level",
	"service_id",
	"event",
	"method",
	"path",
	"status",
]);

// The equality filters a read takes, by option name, and their column.
export const FILTER_COLUMNS = Object.freeze({
	level: "level",
	requestId: "request_id",
	serviceId: "service_id",
	event: "event",
	method: "method",
	path: "path",
});

// The status column is INTEGER: an integer, or a string of digits, is
// stored; anything else is left NULL.
function _status(v) {
	const n = typeof v === "string" && /^-?\d+$/.test(v.trim()) ? Number(v) : v;
	return Number.isInteger(n) && Math.abs(n) <= 2147483647 ? n : null;
}

/** The lifted column values of `row`, in INDEXED_FIELDS order. */
export function liftedValues(row) {
	return INDEXED_FIELDS.map((f) => {
		const v = row[f];
		if (f === "status") return _status(v);
		return typeof v === "string" ? v : null;
	});
}

/** `row` as payload text: JSON, with a BigInt as its digits. */
export function payloadText(row) {
	return JSON.stringify(row, bigintReplacer);
}

/** A stored payload as a row; an integer past 2^53 is a BigInt. */
export function parsePayload(text) {
	return JSON.parse(String(text), bigintReviver);
}

/** `q` with %, _ and \ escaped for LIKE / ILIKE with a backslash escape. */
export function likeEscape(q) {
	return q.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/** A status filter as an integer, or null for none. */
export function statusFilter(status) {
	if (status === undefined || status === null || status === "") return null;
	const n = typeof status === "number" ? status : Number(String(status));
	if (!Number.isInteger(n)) {
		throw new Error(`status must be an integer (got ${String(status)})`);
	}
	return n;
}

function _ts(row) {
	const t = row.timestamp;
	return t === undefined || t === null ? "" : String(t);
}

// A ring row's status against a status filter, compared as integers.
function _statusEquals(v, want) {
	return _status(v) === want;
}

/** The rows of one stream kept in memory, newest first. */
export class Ring {
	constructor(maxlen = 2000) {
		this._max = maxlen;
		this._buf = [];
	}

	push(row) {
		if (this._max <= 0) return;
		this._buf.unshift(row);
		if (this._buf.length > this._max) this._buf.length = this._max;
	}

	get length() {
		return this._buf.length;
	}

	_matching(f = {}) {
		const status = statusFilter(f.status);
		return this._buf.filter((r) => {
			for (const [opt, col] of Object.entries(FILTER_COLUMNS)) {
				if (f[opt] && r[col] !== f[opt]) return false;
			}
			if (status !== null && !_statusEquals(r.status, status)) return false;
			if (f.since && _ts(r) < f.since) return false;
			if (f.until && _ts(r) > f.until) return false;
			return true;
		});
	}

	query({ limit = 100, ...filters } = {}) {
		return this._matching(filters).slice(0, limit);
	}

	countMatching(filters = {}) {
		return this._matching(filters).length;
	}
}

// Rows waiting on one store's insert at most; past that a row is dropped
// and counted as a write failure.
const MAX_PENDING = 10_000;

/**
 * One stream: its ring and, if attached, its store. A row is pushed to the
 * ring and written to the store; a failed or dropped store write marks the
 * store degraded and is reported on stderr by error type only. Reads come
 * from the store when there is one.
 */
export class Stream {
	constructor(name, store, maxlen = 2000) {
		this.name = name;
		this.store = store ?? null;
		this.ring = new Ring(maxlen);
		this._pending = new Set();
	}

	push(row) {
		this.ring.push(row);
		const store = this.store;
		if (!store) return;
		if (this._pending.size >= MAX_PENDING) {
			this._failed(new Error("too many pending writes"), "QueueFull");
			return;
		}
		let p;
		try {
			p = store.insert(row);
		} catch (err) {
			this._failed(err);
			return;
		}
		if (typeof p?.then !== "function") return;
		const tracked = p.then(
			() => {},
			(err) => this._failed(err),
		);
		this._pending.add(tracked);
		tracked.finally(() => this._pending.delete(tracked));
	}

	// The message is left out: a driver error can quote the row's values.
	_failed(err, type) {
		try {
			this.store.noteWriteFailure?.();
		} catch {
			// The stderr line below still reports it.
		}
		const label = this.name === "sys" ? "syslog" : this.name;
		try {
			process.stderr.write(
				`fasten: ${label} persist failed: ${type ?? err?.name ?? "Error"}\n`,
			);
		} catch {
			// Nothing left to report to.
		}
	}

	/** Resolves once the store writes started so far have settled. */
	async settle() {
		while (this._pending.size) await Promise.all([...this._pending]);
	}

	source() {
		if (!this.store) return "ring";
		return this.store.degraded ? "store-degraded" : "store";
	}

	query(opts) {
		return (this.store ?? this.ring).query(opts);
	}

	countMatching(filters) {
		return (this.store ?? this.ring).countMatching(filters);
	}

	// Search covers stored history only: null without a store.
	search(opts) {
		return this.store ? this.store.search(opts) : null;
	}
}
