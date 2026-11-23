// @ts-check
// Stores opened from a DSN, for FASTEN_AUDIT_DSN, FASTEN_API_DSN and
// FASTEN_SYSLOG_DSN. The DSN forms are the Python SDK's.
import { PostgresStore } from "./postgres.js";
import { SqliteStore } from "./sqlite.js";
import { PostgresStreamStore } from "./stream_postgres.js";
import { SqliteStreamStore } from "./stream_sqlite.js";

// A DSN split as Python's urlparse splits it. The scheme is lowercased; a
// bare path has none.
function _split(dsn) {
	const m = /^([A-Za-z][A-Za-z0-9+.-]*):([\s\S]*)$/.exec(dsn);
	const scheme = m ? m[1].toLowerCase() : "";
	let rest = m ? m[2] : dsn;
	const hash = rest.indexOf("#");
	if (hash >= 0) rest = rest.slice(0, hash);
	const q = rest.indexOf("?");
	const query = new URLSearchParams(q >= 0 ? rest.slice(q + 1) : "");
	if (q >= 0) rest = rest.slice(0, q);
	if (m && rest.startsWith("//")) {
		const slash = rest.indexOf("/", 2);
		rest = slash >= 0 ? rest.slice(slash) : "";
	}
	return { scheme, path: rest, query };
}

// The file path of a SQLite DSN. Only the separator slash is stripped:
// sqlite:///rel.db is relative, sqlite:////abs/path.db and a bare
// /abs/path.db are absolute.
function _sqlitePath({ scheme, path }) {
	return scheme && path.startsWith("/") ? path.slice(1) : path;
}

// A query parameter, or `def` when it is missing or empty.
const _param = (query, name, def) => query.get(name) || def;

// A postgres:// DSN without its table parameter, which libpq would refuse,
// and that table.
function _postgres(dsn, defaultTable) {
	const q = dsn.indexOf("?");
	if (q < 0) return { conn: dsn, table: defaultTable };
	let query = dsn.slice(q + 1);
	let fragment = "";
	const hash = query.indexOf("#");
	if (hash >= 0) {
		fragment = query.slice(hash);
		query = query.slice(0, hash);
	}
	const params = new URLSearchParams(query);
	const table = params.get("table") || defaultTable;
	params.delete("table");
	const left = params.toString();
	return {
		conn: `${dsn.slice(0, q)}${left ? `?${left}` : ""}${fragment}`,
		table,
	};
}

const _SCHEMES = ["sqlite", "postgres", "postgresql", ""];

// The DSN split, after checking its scheme. The error names the scheme
// only, since the rest of a DSN can hold a password, and only when "//"
// follows it: in user:password@host/db or host:5432/db the text before the
// colon is not a scheme.
function _checked(dsn, kind) {
	const file = kind === "stream" ? "streams.db" : "audit.db";
	// libpq's keyword form ("host=db dbname=app"): pg reads only URLs.
	if (/^\s*[A-Za-z_]+\s*=/.test(dsn)) {
		throw new Error(
			`fasten: ${kind} DSN in libpq keyword form not supported. Use postgres://user@host/db, sqlite:///./${file}, or a bare filesystem path.`,
		);
	}
	const d = _split(dsn);
	if (!_SCHEMES.includes(d.scheme)) {
		if (!dsn.slice(d.scheme.length + 1).startsWith("//")) {
			throw new Error(
				`fasten: ${kind} DSN form not recognised. Use postgres://..., sqlite:///./${file}, or a bare filesystem path.`,
			);
		}
		throw new Error(
			`fasten: ${kind} DSN scheme '${d.scheme}' not supported. Use sqlite:///./${file}, postgres://..., or a bare filesystem path.`,
		);
	}
	return d;
}

/**
 * The audit store for a DSN: PostgresStore for postgres:// and
 * postgresql://, SqliteStore on the DSN's path for sqlite:///rel.db,
 * sqlite:////abs.db or a bare path. `?table=` names the table and
 * `?wal=false` turns WAL off, as in Python. Any other scheme, or libpq's
 * keyword form, is an error, and no file is created.
 * @param {string} dsn
 */
export function auditStoreFromDsn(dsn) {
	const d = _checked(dsn, "audit");
	if (d.scheme === "postgres" || d.scheme === "postgresql") {
		const { conn, table } = _postgres(dsn, "audit_log");
		return new PostgresStore(conn, { table });
	}
	const path = _sqlitePath(d);
	if (!path) {
		throw new Error(
			"fasten SqliteStore: the DSN has no path. Audit storage must be durable — use sqlite:///./audit.db or similar.",
		);
	}
	return new SqliteStore(path, {
		table: _param(d.query, "table", "audit_log"),
		wal: d.query.get("wal") !== "false",
	});
}

/**
 * The api or sys stream store for a DSN: PostgresStreamStore for
 * postgres:// and postgresql://, SqliteStreamStore for sqlite:///path or a
 * bare path. Any other scheme, or libpq's keyword form, is an error, not
 * a file.
 * @param {string} dsn
 * @param {string} defaultTable
 */
export function streamStoreFromDsn(dsn, defaultTable) {
	const d = _checked(dsn, "stream");
	if (d.scheme === "postgres" || d.scheme === "postgresql") {
		const { conn, table } = _postgres(dsn, defaultTable);
		return new PostgresStreamStore(conn, { table });
	}
	const path = _sqlitePath(d);
	if (!path) {
		throw new Error(
			"fasten: the stream DSN has no path. Use sqlite:///./streams.db",
		);
	}
	return new SqliteStreamStore(path, {
		table: _param(d.query, "table", defaultTable),
		wal: d.query.get("wal") !== "false",
	});
}
