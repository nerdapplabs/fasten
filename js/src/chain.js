/**
 * Row hashing, sealing and chain verification (spec/chain-replication.md).
 *
 * A row hash is the SHA-256 of the row's canonical JSON, the bytes CPython
 * writes for
 *
 *     json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)
 *
 * over the row's hashed fields. Each row records the form it was sealed with
 * in `canonical_form_id`:
 *
 * - Form "1" hashes `detail` directly, with the timestamp in
 *   `datetime.isoformat()` form (`+00:00`).
 * - Form "2" (current) hashes `detail_commitment` instead of `detail`, and
 *   the timestamp as written on the wire.
 *
 * `shipped_at` is hashed as null and `pii_in_detail` is never hashed.
 *
 * Numbers. Text parsed with `parseJson` keeps each number as its token
 * (`JsonNumber`), so `75.0` stays a float and a long integer keeps every
 * digit, as Python reads them. A JS number is taken as the token JS writes
 * for it (`String(n)`, which is also what JSON.stringify writes) and hashed
 * as CPython renders the value `json.loads` gives for that token (spec 1.3):
 * 75 hashes as `75`, 75.5 as `75.5`, 1e-7 as `1e-07`. A BigInt is an exact
 * integer. The stores write the detail column as the same canonical text,
 * so what is stored is what was hashed, and Python reading it hashes the
 * same bytes.
 */
import { createHash, randomBytes } from "node:crypto";

/** Form stamped by `seal`. Form "1" rows still verify. */
export const CURRENT_CANONICAL_FORM_ID = "2";

/** `prev_hash` of a node's first sealed row. */
export const GENESIS = "genesis";

// Nesting allowed in parsed JSON, as in the Rust parser.
const MAX_DEPTH = 128;

/**
 * What the chain functions throw for input they cannot read: text that is
 * not JSON (or nested deeper than 128), a row that is not an object, a row
 * field that is not a string or holds an unpaired surrogate, a missing or
 * bad `monotonic_seq`, a circular value, a value JSON cannot hold, a bad
 * `prevHash` given to `seal`, and a stored row a store cannot read back.
 */
export class ChainError extends Error {
	constructor(message) {
		super(message);
		this.name = "ChainError";
	}
}

/** A row could not be sealed. The stores throw it with the cause. */
export class AuditSealError extends Error {
	constructor(cause) {
		super(`seal failed: ${cause?.message ?? cause}`);
		this.name = "AuditSealError";
		this.cause = cause;
	}
}

/**
 * A JSON number as its source token, for example `75.0` or `1e-7`. Python's
 * `NaN`, `Infinity` and `-Infinity` are number tokens too.
 */
export class JsonNumber {
	constructor(token) {
		if (typeof token !== "string" || !_isNumberToken(token)) {
			throw new ChainError(`not a JSON number: ${JSON.stringify(token)}`);
		}
		this.token = token;
		Object.freeze(this);
	}

	valueOf() {
		return Number(this.token);
	}

	toString() {
		return this.token;
	}

	// JSON.stringify writes the token as it is; NaN and the infinities as null.
	toJSON() {
		return Number.isFinite(Number(this.token))
			? JSON.rawJSON(this.token)
			: null;
	}
}

const _NUMBER_RE = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

function _isNumberToken(t) {
	return t === "NaN" || t === "Infinity" || t === "-Infinity"
		? true
		: _NUMBER_RE.test(t);
}

// --- Parsing -------------------------------------------------------------

/**
 * Parse JSON text as Python's `json.loads` does: numbers become
 * `JsonNumber`, objects have no prototype, a repeated key keeps its last
 * value, an unpaired `\u` surrogate escape is kept, and `NaN`, `Infinity`
 * and `-Infinity` are numbers. Throws ChainError.
 */
export function parseJson(text) {
	if (typeof text !== "string")
		throw new ChainError("JSON text must be a string");
	const p = new _Parser(text);
	const v = p.value(0);
	p.ws();
	if (p.pos !== text.length) p.fail("trailing characters");
	return v;
}

class _Parser {
	constructor(src) {
		this.src = src;
		this.pos = 0;
	}

	fail(what) {
		throw new ChainError(`json at offset ${this.pos}: ${what}`);
	}

	ws() {
		const s = this.src;
		while (this.pos < s.length) {
			const c = s.charCodeAt(this.pos);
			if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) break;
			this.pos++;
		}
	}

	value(depth) {
		if (depth > MAX_DEPTH) this.fail("nested too deeply");
		this.ws();
		const s = this.src;
		const c = s[this.pos];
		switch (c) {
			case "{":
				return this.object(depth);
			case "[":
				return this.array(depth);
			case '"':
				return this.string();
			case "N":
				return this.literal("NaN", new JsonNumber("NaN"));
			case "I":
				return this.literal("Infinity", new JsonNumber("Infinity"));
			case "t":
				return this.literal("true", true);
			case "f":
				return this.literal("false", false);
			case "n":
				return this.literal("null", null);
			case undefined:
				return this.fail("unexpected end");
		}
		if (c === "-" && s[this.pos + 1] === "I") {
			return this.literal("-Infinity", new JsonNumber("-Infinity"));
		}
		if (c === "-" || (c >= "0" && c <= "9")) return this.number();
		return this.fail("unexpected character");
	}

	literal(word, v) {
		if (!this.src.startsWith(word, this.pos)) this.fail("unexpected character");
		this.pos += word.length;
		return v;
	}

	object(depth) {
		this.pos++;
		const out = Object.create(null);
		this.ws();
		if (this.src[this.pos] === "}") {
			this.pos++;
			return out;
		}
		for (;;) {
			this.ws();
			if (this.src[this.pos] !== '"') this.fail("expected an object key");
			const key = this.string();
			this.ws();
			if (this.src[this.pos] !== ":") this.fail("expected ':'");
			this.pos++;
			out[key] = this.value(depth + 1);
			this.ws();
			const c = this.src[this.pos];
			if (c === ",") {
				this.pos++;
			} else if (c === "}") {
				this.pos++;
				return out;
			} else {
				this.fail("expected ',' or '}'");
			}
		}
	}

	array(depth) {
		this.pos++;
		const out = [];
		this.ws();
		if (this.src[this.pos] === "]") {
			this.pos++;
			return out;
		}
		for (;;) {
			out.push(this.value(depth + 1));
			this.ws();
			const c = this.src[this.pos];
			if (c === ",") {
				this.pos++;
			} else if (c === "]") {
				this.pos++;
				return out;
			} else {
				this.fail("expected ',' or ']'");
			}
		}
	}

	// Escapes give UTF-16 units, so a \u pair is one character and an
	// unpaired surrogate stays unpaired, as in Python.
	string() {
		const s = this.src;
		this.pos++;
		let out = "";
		let run = this.pos;
		for (;;) {
			if (this.pos >= s.length) this.fail("unterminated string");
			const c = s.charCodeAt(this.pos);
			if (c === 0x22) {
				out += s.slice(run, this.pos);
				this.pos++;
				return out;
			}
			if (c === 0x5c) {
				out += s.slice(run, this.pos);
				this.pos++;
				out += this.escape();
				run = this.pos;
			} else if (c < 0x20) {
				this.fail("control character in string");
			} else {
				this.pos++;
			}
		}
	}

	escape() {
		const c = this.src[this.pos];
		this.pos++;
		switch (c) {
			case '"':
			case "\\":
			case "/":
				return c;
			case "b":
				return "\b";
			case "f":
				return "\f";
			case "n":
				return "\n";
			case "r":
				return "\r";
			case "t":
				return "\t";
			case "u": {
				const hex = this.src.slice(this.pos, this.pos + 4);
				if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("invalid \\u escape");
				this.pos += 4;
				return String.fromCharCode(Number.parseInt(hex, 16));
			}
		}
		this.pos--;
		return this.fail(
			c === undefined ? "unterminated string" : "invalid escape",
		);
	}

	number() {
		const s = this.src;
		const start = this.pos;
		const digits = () => {
			const from = this.pos;
			while (this.pos < s.length && s[this.pos] >= "0" && s[this.pos] <= "9") {
				this.pos++;
			}
			return this.pos - from;
		};
		if (s[this.pos] === "-") this.pos++;
		const intStart = this.pos;
		const intLen = digits();
		if (intLen === 0 || (intLen > 1 && s[intStart] === "0")) {
			this.fail("invalid number");
		}
		if (s[this.pos] === ".") {
			this.pos++;
			if (digits() === 0) this.fail("invalid number");
		}
		if (s[this.pos] === "e" || s[this.pos] === "E") {
			this.pos++;
			if (s[this.pos] === "+" || s[this.pos] === "-") this.pos++;
			if (digits() === 0) this.fail("invalid number");
		}
		return new JsonNumber(s.slice(start, this.pos));
	}
}

// --- Canonical JSON ------------------------------------------------------

// How canonical JSON is written. PY is the canonical form; the others are
// older Go encodings verification falls back to and sealing never uses.
// `py`: number tokens as CPython renders them, rather than as stored.
// `del`: DEL (0x7f) escaped as \u007f, rather than raw.
const PY = { py: true, del: true };
const GO_NUMBERS = { py: false, del: true };
const GO_RAW_DEL = { py: false, del: false };
const PY_RAW_DEL = { py: true, del: false };

/**
 * Canonical JSON of `value`: keys sorted by code point, no whitespace,
 * non-ASCII and DEL escaped, numbers as CPython renders them (see the module
 * comment). Undefined, functions and symbols are dropped from objects and
 * written as null in arrays, and `toJSON` is called, as JSON.stringify does.
 * A circular value throws ChainError.
 */
export function canonicalJSON(value) {
	return _render(value, PY);
}

/**
 * The text a store writes to the `detail` column for `detail`: canonical
 * JSON, except that a `JsonNumber` keeps its token as written, so a row
 * sealed elsewhere reads back with the tokens it was hashed with.
 */
export function detailText(detail) {
	return _render(detail, GO_NUMBERS);
}

function _render(value, canon) {
	const out = [];
	_write(value, out, canon, new Set(), "");
	return out.join("");
}

function _skipped(v) {
	return v === undefined || typeof v === "function" || typeof v === "symbol";
}

function _write(v, out, canon, stack, key) {
	if (v !== null && typeof v === "object" && typeof v.toJSON === "function") {
		if (!(v instanceof JsonNumber)) v = v.toJSON(key);
	}
	if (v === null) {
		out.push("null");
		return;
	}
	switch (typeof v) {
		case "boolean":
			out.push(v ? "true" : "false");
			return;
		case "string":
			out.push(_str(v, canon));
			return;
		case "number":
			out.push(_jsNumber(v));
			return;
		case "bigint":
			out.push(v.toString());
			return;
		case "object":
			break;
		default:
			if (_skipped(v)) {
				out.push("null");
				return;
			}
			throw new ChainError(`cannot write a ${typeof v} as JSON`);
	}
	if (v instanceof JsonNumber) {
		out.push(canon.py ? pyNumberToken(v.token) : v.token);
		return;
	}
	if (stack.has(v)) throw new ChainError("circular reference");
	stack.add(v);
	if (Array.isArray(v)) {
		out.push("[");
		for (let i = 0; i < v.length; i++) {
			if (i > 0) out.push(",");
			_write(_skipped(v[i]) ? null : v[i], out, canon, stack, String(i));
		}
		out.push("]");
	} else {
		const keys = Object.keys(v)
			.filter((k) => !_skipped(v[k]))
			.sort(compareCodePoints);
		out.push("{");
		keys.forEach((k, i) => {
			if (i > 0) out.push(",");
			out.push(_str(k, canon), ":");
			_write(v[k], out, canon, stack, k);
		});
		out.push("}");
	}
	stack.delete(v);
}

// Characters CPython writes as they are with ensure_ascii.
const _PLAIN = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;
const _SHORT = {
	34: '\\"',
	92: "\\\\",
	10: "\\n",
	13: "\\r",
	9: "\\t",
	8: "\\b",
	12: "\\f",
};

// A string as CPython writes it with ensure_ascii: its short escapes, and
// \uXXXX (lowercase, UTF-16 units) for everything outside ' '..'~'. An
// unpaired surrogate is written as its own \uXXXX.
function _str(s, canon) {
	if (_PLAIN.test(s)) return `"${s}"`;
	let out = '"';
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		const short = _SHORT[c];
		if (short) out += short;
		else if (c === 0x7f && !canon.del) out += "\x7f";
		else if (c >= 0x20 && c <= 0x7e) out += s[i];
		else out += `\\u${c.toString(16).padStart(4, "0")}`;
	}
	return `${out}"`;
}

/** Compare two strings by code point, the order Python sorts them in. */
export function compareCodePoints(a, b) {
	if (a === b) return 0;
	const ia = a[Symbol.iterator]();
	const ib = b[Symbol.iterator]();
	for (;;) {
		const x = ia.next();
		const y = ib.next();
		if (x.done || y.done) return x.done ? (y.done ? 0 : -1) : 1;
		const cx = x.value.codePointAt(0);
		const cy = y.value.codePointAt(0);
		if (cx !== cy) return cx < cy ? -1 : 1;
	}
}

// A JS number: the token JS writes for it, rendered as CPython renders the
// value json.loads reads from that token.
function _jsNumber(n) {
	if (Number.isNaN(n)) return "NaN";
	if (!Number.isFinite(n)) return n > 0 ? "Infinity" : "-Infinity";
	return pyNumberToken(String(n));
}

/**
 * A number token as CPython's json.dumps writes the value json.loads reads
 * from it. NaN, Infinity and -Infinity are written as they are. A token with
 * no '.', 'e' or 'E' is an int and is kept as written, except "-0", which
 * reads as 0. Any other token is a float, written as repr() writes it.
 */
export function pyNumberToken(tok) {
	if (tok === "NaN" || tok === "Infinity" || tok === "-Infinity") return tok;
	if (!/[.eE]/.test(tok)) return tok === "-0" ? "0" : tok;
	const f = Number(tok);
	if (Number.isNaN(f)) return tok;
	if (!Number.isFinite(f)) return f > 0 ? "Infinity" : "-Infinity";
	return pyFloatRepr(f);
}

/**
 * CPython's repr() of a finite float: the shortest digits that round-trip,
 * in fixed notation when the decimal exponent is from -4 to 15 (with ".0" on
 * a whole number), otherwise scientific with a signed exponent of at least
 * two digits (5e-05, 1e+16).
 */
export function pyFloatRepr(f) {
	// toExponential() with no argument gives the shortest round-trip digits.
	const [mantissa, e] = Math.abs(f).toExponential().split("e");
	const exp = Number(e);
	const digits = mantissa.replace(".", "");
	const sign = f < 0 || Object.is(f, -0) ? "-" : "";
	if (exp >= -4 && exp < 16) {
		const point = exp + 1;
		if (point >= digits.length) {
			return `${sign}${digits}${"0".repeat(point - digits.length)}.0`;
		}
		if (point > 0) {
			return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
		}
		return `${sign}0.${"0".repeat(-point)}${digits}`;
	}
	const frac = digits.length > 1 ? `.${digits.slice(1)}` : "";
	const abs = String(Math.abs(exp)).padStart(2, "0");
	return `${sign}${digits[0]}${frac}e${exp < 0 ? "-" : "+"}${abs}`;
}

// --- Hashing -------------------------------------------------------------

function _sha256(...parts) {
	const h = createHash("sha256");
	for (const p of parts) h.update(p, "utf8");
	return h.digest("hex");
}

/**
 * `sha256(salt + canonical JSON of detail)` as hex (spec 1.4). Without the
 * salt a short value such as an email address could be recovered by
 * guessing, so redaction clears the salt along with detail.
 */
export function detailCommitment(salt, detail) {
	return _commitment(salt, detail, PY);
}

function _commitment(salt, detail, canon) {
	return _sha256(salt, _render(detail, canon));
}

const _TS =
	/^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * An RFC 3339 timestamp in the wire form (spec 4.3): UTC, six fractional
 * digits, "Z". Digits past the sixth are dropped. Text that is not RFC 3339
 * is returned as it is.
 */
export function canonicalTimestamp(ts) {
	const m = typeof ts === "string" ? _TS.exec(ts) : null;
	if (!m) return ts;
	const [, y, mo, d, h, mi, s, frac = "", off] = m;
	const [Y, M, D, H, MI, S] = [y, mo, d, h, mi, s].map(Number);
	const t = new Date(Date.UTC(Y, M - 1, D, H, MI, S));
	t.setUTCFullYear(Y);
	if (
		t.getUTCMonth() !== M - 1 ||
		t.getUTCDate() !== D ||
		H > 23 ||
		MI > 59 ||
		S > 59
	) {
		return ts;
	}
	let ms = t.getTime();
	if (off !== "Z" && off !== "z") {
		const mins = Number(off.slice(1, 3)) * 60 + Number(off.slice(4, 6));
		ms -= (off[0] === "-" ? -1 : 1) * mins * 60_000;
	}
	const at = new Date(ms).toISOString();
	return `${at.slice(0, 19)}.${frac.slice(0, 6).padEnd(6, "0")}Z`;
}

// A wire timestamp as form "1" hashes it, which is Python's
// datetime.isoformat(): "+00:00", with microseconds only when nonzero.
function _isoTs(wire) {
	if (typeof wire !== "string" || !wire.endsWith("Z")) return wire;
	const body = wire.slice(0, -1);
	return `${body.endsWith(".000000") ? body.slice(0, -7) : body}+00:00`;
}

// One way a row was hashed. The first shape of a form is the one it seals
// with; the rest are accepted on verification only.
// commitsDetail: form "2", detail_commitment in place of detail.
// isoTs: timestamps as +00:00 isoformat rather than the wire form.
// shippedAt: the stored shipped_at rather than null.
const FORM_1 = { commitsDetail: false, isoTs: true, shippedAt: false };
const FORM_2 = { commitsDetail: true, isoTs: false, shippedAt: false };
// Form "1" over the wire "Z" timestamp, as Python sealed it at first.
const FORM_1_WIRE_TS = { ...FORM_1, isoTs: false };

function _shape(formId) {
	return formId === "1" ? FORM_1 : formId === "2" ? FORM_2 : null;
}

function _formId(row) {
	return row.canonical_form_id ? row.canonical_form_id : "1";
}

// The fields one shape hashes, as an object.
function _hashedFields(row, shape) {
	const ts = (wire) => {
		const c = canonicalTimestamp(wire);
		return shape.isoTs ? _isoTs(c) : c;
	};
	const d = {
		action: row.action,
		actor: row.actor,
		actor_kind: row.actor_kind,
		canonical_form_id: _formId(row),
		category: row.category,
		code: row.code,
		domain: row.domain,
		id: row.id,
		method: row.method,
		monotonic_seq: row.monotonic_seq,
		origin_id: row.origin_id,
		prev_hash: row.prev_hash,
		request_id: row.request_id,
		service_id: row.service_id,
		severity: row.severity,
		shipped_at:
			shape.shippedAt && row.shipped_at != null ? ts(row.shipped_at) : null,
		source_node_id: row.source_node_id,
		target: row.target,
		tenant_id: row.tenant_id,
		timestamp: ts(row.timestamp),
		wire_version: row.wire_version,
	};
	if (shape.commitsDetail) d.detail_commitment = row.detail_commitment;
	else d.detail = row.detail;
	return d;
}

function _hashWith(row, shape, canon) {
	return _sha256(_render(_hashedFields(row, shape), canon));
}

/**
 * The hash of `row` under its `canonical_form_id`, or null for a form this
 * version does not know. This is the hash a writer computes today, not the
 * test `verifyChain` applies: verification also accepts the encodings older
 * releases hashed with, and for form "2" checks detail against its
 * commitment.
 */
export function rowHash(row) {
	const r = toChainRow(row);
	const shape = _shape(_formId(r));
	return shape ? _hashWith(r, shape, PY) : null;
}

const _HEX64 = /^[0-9a-f]{64}$/;

/**
 * A copy of `row` sealed after `prevHash`, which must be "genesis" or a
 * row hash (64 lowercase hex digits). Sets `canonical_form_id` (the current
 * form), `prev_hash`, `detail_commitment` and `hash`. A non-empty
 * `detail_salt` is kept, so a row can be sealed again to the same hash;
 * otherwise a new one is drawn. `monotonic_seq` is hashed as the row carries
 * it: set it first, to one more than the highest seq on the node.
 *
 * The copy carries every hashed field as it was hashed, defaults filled in
 * as `toChainRow` fills them (a missing `wire_version` is "1", a missing
 * `detail` {}) and the timestamp in the wire form. `shipped_at`,
 * `pii_in_detail` and fields the hash does not cover are copied as they
 * are. Throws ChainError for a row `toChainRow` cannot read.
 */
export function seal(prevHash, row) {
	if (prevHash !== GENESIS && !_HEX64.test(prevHash)) {
		throw new ChainError(
			`prev_hash must be "genesis" or 64 lowercase hex digits (got ${JSON.stringify(prevHash)})`,
		);
	}
	const salt = row.detail_salt
		? row.detail_salt
		: randomBytes(32).toString("hex");
	const r = toChainRow({
		...row,
		canonical_form_id: CURRENT_CANONICAL_FORM_ID,
		prev_hash: prevHash,
		detail_salt: salt,
		detail_commitment: null,
	});
	r.detail_commitment = detailCommitment(salt, r.detail);
	r.timestamp = canonicalTimestamp(r.timestamp);
	const { pii_in_detail: _pii, shipped_at: _shipped, ...hashed } = r;
	return { ...row, ...hashed, hash: _hashWith(r, FORM_2, PY) };
}

// --- Rows ----------------------------------------------------------------

const _LONE_SURROGATE =
	/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * A row in the shape the chain functions use, from a wire-format row object
 * or one line of JSON text (a stdout line, a vector row). Text is parsed
 * with `parseJson`, so its detail numbers stay exact. Only `monotonic_seq`
 * is required, a non-negative safe integer. For the rest:
 *
 * - a missing or null string field is "", so a missing `hash` is unsealed;
 * - a missing `detail` is {}, and a null one is a redacted detail;
 * - a missing, null or empty `wire_version` is "1", and `prev_hash`
 *   "genesis";
 * - an empty `detail_salt` or `detail_commitment` is null.
 *
 * A row field holding an unpaired surrogate is an error; inside `detail`
 * it is kept. Throws ChainError.
 */
export function toChainRow(input) {
	const v = typeof input === "string" ? parseJson(input) : input;
	if (v === null || typeof v !== "object" || Array.isArray(v)) {
		throw new ChainError("row: not an object");
	}
	const opt = (k) => {
		const x = v[k];
		if (x === null || x === undefined) return null;
		if (typeof x !== "string")
			throw new ChainError(`row field "${k}": not a string`);
		if (_LONE_SURROGATE.test(x)) {
			throw new ChainError(`row field "${k}": has an unpaired surrogate`);
		}
		return x;
	};
	const text = (k) => opt(k) ?? "";
	const or = (k, dflt) => opt(k) || dflt;
	return {
		wire_version: or("wire_version", "1"),
		id: text("id"),
		origin_id: text("origin_id"),
		monotonic_seq: _seq(v.monotonic_seq),
		timestamp: text("timestamp"),
		code: text("code"),
		action: text("action"),
		severity: text("severity"),
		service_id: text("service_id"),
		source_node_id: text("source_node_id"),
		tenant_id: opt("tenant_id"),
		actor: text("actor"),
		actor_kind: text("actor_kind"),
		target: text("target"),
		category: text("category"),
		domain: text("domain"),
		method: text("method"),
		request_id: text("request_id"),
		detail: v.detail === undefined ? {} : v.detail,
		pii_in_detail: v.pii_in_detail === true || Number(v.pii_in_detail) === 1,
		shipped_at: opt("shipped_at"),
		canonical_form_id: text("canonical_form_id"),
		prev_hash: or("prev_hash", GENESIS),
		hash: text("hash"),
		detail_salt: opt("detail_salt") || null,
		detail_commitment: opt("detail_commitment") || null,
	};
}

function _seq(x) {
	if (x === undefined)
		throw new ChainError('row field "monotonic_seq": missing');
	let n = x;
	if (x instanceof JsonNumber) {
		if (!/^\d+$/.test(x.token)) {
			throw new ChainError(
				'row field "monotonic_seq": not an unsigned integer',
			);
		}
		n = Number(x.token);
	} else if (typeof x === "bigint") {
		n = Number(x);
	} else if (typeof x !== "number") {
		throw new ChainError('row field "monotonic_seq": not a number');
	}
	if (!Number.isSafeInteger(n) || n < 0 || Object.is(n, -0)) {
		throw new ChainError(
			'row field "monotonic_seq": not an unsigned safe integer',
		);
	}
	return n;
}

/**
 * Whether `a` and `b` are the same event: every hashed field but the chain
 * fields, `monotonic_seq` and `shipped_at` is equal, with timestamps compared
 * as instants and detail by its canonical JSON. A redacted (null) detail on
 * either side matches any detail. The stores use it to tell a retried insert
 * from a different row under a stored id.
 */
export function sameEvent(a, b) {
	const ra = toChainRow(a);
	const rb = toChainRow(b);
	const anyRedacted = ra.detail === null || rb.detail === null;
	const content = (r) =>
		_render(
			_hashedFields(
				{
					...r,
					monotonic_seq: 0,
					shipped_at: null,
					canonical_form_id: "",
					prev_hash: "",
					detail: anyRedacted ? null : r.detail,
				},
				FORM_1,
			),
			PY,
		);
	return content(ra) === content(rb);
}

// --- Verification --------------------------------------------------------

// Whether any string the row holds has DEL in it.
function _hasDel(row) {
	for (const [k, v] of Object.entries(row)) {
		if (k !== "detail" && typeof v === "string" && v.includes("\x7f")) {
			return true;
		}
	}
	return _render(row.detail, GO_RAW_DEL).includes("\x7f");
}

// Whether row.hash is the row's hash under canon: its form's own, or one of
// the older shapes.
function _hashMatches(row, shape, canon) {
	const is = (s) => _hashWith(row, s, canon) === row.hash;
	if (is(shape)) return true;
	const form1 = !shape.commitsDetail;
	if (form1 && is(FORM_1_WIRE_TS)) return true;
	// Sealed with shipped_at already set, and hashed over that value.
	return (
		row.shipped_at != null &&
		(is({ ...shape, shippedAt: true }) ||
			(form1 && is({ ...FORM_1_WIRE_TS, shippedAt: true })))
	);
}

// Check a sealed row on its own: its form, its detail commitment and its
// hash. Returns why it fails, or null if it checks out.
function _rowBreak(row) {
	const formId = _formId(row);
	const shape = _shape(formId);
	if (!shape) return `row ${row.id}: unknown canonical_form_id "${formId}"`;

	// Each check runs with the canonical encoding first, then with the older
	// Go encodings. The raw-DEL ones can only differ when the row holds DEL.
	let del = null;
	const matches = (check) => {
		if (check(PY) || check(GO_NUMBERS)) return true;
		if (del === null) del = _hasDel(row);
		return del && (check(GO_RAW_DEL) || check(PY_RAW_DEL));
	};

	// Form "2" hashes detail_commitment, not detail, so while detail is
	// present the commitment is recomputed and compared. A missing salt is a
	// break, since redaction clears detail and salt together (spec 7.1).
	if (shape.commitsDetail && row.detail !== null) {
		const salt = row.detail_salt;
		if (!salt) {
			return `row ${row.id}: detail present but detail_salt is missing — commitment cannot be verified`;
		}
		const stored = row.detail_commitment ?? "";
		if (!matches((c) => _commitment(salt, row.detail, c) === stored)) {
			return `row ${row.id}: detail does not match its commitment`;
		}
	}
	if (!matches((c) => _hashMatches(row, shape, c))) {
		return `row ${row.id}: hash mismatch`;
	}
	return null;
}

// The first break in one node's chain, sorted by monotonic_seq, as
// [monotonic_seq, reason]; null if the chain verifies.
function _firstBreak(sorted) {
	let firstSealed = null;
	for (const r of sorted) {
		if (r.hash && (firstSealed === null || r.monotonic_seq < firstSealed)) {
			firstSealed = r.monotonic_seq;
		}
	}
	const seen = new Map();
	for (let i = 0; i < sorted.length; i++) {
		const row = sorted[i];
		const seq = row.monotonic_seq;
		if (!row.hash) {
			if (firstSealed !== null && seq >= firstSealed) {
				return [seq, `row ${row.id}: no hash after the node's chain started`];
			}
			continue; // written before chaining, or stdout-only
		}
		// monotonic_seq is unique within a node, so two sealed rows sharing
		// one came from two allocators (spec 2.1).
		const other = seen.get(seq);
		seen.set(seq, row.id);
		if (other !== undefined && other !== row.id) {
			return [
				seq,
				`duplicate monotonic_seq ${seq} on node '${row.source_node_id}': rows ${other} and ${row.id}. Two engines allocated independently (spec §2.1).`,
			];
		}
		const reason = _rowBreak(row);
		if (reason !== null) return [seq, reason];
		if (i > 0) {
			const prev = sorted[i - 1];
			if (prev.hash && row.prev_hash !== prev.hash) {
				return [
					seq,
					`row ${row.id}: prev_hash does not match preceding row ${prev.id}`,
				];
			}
			// Only a node's first sealed row may skip the check above: it
			// links to "genesis" when the unsealed row before it is at
			// seq-1, and a purged head leaves a gap where the rows start.
			if (
				!prev.hash &&
				prev.monotonic_seq + 1 === seq &&
				row.prev_hash !== GENESIS
			) {
				return [
					seq,
					`row ${row.id}: first sealed row does not link to genesis`,
				];
			}
		}
	}
	return null;
}

// Check each node's rows against the checkpoints (spec 9.3). Returns the
// break at the lowest seq, as { seq, node, reason }, or null, and how many
// checkpoints had a row at their seq to compare with. Checkpoints are taken
// by node, then seq, so every SDK reports the same break.
function _checkpointBreak(byNode, checkpoints, partial) {
	let checked = 0;
	const newest = new Map();
	for (const cp of checkpoints) {
		const n = newest.get(cp.source_node_id);
		newest.set(
			cp.source_node_id,
			n === undefined ? cp.monotonic_seq : Math.max(n, cp.monotonic_seq),
		);
	}
	const index = new Map();
	for (const node of newest.keys()) {
		const rows = byNode.get(node);
		if (!rows) continue;
		const bySeq = new Map();
		for (const r of rows) {
			const at = bySeq.get(r.monotonic_seq);
			if (at) at.push(r);
			else bySeq.set(r.monotonic_seq, [r]);
		}
		// Rows are sorted by seq.
		index.set(node, {
			bySeq,
			lowest: rows[0].monotonic_seq,
			highest: rows[rows.length - 1].monotonic_seq,
		});
	}
	const sorted = [...checkpoints].sort(
		(a, b) =>
			compareCodePoints(a.source_node_id, b.source_node_id) ||
			a.monotonic_seq - b.monotonic_seq,
	);
	let first = null;
	for (const cp of sorted) {
		const node = cp.source_node_id;
		const seq = cp.monotonic_seq;
		const ix = index.get(node);
		let found = null;
		if (!ix) {
			// A node with no rows breaks once, at its newest checkpoint.
			if (!partial && newest.get(node) === seq) {
				found = [
					seq,
					`node '${node}': no rows, but checkpointed at seq ${seq}`,
				];
			}
		} else {
			const at = ix.bySeq.get(seq);
			if (at) {
				checked++;
				if (!at.some((r) => r.hash === cp.hash)) {
					const id = at.map((r) => r.id).sort(compareCodePoints)[0];
					found = [
						seq,
						`row ${id}: hash differs from checkpoint at seq ${seq}`,
					];
				}
			} else if (seq > ix.highest) {
				// In a partial verify the batch ends earlier.
				if (!partial) {
					found = [
						ix.highest + 1,
						`node '${node}': chain ends at seq ${ix.highest} before checkpoint at seq ${seq}`,
					];
				}
			} else if (seq < ix.lowest) {
				// In a partial verify the batch starts later.
				if (!partial) {
					found = [
						ix.lowest,
						`node '${node}': rows start at seq ${ix.lowest}, after the checkpoint at seq ${seq}`,
					];
				}
			} else {
				found = [seq, `node '${node}': no row at checkpointed seq ${seq}`];
			}
		}
		if (found && (first === null || found[0] < first.seq)) {
			first = { seq: found[0], node, reason: found[1] };
		}
	}
	return { first, checked };
}

/**
 * Walk the hash chain of each node in `rows` and report the first break.
 *
 * `rows` are wire-format row objects or JSON lines (see `toChainRow`); read
 * stored rows with a store's `chainRows` or `allChainRows`, which keep the
 * detail numbers exact.
 *
 * - Chains are per `source_node_id`; each is walked in `monotonic_seq` order.
 * - A row given more than once is checked once: a sealed copy wins over an
 *   unsealed one, and two sealed copies must have the same, valid hash.
 * - An unsealed row (empty `hash`) is skipped below its node's first sealed
 *   seq and breaks the chain at or above it. A sealed row right after an
 *   unsealed one must link to "genesis".
 * - A row with an unknown `canonical_form_id` breaks the chain.
 * - `firstBreakAt` is the lowest seq at which any node breaks, and
 *   `firstBreakNode` the node it is on.
 * - `ok` says no break was found in what was checked: `sealedRows` rows,
 *   and `checkpointsChecked` checkpoints that had a row at their seq. It
 *   is also true when nothing was checked.
 *
 * With `checkpoints` (spec 9.3), each checkpoint within a node's rows must
 * match the row at its seq. Unless `partial` is set, `rows` are taken as the
 * whole chain: every checkpointed node must have rows, and no checkpoint may
 * be below its node's oldest row or above its newest. Under retention, pass
 * only the checkpoints taken since the latest purge (`checkpointsSince`).
 * Rows after a node's newest checkpoint are not covered by it.
 *
 * Without checkpoints it cannot tell that rows were deleted from the end of
 * a node's chain, that the start of a chain was deleted (it looks like a
 * purge), or that a whole chain was sealed again from genesis.
 *
 * Throws ChainError for a row `toChainRow` cannot read, naming its index.
 */
export function verifyChain(rows, { checkpoints = [], partial = false } = {}) {
	const list = [...rows].map((r, i) => {
		try {
			return toChainRow(r);
		} catch (err) {
			throw new ChainError(`rows[${i}]: ${err.message}`);
		}
	});
	// One copy per (node, id), in first-seen order.
	const byNode = new Map();
	let dup = null;
	for (const row of list) {
		let node = byNode.get(row.source_node_id);
		if (!node) {
			node = new Map();
			byNode.set(row.source_node_id, node);
		}
		const old = node.get(row.id);
		if (old === undefined) {
			node.set(row.id, row);
		} else if (!old.hash && row.hash) {
			node.set(row.id, row);
		} else if (old.hash && row.hash) {
			const reason =
				row.hash === old.hash
					? _rowBreak(row)
					: `row ${row.id}: two sealed copies with different hashes`;
			const seq = Math.min(row.monotonic_seq, old.monotonic_seq);
			if (reason !== null && (dup === null || seq < dup.seq)) {
				dup = { seq, node: row.source_node_id, reason };
			}
		}
	}

	let first = null;
	const lower = (b) => {
		if (b && (first === null || b.seq < first.seq)) first = b;
	};
	let sealedRows = 0;
	const sortedNodes = new Map();
	for (const name of [...byNode.keys()].sort(compareCodePoints)) {
		const sorted = [...byNode.get(name).values()].sort(
			(a, b) => a.monotonic_seq - b.monotonic_seq,
		);
		sortedNodes.set(name, sorted);
		sealedRows += sorted.filter((r) => r.hash).length;
		const found = _firstBreak(sorted);
		if (found) lower({ seq: found[0], node: name, reason: found[1] });
	}
	lower(dup);
	const cps = _checkpointBreak(sortedNodes, [...checkpoints], partial);
	lower(cps.first);

	return {
		ok: first === null,
		totalRows: list.length,
		sealedRows,
		checkpointsChecked: cps.checked,
		firstBreakAt: first ? first.seq : null,
		firstBreakNode: first ? first.node : null,
		reason: first ? first.reason : null,
	};
}

// --- JSON text with BigInt -----------------------------------------------

/** JSON.stringify replacer that writes a BigInt as its integer token. */
export function bigintReplacer(_key, value) {
	return typeof value === "bigint" ? JSON.rawJSON(value.toString()) : value;
}

/**
 * JSON.parse reviver that keeps an integer a number cannot hold exactly as
 * a BigInt, so text written with `bigintReplacer` reads back the same.
 */
export function bigintReviver(_key, value, context) {
	if (typeof value !== "number" || Number.isSafeInteger(value)) return value;
	const src = context?.source;
	return typeof src === "string" && /^-?\d+$/.test(src) && String(value) !== src
		? BigInt(src)
		: value;
}
