// Redaction and code-catalog validation in plain JS (no native library).
// Error codes match fasten-core's C ABI.

// --- Redaction -------------------------------------------------------------

const REDACT_REPLACEMENT = "***";

// Matched against object keys, case-insensitive. Keep in sync with
// x-fasten-redact.patterns in spec/row-schema.json.
const _DEFAULT_PATTERNS = [
	/api[_-]?key/i,
	/password/i,
	/passwd/i,
	/token/i,
	/secret/i,
	/authorization/i,
	/bearer/i,
	/m2m[_-]?key/i,
	/cert[_-]?private/i,
	/private[_-]?key/i,
	/access[_-]?key/i,
	/session[_-]?id/i,
	/cookie/i,
	/credential/i,
	/pwd/i,
	/passphrase/i,
	/dsn$/i,
	// Whole key only: as substrings they would match primary_key or author.
	/^key$/i,
	/^auth$/i,
];

// A JWT: eyJ... "." eyJ... "." signature, in base64url. A linear scan with
// the same match as fasten-core's regex.
function _hasJwt(s) {
	if (!s.includes(".eyJ")) return false;
	for (const run of s.match(/[A-Za-z0-9_.-]+/g) ?? []) {
		if (!run.includes(".eyJ")) continue;
		const parts = run.split(".");
		for (let k = 0; k + 2 < parts.length; k++) {
			const h = parts[k].indexOf("eyJ");
			if (
				h >= 0 &&
				h + 3 < parts[k].length &&
				parts[k + 1].startsWith("eyJ") &&
				parts[k + 1].length > 3 &&
				parts[k + 2].length > 0
			) {
				return true;
			}
		}
	}
	return false;
}

// Credentials in a URL: scheme://user:password@, user may be empty. Checked
// from each "://", so a long string without one costs a single scan.
const _URL_USERINFO_RE = /[^\t\n\v\f\r /:@?#]*:[^\t\n\v\f\r /@?#]+@/y;
function _hasUrlCredentials(s) {
	for (let i = s.indexOf("://"); i !== -1; i = s.indexOf("://", i + 1)) {
		if (i > 0 && /[A-Za-z0-9+.-]/.test(s[i - 1])) {
			_URL_USERINFO_RE.lastIndex = i + 3;
			if (_URL_USERINFO_RE.test(s)) return true;
		}
	}
	return false;
}

// Matched against string values, anywhere in the string: a regex or a test
// function. Same order as fasten-core/src/redact.rs.
const _VALUE_SHAPE_RULES = [
	[_hasJwt, "***JWT***"],
	// PEM private key block header, encrypted or not
	[
		/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----/,
		"***PRIVATE_KEY***",
	],
	// AWS access key: permanent AKIA or short-lived ASIA
	[/(?:AKIA|ASIA)[A-Z0-9]{16}/, "***AWS_KEY***"],
	// GitHub tokens
	[/(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/, "***GH_TOKEN***"],
	// Stripe live secret key
	[/sk_live_[A-Za-z0-9]{24,}/, "***STRIPE_KEY***"],
	// OpenAI API key (legacy sk-... and org sk-proj-... formats)
	[/sk-(?:proj-)?[A-Za-z0-9_-]{32,}/, "***OPENAI_KEY***"],
	// GitHub fine-grained personal access token
	[/github_pat_[A-Za-z0-9_]{22,}/, "***GH_TOKEN***"],
	// Slack token
	[/xox[abposr]-[A-Za-z0-9-]{10,}/, "***SLACK_TOKEN***"],
	[_hasUrlCredentials, "***URL_CREDENTIALS***"],
	[_hasAuthHeader, "***AUTH_HEADER***"],
];

// A run of digit groups split by spaces or dashes.
const _DIGIT_RUN_RE = /[0-9]+(?:[ -]+[0-9]+)*/g;

// Card layouts printed in groups, as in fasten-core.
const _CARD_LAYOUTS = [
	[4, 4, 4, 4],
	[4, 4, 4, 4, 1],
	[4, 4, 4, 4, 2],
	[4, 4, 4, 4, 3],
	[4, 6, 5],
	[4, 6, 4],
];

const _WORD_CHAR_RE = /[A-Za-z0-9_]/;

// Whether s holds a card number: a group of 13 to 19 digits, or groups in a
// card layout, that pass the Luhn check. Same rules as fasten-core: digits
// joined to a letter or "_" are skipped.
function _hasCard(s) {
	for (const m of s.matchAll(_DIGIT_RUN_RE)) {
		const start = m.index;
		const end = start + m[0].length;
		const openStart = start === 0 || !_WORD_CHAR_RE.test(s[start - 1]);
		const openEnd = end === s.length || !_WORD_CHAR_RE.test(s[end]);
		const groups = m[0].split(/[ -]+/);
		const fitsEnd = (e) => e < groups.length || openEnd;
		for (let i = 0; i < groups.length; i++) {
			if (i === 0 && !openStart) continue;
			const g = groups[i];
			if (g.length >= 13 && g.length <= 19 && fitsEnd(i + 1) && _luhn(g)) {
				return true;
			}
			for (const layout of _CARD_LAYOUTS) {
				const e = i + layout.length;
				if (e > groups.length || !fitsEnd(e)) continue;
				const window = groups.slice(i, e);
				if (
					window.every((w, k) => w.length === layout[k]) &&
					_luhn(window.join(""))
				) {
					return true;
				}
			}
		}
	}
	return false;
}

// An Authorization header value: Bearer or Basic, then a credential that
// holds a digit or one of + / =, as in fasten-core.
const _AUTH_HEADER_RE =
	/(?:^|[^A-Za-z0-9_])(?:Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=-]{16,})/g;
function _hasAuthHeader(s) {
	for (const m of s.matchAll(_AUTH_HEADER_RE)) {
		if (/[0-9+/=]/.test(m[1])) return true;
	}
	return false;
}

function _luhn(digits) {
	const len = digits.length;
	let sum = 0;
	for (let i = 0; i < len; i++) {
		let n = Number.parseInt(digits[len - 1 - i], 10);
		if (i % 2 === 1) {
			n *= 2;
			if (n > 9) n -= 9;
		}
		sum += n;
	}
	return sum % 10 === 0;
}

function _checkValueShape(s) {
	// The Luhn check keeps order numbers and similar ids from matching.
	if (_hasCard(s)) return "***CC***";
	for (const [rule, token] of _VALUE_SHAPE_RULES) {
		if (typeof rule === "function" ? rule(s) : rule.test(s)) return token;
	}
	return null;
}

function _matchesAny(key, patterns) {
	return patterns.some((p) => p.test(key));
}

function _redactObj(val, patterns, replacement) {
	if (typeof val === "string") {
		const shaped = _checkValueShape(val);
		return shaped !== null ? shaped : val;
	}
	if (val === null || typeof val !== "object") return val;
	if (Array.isArray(val)) {
		return val.map((item) => _redactObj(item, patterns, replacement));
	}
	const out = {};
	for (const [k, v] of Object.entries(val)) {
		out[k] = _matchesAny(k, patterns)
			? replacement
			: _redactObj(v, patterns, replacement);
	}
	return out;
}

/**
 * Redact a JSON string using the default key-pattern list.
 * Returns a JSON string with matching key values replaced by "***".
 */
export function coreRedact(inJson) {
	const obj = JSON.parse(inJson);
	return JSON.stringify(_redactObj(obj, _DEFAULT_PATTERNS, REDACT_REPLACEMENT));
}

function _escapeRe(s) {
	return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Redact with optional extra key patterns and a custom replacement string.
 * extraKeysJson: JSON array of plain strings, matched literally (e.g. '["my_secret","ssn"]')
 * replacement:   string to substitute (null means "***")
 */
export function coreRedactFull(inJson, extraKeysJson, replacement) {
	const rep = replacement ?? REDACT_REPLACEMENT;
	const extra = extraKeysJson
		? JSON.parse(extraKeysJson).map((k) => new RegExp(_escapeRe(k), "i"))
		: [];
	const patterns = [..._DEFAULT_PATTERNS, ...extra];
	const obj = JSON.parse(inJson);
	return JSON.stringify(_redactObj(obj, patterns, rep));
}

// --- Catalog ---------------------------------------------------------------

const UPPER_SNAKE_RE = /^[A-Z][A-Z0-9_]*$/;

// FASTEN_ERR_* in fasten-core/include/fasten_core.h.
const ERR = {
	INVALID_KEY: 6,
	ID_MISMATCH: 7,
	DOMAIN_MISMATCH: 8,
	DUPLICATE_CODE: 9,
};

// index.js keeps its own copy, filled from here through coreMetaOf.
const _coreRegistry = new Map();

function _err(msg, code) {
	const e = new Error(msg);
	e.catalogCode = code;
	return e;
}

/**
 * Validate and register codes for a domain. Nothing is registered if any
 * code fails. Errors carry .catalogCode. pii codes get retention "short".
 */
export function coreRegisterCodes(domain, codesJson) {
	const codes = JSON.parse(codesJson);
	for (const [id, meta] of Object.entries(codes)) {
		if (!UPPER_SNAKE_RE.test(id))
			throw _err(`code key "${id}" must be UPPER_SNAKE_CASE`, ERR.INVALID_KEY);
		if (meta.id && meta.id !== id)
			throw _err(
				`code key "${id}" disagrees with Meta.id="${meta.id}"`,
				ERR.ID_MISMATCH,
			);
		if (meta.domain && meta.domain !== domain)
			throw _err(
				`code ${id} declares domain="${meta.domain}" but registered under "${domain}"`,
				ERR.DOMAIN_MISMATCH,
			);
		if (_coreRegistry.has(id))
			throw _err(`duplicate code: "${id}"`, ERR.DUPLICATE_CODE);
	}
	for (const [id, meta] of Object.entries(codes)) {
		const pii = !!meta.pii_in_detail;
		_coreRegistry.set(id, {
			...meta,
			id,
			domain: meta.domain || domain,
			retention_class: pii ? "short" : meta.retention_class || "medium",
			detail_passthrough_keys: meta.detail_passthrough_keys ?? [],
		});
	}
}

/** Return canonical JSON for a registered code, or null if not found. */
export function coreMetaOf(code) {
	const m = _coreRegistry.get(code);
	return m ? JSON.stringify(m) : null;
}

/** Test teardown only. */
export function coreRegistryClear() {
	_coreRegistry.clear();
}
