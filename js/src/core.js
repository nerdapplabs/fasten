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
	/access_key/i,
	/session_id/i,
	/cookie/i,
	/credential/i,
];

// Matched against string values, anywhere in the string. Same order as
// fasten-core/src/redact.rs.
const _VALUE_SHAPE_RULES = [
	// JWT: header AND payload must be base64url-encoded JSON (eyJ prefix)
	[/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, "***JWT***"],
	// PEM private key block header (RSA, EC, DSA, OPENSSH, or generic)
	[
		/-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/,
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
];

// Card numbers: 13 to 19 digits, optional spaces or dashes, Luhn-checked.
const _CC_DIGIT_RE = /\b\d[\d\s-]{11,17}\d\b/;

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
	const ccMatch = _CC_DIGIT_RE.exec(s);
	if (ccMatch) {
		const digits = ccMatch[0].replace(/[\s-]/g, "");
		if (digits.length >= 13 && digits.length <= 19 && _luhn(digits)) {
			return "***CC***";
		}
	}
	for (const [re, token] of _VALUE_SHAPE_RULES) {
		if (re.test(s)) return token;
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

/**
 * Redact with optional extra key patterns and a custom replacement string.
 * extraKeysJson: JSON array of regex strings (e.g. '["my_secret","ssn"]')
 * replacement:   string to substitute (null means "***")
 */
export function coreRedactFull(inJson, extraKeysJson, replacement) {
	const rep = replacement ?? REDACT_REPLACEMENT;
	let extra = [];
	if (extraKeysJson) {
		try {
			extra = JSON.parse(extraKeysJson).map((k) => new RegExp(k, "i"));
		} catch {
			/* ignore malformed extra keys */
		}
	}
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
