/**
 * core_ffi.js — pure JS implementation of the fasten-core surface.
 *
 * Replaces the previous koffi/Rust FFI shim. No native dependencies,
 * no Rust toolchain required, no FASTEN_CORE_LIB env var needed.
 *
 * Implements:
 *   - Key-pattern redaction (mirrors spec/row-schema.json x-fasten-redact)
 *   - Code catalog validation (UPPER_SNAKE_CASE, id-mismatch, domain-mismatch,
 *     duplicate) with the same error codes as the Rust ABI
 */

// ── Redaction ─────────────────────────────────────────────────────────────

const REDACT_REPLACEMENT = "***";

// Patterns from spec/row-schema.json x-fasten-redact.patterns — case-insensitive
// match on object keys (not values). Keep in sync with the spec.
const _DEFAULT_PATTERNS = [
	/api[_-]?key/i,
	/^password$/i,
	/^passwd$/i,
	/token/i,
	/secret/i,
	/authorization/i,
	/bearer/i,
	/m2m[_-]?key/i,
	/cert[_-]?private/i,
	/private[_-]?key/i,
	/access_key/i,
	/session_id/i,
	/^cookie$/i,
	/credential/i,
];

function _matchesAny(key, patterns) {
	return patterns.some((p) => p.test(key));
}

function _redactObj(val, patterns, replacement) {
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
 * replacement:   string to substitute (null → "***")
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

// ── Catalog registry + validation ─────────────────────────────────────────

const UPPER_SNAKE_RE = /^[A-Z][A-Z0-9_]*$/;

// Error codes mirror the Rust ABI constants (fasten_store_core.h FASTEN_ERR_*).
const ERR = {
	INVALID_KEY:     6,
	ID_MISMATCH:     7,
	DOMAIN_MISMATCH: 8,
	DUPLICATE_CODE:  9,
};

// In-process canonical registry used by coreMetaOf / coreRegistryClear.
// index.js maintains its own _registry populated from this via coreMetaOf.
const _coreRegistry = new Map();

function _err(msg, code) {
	const e = new Error(msg);
	e.rustCode = code;
	return e;
}

/**
 * Validate and register a batch of codes for a domain.
 * Throws with .rustCode set on violation — same error contract as the Rust ABI.
 * Normalization applied: id filled from key; retention_class forced to "short"
 * when pii_in_detail=true.
 */
export function coreRegisterCodes(domain, codesJson) {
	const codes = JSON.parse(codesJson);
	// Full validation pass before any mutation.
	for (const [id, meta] of Object.entries(codes)) {
		if (!UPPER_SNAKE_RE.test(id))
			throw _err(`code key "${id}" must be UPPER_SNAKE_CASE`, ERR.INVALID_KEY);
		if (meta.id && meta.id !== id)
			throw _err(`code key "${id}" disagrees with Meta.id="${meta.id}"`, ERR.ID_MISMATCH);
		if (meta.domain && meta.domain !== domain)
			throw _err(
				`code ${id} declares domain="${meta.domain}" but registered under "${domain}"`,
				ERR.DOMAIN_MISMATCH,
			);
		if (_coreRegistry.has(id))
			throw _err(`duplicate code: "${id}"`, ERR.DUPLICATE_CODE);
	}
	// Commit with normalization (all validation passed).
	for (const [id, meta] of Object.entries(codes)) {
		const pii = !!meta.pii_in_detail;
		_coreRegistry.set(id, {
			...meta,
			id,
			domain: meta.domain || domain,
			retention_class: pii ? "short" : (meta.retention_class || "medium"),
			detail_passthrough_keys: meta.detail_passthrough_keys ?? [],
		});
	}
}

/** Return canonical JSON for a registered code, or null if not found. */
export function coreMetaOf(code) {
	const m = _coreRegistry.get(code);
	return m ? JSON.stringify(m) : null;
}

/** Wipe the registry — for test teardown only. */
export function coreRegistryClear() {
	_coreRegistry.clear();
}
