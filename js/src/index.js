// fasten audit and correlation SDK for Node.js. See ../README.md.
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { canonicalTS } from "./canonical_ts.js";
import {
	AuditSealError,
	bigintReplacer,
	bigintReviver,
	ChainError,
	CURRENT_CANONICAL_FORM_ID,
	canonicalJSON,
	detailCommitment,
	detailText,
	GENESIS,
	JsonNumber,
	parseJson,
	seal,
	toChainRow,
	verifyChain,
} from "./chain.js";
import {
	Checkpoint,
	checkpointsSince,
	FileCheckpointSink,
	HttpCheckpointSink,
	loadCheckpoints,
	PartialLastLineError,
	publishCheckpoints,
	takeCheckpoints,
} from "./checkpoints.js";
import {
	coreMetaOf,
	coreRedact,
	coreRedactFull,
	coreRegisterCodes,
	coreRegistryClear,
} from "./core.js";
import { auditStoreFromDsn, streamStoreFromDsn } from "./store/dsn.js";
import { isSentinel, mintSentinel, Stream } from "./streams.js";

// --- Correlation context --------------------------------------------------

const als = new AsyncLocalStorage();

export function mintID() {
	return randomUUID().replace(/-/g, "").slice(0, 12);
}

export function currentRequestID() {
	// A non-string id (e.g. a number passed to withRequestID) counts as
	// missing, so emit mints a new one instead of writing the wrong type.
	const rid = als.getStore()?.requestId;
	return typeof rid === "string" && rid ? rid : null;
}

export function withRequestID(requestId, fn) {
	return als.run({ requestId }, fn);
}

export { isSentinel, mintSentinel };

// A request id from outside (an HTTP header) is used only when it is 1 to
// 128 letters, digits, ".", "_" and "-": it is stored and indexed with every
// row of the request.
const _USABLE_REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;

// --- Code catalog ---------------------------------------------------------

const _registry = new Map();
// Codes loaded from yaml, so reload() can drop removed ones without
// touching codes added with register(). Used by codes_yaml.js.
export const _yamlCodes = new Set();

export function registry() {
	return _registry;
}

// Used by codes_yaml.js reload() to swap in the new registry.
export function _resetRegistryForReload(newRegistry, newYamlCodes) {
	_registry.clear();
	for (const [k, v] of newRegistry) _registry.set(k, v);
	_yamlCodes.clear();
	for (const k of newYamlCodes) _yamlCodes.add(k);
}

// Domain is a plain string chosen by the adopter. Kept so existing
// imports don't break.
export const Domain = {};

// ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
export const Severity = Object.freeze({
	DEBUG: "debug",
	INFO: "info",
	WARN: "warn",
	ERROR: "error",
	CRITICAL: "critical",
});
export const RetentionClass = Object.freeze({
	SHORT: "short",
	MEDIUM: "medium",
	LONG: "long",
});
export const ActorKind = Object.freeze({
	USER: "user",
	SERVICE: "service",
	SCHEDULE: "schedule",
	AGENT: "agent",
});
export const Method = Object.freeze({
	HTTP: "http",
	MQTT: "mqtt",
	CLI: "cli",
	SCHEDULER: "scheduler",
	UI: "ui",
	AGENT_TOOL: "agent_tool",
	SDK: "sdk",
});
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

export const REDACT_REPLACEMENT = "***";

// Same values as FASTEN_ERR_* in fasten-core/include/fasten_core.h.
export const CATALOG_ERR = Object.freeze({
	BACKEND: 1,
	BAD_JSON: 3,
	INVALID_KEY: 6, // key is not UPPER_SNAKE_CASE
	ID_MISMATCH: 7, // Meta.id set but disagrees with the dict key
	DOMAIN_MISMATCH: 8, // code domain disagrees with registration domain
	DUPLICATE_CODE: 9, // code already registered
});

export class AuditCatalogError extends Error {
	constructor(message, code = 0) {
		super(message);
		this.name = "AuditCatalogError";
		this.code = code;
	}
}

// Largest serialised detail or log line that is redacted and kept; the
// same variable and default as Python and Go.
const MAX_DETAIL_BYTES_DEFAULT = 64 * 1024;
function _maxDetailBytes() {
	// Digits only, as Python's int() and Go's Atoi read it: "64k" is not 64.
	const raw = (process.env.FASTEN_MAX_DETAIL_BYTES ?? "").trim();
	const n = /^[0-9]+$/.test(raw) ? Number(raw) : 0;
	return n > 0 ? n : MAX_DETAIL_BYTES_DEFAULT;
}

function _metaFromCore(rm) {
	return {
		id: rm.id,
		domain: rm.domain,
		category: rm.category ?? "",
		action: rm.action ?? "",
		severity: rm.severity ?? "info",
		description: rm.description ?? "",
		emitter: rm.emitter ?? "",
		retentionClass: rm.retention_class ?? "medium",
		highVolume: !!rm.high_volume,
		piiInDetail: !!rm.pii_in_detail,
		declaredUnused: !!rm.declared_unused,
		detailPassthroughKeys: rm.detail_passthrough_keys ?? [],
	};
}

/**
 * Register codes for a domain. The object key is the code id; `meta.id`
 * may be set but must match it.
 *
 *     register('user', {
 *         USER_CREATED: { domain: 'user', action: 'create', severity: 'info' },
 *     });
 *
 * Throws AuditCatalogError (with a numeric .code) on a bad key, id or
 * domain mismatch, or a duplicate.
 */
export function register(domain, codes) {
	const codesObj = {};
	for (const [id, meta] of Object.entries(codes)) {
		const rc =
			meta.retentionClass ?? meta.retention_class ?? RetentionClass.MEDIUM;
		const pii = !!(meta.piiInDetail ?? meta.pii_in_detail);
		// core.js forces SHORT for pii codes; say so instead of doing it silently.
		if (pii && rc !== RetentionClass.SHORT) {
			console.warn(
				`fasten: code ${id} has piiInDetail=true; ` +
					`retentionClass forced to SHORT (was ${String(rc).toUpperCase()}).`,
			);
		}
		if (_registry.has(id)) {
			throw new AuditCatalogError(
				`register: duplicate code '${id}'`,
				CATALOG_ERR.DUPLICATE_CODE,
			);
		}
		codesObj[id] = {
			id: meta.id || id,
			domain: meta.domain || domain,
			category: meta.category ?? "",
			action: meta.action ?? "",
			severity: meta.severity ?? "info",
			description: meta.description ?? "",
			emitter: meta.emitter ?? "",
			retention_class: rc,
			high_volume: !!(meta.highVolume ?? meta.high_volume),
			pii_in_detail: pii,
			declared_unused: !!(meta.declaredUnused ?? meta.declared_unused),
			detail_passthrough_keys:
				meta.detailPassthroughKeys ?? meta.detail_passthrough_keys ?? [],
		};
	}
	try {
		coreRegisterCodes(domain, JSON.stringify(codesObj));
	} catch (e) {
		throw new AuditCatalogError(e.message, e.catalogCode ?? 0);
	}
	for (const id of Object.keys(codes)) {
		const metaJson = coreMetaOf(id);
		if (metaJson && metaJson !== "{}") {
			_registry.set(id, _metaFromCore(JSON.parse(metaJson)));
		}
	}
}

export function metaOf(code) {
	return _registry.get(code);
}

/**
 * Codes whose rows may carry personal data in `detail`: those that declare
 * piiInDetail or are classified SHORT. Sorted.
 */
export function piiCodes() {
	return [..._registry.values()]
		.filter((m) => m.piiInDetail || m.retentionClass === RetentionClass.SHORT)
		.map((m) => m.id)
		.sort();
}

export function dump() {
	return [..._registry.values()]
		.map((m) => [m.id, m.domain, m.severity])
		.sort()
		.map(([i, d, s]) => `${i},${d},${s}`)
		.join("\n");
}

// Test teardown only. Clears the core.js registry.
export function _clearCoreRegistry() {
	coreRegistryClear();
}

// --- Retention ------------------------------------------------------------

const _DURATION_UNITS = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };

/**
 * Parse a retention duration like "30d", "24h", "90m" or "3600s" into
 * milliseconds. Throws on anything else (empty, unknown unit, non-positive,
 * compound).
 */
export function parseDuration(s) {
	if (typeof s !== "string" || !s) {
		throw new Error(
			`retention duration must be a non-empty string (got ${JSON.stringify(s)})`,
		);
	}
	const token = s.trim().toLowerCase();
	const unit = _DURATION_UNITS[token.at(-1)];
	if (token.length < 2 || !unit) {
		throw new Error(
			`retention duration ${JSON.stringify(s)}: unit must be one of s/m/h/d (e.g. '7d', '24h')`,
		);
	}
	const num = token.slice(0, -1);
	if (!/^[+-]?\d+$/.test(num)) {
		throw new Error(
			`retention duration ${JSON.stringify(s)}: expected integer before the unit`,
		);
	}
	const n = Number(num);
	if (n <= 0) {
		throw new Error(
			`retention duration ${JSON.stringify(s)}: must be positive`,
		);
	}
	return n * unit;
}

// Spec §7.2: fasten's own code for the redaction event, registered on first
// use so adopters who never redact don't carry it.
const REDACTION_CODE = "AUDIT_ROW_REDACTED";

function _ensureRedactionCode() {
	if (_registry.has(REDACTION_CODE)) return;
	register("fasten", {
		[REDACTION_CODE]: {
			domain: "fasten",
			category: "retention",
			action: "redact",
			severity: Severity.WARN,
			description: "Audit row detail destroyed under a retention policy",
			emitter: "fasten",
			retentionClass: RetentionClass.LONG,
		},
	});
}

const RETENTION_CHECK_MS = 3_600_000;

// --- Engine ---------------------------------------------------------------

import {
	_setDefaultEngine,
	AuditOutcomeUnknownError,
	AuditQueueDrainer,
	AuditRowRejectedError,
	AuditStoreError,
	errorType,
} from "./audit_queue.js";

export {
	AuditOutcomeUnknownError,
	AuditRowRejectedError,
	AuditSealError,
	AuditStoreError,
	ChainError,
	Checkpoint,
	CURRENT_CANONICAL_FORM_ID,
	canonicalJSON,
	checkpointsSince,
	detailCommitment,
	FileCheckpointSink,
	GENESIS,
	HttpCheckpointSink,
	JsonNumber,
	loadCheckpoints,
	PartialLastLineError,
	parseJson,
	publishCheckpoints,
	seal,
	takeCheckpoints,
	toChainRow,
	verifyChain,
};

// Streams the engine has put an 'error' listener on, so a failed write
// such as EPIPE is logged rather than crashing the process.
const _watched = new WeakSet();

// Whether `store` seals the rows it stores (spec §2.1). A store opts in
// with a seals() method that returns true.
function _seals(store) {
	return typeof store?.seals === "function" && store.seals() === true;
}

// The second stdout line for a row, once the store sealed it (spec §8).
// The detail is the text the store wrote and hashed, so the line verifies
// as it is.
function _sealedLine(row) {
	const { detail, ...rest } = row;
	const head = JSON.stringify({ shape: "audit", ...rest }, bigintReplacer);
	return `${head.slice(0, -1)},"detail":${detailText(detail === undefined ? {} : detail)}}\n`;
}

const _EMPTY_CONFIG = Object.freeze({
	serviceId: "",
	nodeId: "",
	tenantId: null,
	auditStore: null,
	apiStore: null,
	syslogStore: null,
	searchEnabled: false,
	extraRedactKeys: [],
	redactReplacement: null,
	failureStrategy: "queue",
});

const _STREAM_NAMES = ["api", "sys"];

function _pyList(names) {
	return `[${[...names]
		.sort()
		.map((n) => JSON.stringify(n))
		.join(", ")}]`;
}

// The streams named in persistStreams (or FASTEN_PERSIST_STREAMS), or null
// when neither is set. Throws for a name other than api or sys.
function _persistStreams(opt) {
	let named = null;
	if (opt !== undefined && opt !== null) {
		named = [...opt].map((s) => String(s).trim()).filter(Boolean);
	} else {
		const env = process.env.FASTEN_PERSIST_STREAMS ?? "";
		if (env.trim()) {
			named = env
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean);
		}
	}
	if (named === null) return null;
	const set = new Set(named);
	const unknown = [...set].filter((s) => !_STREAM_NAMES.includes(s));
	if (unknown.length) {
		throw new Error(
			`fasten.init: persistStreams=${_pyList(set)}: unknown stream(s) ${_pyList(unknown)}. Only ${_pyList(_STREAM_NAMES)} are valid (audit persistence is driven by auditStore, not persistStreams).`,
		);
	}
	return set;
}

// Every named stream needs a store and every attached store must be named.
function _checkPersistStreams(named, stores) {
	if (named === null) return;
	const have = new Set(_STREAM_NAMES.filter((s) => stores[s]));
	const missing = [...named].filter((s) => !have.has(s));
	const unlisted = [...have].filter((s) => !named.has(s));
	const bits = [];
	if (missing.length) {
		bits.push(
			`named in persistStreams but no store attached: ${_pyList(missing)}`,
		);
	}
	if (unlisted.length) {
		bits.push(`store attached but not in persistStreams: ${_pyList(unlisted)}`);
	}
	if (bits.length) {
		throw new Error(
			`fasten.init: persistStreams / stores mismatch: ${bits.join("; ")}`,
		);
	}
}

export class Engine {
	#config = { ..._EMPTY_CONFIG };
	// The api and sys streams of the current init; see streams.js.
	#streams = null;
	#bootRequestId = null;
	#bootOver = false;
	// An audit row failed to reach the current store outside the drainer.
	#auditWriteSwallowed = false;
	_streamRetention = [];
	_drainer = null; // also read by the audit_queue.js helpers
	_retiring = new Set(); // drainers taken out of the slot, still stopping
	#closing = null;
	_retentionTimer = null;
	_retentionFirst = null;
	#unsealedReported = false;
	// Stores opened from FASTEN_*_DSN, by variable and DSN, so a re-init
	// with the same DSN keeps the store and its connections.
	#envStores = new Map();

	init(opts = {}) {
		const envExtra = (process.env.FASTEN_REDACT_KEYS ?? "")
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
		const extraKeys =
			opts.extraRedactKeys ?? (envExtra.length ? envExtra : null);

		const strategy = (
			opts.auditStoreFailureStrategy ??
			process.env.FASTEN_AUDIT_STORE_FAILURE_STRATEGY ??
			"queue"
		).toLowerCase();
		if (strategy !== "queue" && strategy !== "raise") {
			throw new Error(
				`fasten.init: auditStoreFailureStrategy must be 'queue' or 'raise' (got '${strategy}')`,
			);
		}

		// A store passed in wins over one from the environment, as in Python.
		const auditStore =
			opts.auditStore ?? this.#fromEnv("FASTEN_AUDIT_DSN", auditStoreFromDsn);
		const streamStores = {
			api:
				opts.apiStore ??
				this.#fromEnv("FASTEN_API_DSN", (d) =>
					streamStoreFromDsn(d, "api_log"),
				),
			sys:
				opts.syslogStore ??
				this.#fromEnv("FASTEN_SYSLOG_DSN", (d) =>
					streamStoreFromDsn(d, "syslog"),
				),
		};
		for (const [name, s] of Object.entries(streamStores)) {
			if (s && typeof s.insert !== "function") {
				throw new Error(
					`fasten.init: ${name === "api" ? "apiStore" : "syslogStore"} has no insert()`,
				);
			}
		}
		_checkPersistStreams(_persistStreams(opts.persistStreams), streamStores);
		const streamRetention = [];
		for (const [name, opt, env] of [
			["api", "retentionApi", "FASTEN_RETENTION_API"],
			["sys", "retentionSyslog", "FASTEN_RETENTION_SYSLOG"],
		]) {
			const raw = opts[opt] ?? (process.env[env] || null);
			const ms = raw ? parseDuration(raw) : 0;
			const s = streamStores[name];
			if (!ms || !s) continue;
			if (typeof s.purge !== "function") {
				throw new Error(
					`fasten.init: ${opt} is set but the ${name} store has no purge()`,
				);
			}
			streamRetention.push({ name, store: s, ms });
		}
		const envSearch = (process.env.FASTEN_SEARCH_ENABLED ?? "").toLowerCase();

		const prevStore = this.#config.auditStore;
		this.#config = {
			serviceId: opts.serviceId ?? process.env.FASTEN_SERVICE_ID ?? "",
			nodeId: opts.nodeId ?? process.env.FASTEN_NODE_ID ?? "",
			// An empty FASTEN_TENANT_ID is no tenant, as in the other SDKs.
			tenantId: opts.tenantId ?? (process.env.FASTEN_TENANT_ID || null),
			auditStore,
			apiStore: streamStores.api,
			syslogStore: streamStores.sys,
			searchEnabled:
				opts.searchEnabled === true || ["1", "true", "yes"].includes(envSearch),
			extraRedactKeys: extraKeys ?? [],
			redactReplacement:
				opts.redactReplacement ?? process.env.FASTEN_REDACT_REPLACEMENT ?? null,
			failureStrategy: strategy,
		};
		// A gap in the previous store's history says nothing about another.
		if (this.#config.auditStore !== prevStore) {
			this.#auditWriteSwallowed = false;
		}
		this._stopRetention();
		if (!this.#config.serviceId || !this.#config.nodeId) {
			this.#streams = null;
			throw new Error(
				"fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required",
			);
		}
		// Stream rows without a request_id get this boot id until the first
		// row with a real one (spec persistent-streams §7).
		this.#bootRequestId = mintSentinel("boot", this.#config.serviceId);
		this.#bootOver = false;
		this.#streams = {
			api: new Stream("api", streamStores.api),
			sys: new Stream("sys", streamStores.sys),
		};
		const piiRet =
			opts.retentionPii ?? (process.env.FASTEN_RETENTION_PII || null);
		const piiRetMs = piiRet ? parseDuration(piiRet) : 0;
		const store = this.#config.auditStore;
		if (
			piiRetMs &&
			store &&
			(typeof store.listRedactionCandidates !== "function" ||
				typeof store.redactRows !== "function")
		) {
			throw new Error(
				"fasten.init: retentionPii is set but the audit store has no listRedactionCandidates / redactRows (spec §7.1); personal data would never be redacted",
			);
		}

		// Say once per init that rows are not chained: there is no store to
		// allocate against (spec §8.1), or the store does not seal (§8.2).
		if (!store) {
			this._drainerSysLog("error", "audit_chain_unavailable", {
				store: null,
				reason:
					"no audit store configured (spec 8.1); rows are written to stdout unsealed",
			});
		} else if (!_seals(store)) {
			this._drainerSysLog("error", "audit_chain_unavailable", {
				store: store.constructor?.name ?? null,
				reason:
					"the audit store does not seal rows (spec 2.1); rows are written unsealed",
			});
		}

		if (strategy === "queue" && store) {
			this._installDrainer({
				store: { insert: (row) => this._storeRow(store, row) },
				sysLog: (l, e, f) => this._drainerSysLog(l, e, f),
				capacity: opts.queueCapacity ?? 100,
				retryInitialMs: opts.queueRetryInitialMs ?? 100,
				retryMaxMs: opts.queueRetryMaxMs ?? 60_000,
				retryJitter: opts.queueRetryJitter ?? true,
				maxAttempts: opts.queueDrainMaxAttempts ?? 50,
			});
		} else {
			this._uninstallDrainer(5000, true);
		}
		if (piiRetMs && store) this._startRetention(piiRetMs);
		for (const r of streamRetention) this._startStreamRetention(r);
	}

	// The store for the DSN in environment variable `name`, or null when it
	// is unset or empty.
	#fromEnv(name, open) {
		const dsn = process.env[name];
		if (!dsn) return null;
		const key = `${name}\n${dsn}`;
		let store = this.#envStores.get(key);
		if (!store) {
			store = open(dsn);
			this.#envStores.set(key, store);
		}
		return store;
	}

	emit(input) {
		const cfg = this.#config;
		const row = this._buildRow(input);
		if (cfg.auditStore) {
			if (cfg.failureStrategy === "queue") {
				const d = this._drainer;
				if (d) {
					d.put(row);
				} else {
					const failed = (err) => {
						this.#auditWriteSwallowed = true;
						this._drainerSysLog("error", "audit_sync_fallback_failed", {
							error_type: errorType(err),
							row_id: row?.id ?? null,
						});
					};
					try {
						const p = this._storeRow(cfg.auditStore, row);
						if (typeof p?.then === "function") p.then(undefined, failed);
					} catch (err) {
						failed(err);
					}
				}
			} else {
				let p;
				try {
					p = this._storeRow(cfg.auditStore, row);
				} catch (err) {
					throw new AuditStoreError(err);
				}
				// An async store fails after emit() returns, so hand the caller a
				// promise for the stored row that rejects with AuditStoreError.
				if (typeof p?.then === "function") {
					return p.then(
						(stored) => stored,
						(err) => {
							throw new AuditStoreError(err);
						},
					);
				}
				return p;
			}
		}
		return row;
	}

	// Insert `row` through `store` and return the row as stored: what
	// insert() returned when it is a row with the same id, else `row`. A
	// returned row with a hash is written to stdout again (spec §8); a failed
	// write is logged as audit_stdout_failed, not thrown, since the row is
	// stored. A store that says it seals but returns no hash is logged once.
	_storeRow(store, row) {
		const done = (stored) => {
			const out =
				stored && typeof stored === "object" && stored.id === row.id
					? stored
					: row;
			if (out.hash) {
				this._writeSealed(out);
			} else if (!this.#unsealedReported && _seals(store)) {
				this.#unsealedReported = true;
				this._drainerSysLog("error", "audit_chain_row_unsealed", {
					row_id: row.id,
					store: store.constructor?.name ?? null,
					reason:
						"the audit store reports seals() but insert() did not return the row with a hash",
				});
			}
			return out;
		};
		const p = store.insert(row);
		return typeof p?.then === "function" ? p.then(done) : done(p);
	}

	_writeSealed(row) {
		this._writeStdout(_sealedLine(row), { row_id: row.id, sealed: true });
	}

	// Write one line to stdout. A failed write is logged as
	// audit_stdout_failed with `fields`, never thrown.
	_writeStdout(line, fields) {
		const stream = process.stdout;
		if (!_watched.has(stream)) {
			_watched.add(stream);
			stream.on("error", (err) => this._stdoutFailed(err, {}));
		}
		try {
			stream.write(line, (err) => {
				if (err) this._stdoutFailed(err, fields);
			});
		} catch (err) {
			this._stdoutFailed(err, fields);
		}
	}

	_stdoutFailed(err, fields) {
		this._drainerSysLog("error", "audit_stdout_failed", {
			error_type: err?.name ?? "Error",
			error_code: typeof err?.code === "string" ? err.code : null,
			...fields,
		});
	}

	// Builds the row and writes it to stdout (spec §8 phase 1).
	_buildRow({
		code,
		target,
		actor = "system",
		actorKind = "service",
		detail = {},
		severity,
		method = "sdk",
	}) {
		const cfg = this.#config;
		if (!cfg.serviceId)
			throw new Error("fasten.init() must be called before emit()");
		const meta = _registry.get(code);
		if (!meta) throw new Error(`unknown audit code: ${code}`);
		if (typeof target !== "string") {
			throw new ChainError(
				`emit: target must be a string (got ${typeof target})`,
			);
		}

		const id = `evt-${randomUUID().replace(/-/g, "").slice(0, 20)}`;
		let outDetail;
		if (meta.piiInDetail) {
			const passthrough = new Set(meta.detailPassthroughKeys ?? []);
			const kept = {};
			for (const [k, v] of Object.entries(detail)) {
				if (passthrough.has(k)) kept[k] = v;
			}
			// The markers last, so a passthrough key with a marker's name
			// can't replace it.
			outDetail = {
				...this._redact(kept),
				_redacted: REDACT_REPLACEMENT,
				_pii_in_detail: true,
			};
		} else {
			outDetail = this._redact(detail);
		}

		const row = {
			wire_version: "1",
			id,
			origin_id: id,
			// Spec §8: the store allocates the seq and seals the row on insert.
			monotonic_seq: 0,
			timestamp: canonicalTS(),
			code,
			action: meta.action,
			severity: severity ?? meta.severity,
			service_id: cfg.serviceId,
			source_node_id: cfg.nodeId,
			tenant_id: cfg.tenantId,
			actor,
			actor_kind: actorKind,
			target,
			category: meta.category,
			domain: meta.domain,
			method,
			request_id: currentRequestID() ?? mintID(),
			detail: outDetail,
			pii_in_detail: !!meta.piiInDetail,
		};
		// A row field no store can seal (not a string, or an unpaired
		// surrogate) fails here, before the row is written anywhere.
		try {
			toChainRow(row);
		} catch (err) {
			throw new ChainError(`emit: ${err.message}`);
		}
		// Not sealed yet (spec §8), so the hashes are empty. The
		// store seals the row on insert and it is written again then.
		this._writeStdout(
			`${JSON.stringify({ shape: "audit", ...row, prev_hash: "", hash: "" }, bigintReplacer)}\n`,
			{ row_id: id, sealed: false },
		);

		return row;
	}

	/**
	 * Clear `detail` on PII rows older than `before` and record each one with
	 * an AUDIT_ROW_REDACTED row (spec §7). Never deletes. The record is
	 * inserted straight into the store before its row is cleared, so a failed
	 * insert clears nothing. Returns the ids redacted.
	 */
	async redactExpired({ before, codes = piiCodes(), reason = "retention" }) {
		const store = this.#config.auditStore;
		if (
			typeof store?.listRedactionCandidates !== "function" ||
			typeof store?.redactRows !== "function"
		) {
			throw new AuditStoreError(
				new Error(
					"redactExpired: the audit store does not implement listRedactionCandidates / redactRows (spec §7.1)",
				),
			);
		}
		if (codes.length === 0) return [];
		_ensureRedactionCode();
		const { candidates, skipped } = await store.listRedactionCandidates({
			before,
			codes,
		});
		if (skipped > 0) {
			this._drainerSysLog("warn", "pii_redaction_skipped_legacy_form", {
				rows: skipped,
				reason:
					"canonical_form_id != 2; detail is inside the hash, so redacting would break the chain. The personal data in these rows still exists.",
			});
		}
		const redacted = [];
		// One row at a time, record then clear, so a failure repeats at most
		// one record on the next run.
		for (const c of candidates) {
			const record = this._buildRow({
				code: REDACTION_CODE,
				target: c.id,
				detail: {
					redacted_seq: c.monotonicSeq,
					reason,
					redacted_id: c.id,
				},
			});
			try {
				await this._storeRow(store, record);
			} catch (err) {
				throw new AuditStoreError(err);
			}
			redacted.push(...(await store.redactRows({ ids: [c.id] })));
		}
		return redacted;
	}

	// The audit store, with the methods `op` needs.
	_storeWith(op, ...methods) {
		const store = this.#config.auditStore;
		if (!store || methods.some((m) => typeof store[m] !== "function")) {
			throw new AuditStoreError(
				new Error(
					`${op}: the audit store does not implement ${methods.join(" / ")}`,
				),
			);
		}
		return store;
	}

	/**
	 * Rows this engine's service and node originated that are not shipped
	 * yet, oldest first, as the store's `listUnshipped` returns them with
	 * `exact` set: ship them as `JSON.stringify` writes them. Rows ingested
	 * from other nodes are left out (spec §4).
	 */
	async listUnshipped(limit = 100) {
		const store = this._storeWith("listUnshipped", "listUnshipped");
		return store.listUnshipped(limit, {
			serviceId: this.#config.serviceId,
			sourceNodeId: this.#config.nodeId,
			exact: true,
		});
	}

	/** Mark rows shipped upstream, by id. */
	async markShipped(ids) {
		await this._storeWith("markShipped", "markShipped").markShipped(ids);
	}

	/**
	 * Verify a batch replicated from other nodes and store its verified
	 * prefix (spec §4), through the store's `ingestReplicated`. A chain break
	 * does not throw: the result's `rejectedFromSeq` is the seq to resend
	 * from. The batch stops at the first row from this engine's node id.
	 */
	async ingestReplicated(rows) {
		const store = this._storeWith("ingestReplicated", "ingestReplicated");
		return store.ingestReplicated(rows, { localNodeId: this.#config.nodeId });
	}

	queueStats() {
		return this._drainer ? this._drainer.stats() : null;
	}

	// Also waits for drainers a re-init is retiring, and for api and sys
	// rows still being written to their stores.
	async flush(timeoutMs = 5000) {
		const ds = [...this._retiring].map((e) => e.drainer);
		if (this._drainer) ds.push(this._drainer);
		const ok = await Promise.all([
			...ds.map((d) => d.flush(timeoutMs)),
			this._settleStreams(timeoutMs),
		]);
		return ok.every(Boolean);
	}

	async _settleStreams(timeoutMs) {
		const s = this.#streams;
		if (!s) return true;
		let timer;
		const timeout = new Promise((r) => {
			timer = setTimeout(() => r(false), timeoutMs);
			timer.unref?.();
		});
		const settled = Promise.all([s.api.settle(), s.sys.settle()]).then(
			() => true,
		);
		try {
			return await Promise.race([settled, timeout]);
		} finally {
			clearTimeout(timer);
		}
	}

	/**
	 * Flush pending audit rows for up to half of timeoutMs, then stop the
	 * drainer. Rows still queued get one attempt; a row not stored by
	 * timeoutMs is reported lost (audit_drain_lost_at_stop). Call it on
	 * shutdown: flush() alone leaves a row in backoff unreported at exit.
	 * Emits after close are stored without the queue. Resolves false if a
	 * row was lost.
	 */
	close(timeoutMs = 5000) {
		// A second close while one is running waits for the same outcome.
		if (!this.#closing) {
			this.#closing = this.#close(timeoutMs).finally(() => {
				this.#closing = null;
			});
		}
		return this.#closing;
	}

	async #close(timeoutMs) {
		if (!this._drainer && this._retiring.size === 0) {
			await this._settleStreams(timeoutMs);
			return true;
		}
		const deadline = Date.now() + timeoutMs;
		const left = () => Math.max(0, deadline - Date.now());
		await this.flush(timeoutMs / 2);
		// A drainer a re-init is retiring is stopped within this timeout too.
		const retiring = [...this._retiring];
		const ok = await Promise.all([
			this._uninstallDrainer(left()),
			...retiring.map((e) => e.stop(left())),
		]);
		await Promise.all(retiring.map((e) => e.done));
		return ok.every(Boolean);
	}

	// Stops the drainer and any a re-init is retiring.
	async resetForTests() {
		const retiring = [...this._retiring];
		const stopped = this._uninstallDrainer();
		this._stopRetention();
		this.#config = { ..._EMPTY_CONFIG };
		this.#streams = null;
		this.#auditWriteSwallowed = false;
		await Promise.all([stopped, ...retiring.map((e) => e.stop())]);
		await Promise.all(retiring.map((e) => e.done));
	}

	// The in-flight pass lives on the engine, so a re-init can't start a second
	// pass over the same rows and write their redaction records twice.
	_startRetention(piiRetMs) {
		// The first tick waits out a pass a re-init left running, so the new
		// config gets its pass now rather than at the next hourly tick.
		const tick = async (wait) => {
			while (this._redactionPass) {
				if (!wait) return;
				await this._redactionPass;
				if (this._retentionTimer !== timer) return;
			}
			let done;
			this._redactionPass = new Promise((r) => {
				done = r;
			});
			try {
				await this.redactExpired({
					before: new Date(Date.now() - piiRetMs),
				});
			} catch (err) {
				// Type only: driver messages can carry row values.
				this._drainerSysLog("error", "retention_purge_failed", {
					stream: "audit/pii-redaction",
					error_type: errorType(err?.cause ?? err),
				});
			} finally {
				this._redactionPass = null;
				done();
			}
		};
		const timer = setInterval(() => tick(false), RETENTION_CHECK_MS);
		timer.unref();
		this._retentionTimer = timer;
		this._retentionFirst = setImmediate(() => tick(true));
		this._retentionFirst.unref();
	}

	_stopRetention() {
		clearInterval(this._retentionTimer);
		clearImmediate(this._retentionFirst);
		this._retentionTimer = null;
		this._retentionFirst = null;
		for (const t of this._streamRetention) {
			clearInterval(t.timer);
			clearImmediate(t.first);
		}
		this._streamRetention = [];
	}

	// Delete api or sys rows older than `ms` from the stream's store, on
	// init and then hourly (spec persistent-streams §10).
	_startStreamRetention({ name, store, ms }) {
		let running = false;
		const tick = async () => {
			if (running) return;
			running = true;
			try {
				await store.purge({ before: new Date(Date.now() - ms) });
			} catch (err) {
				// Type only: driver messages can carry row values.
				this._drainerSysLog("error", "retention_purge_failed", {
					stream: name,
					error_type: errorType(err),
				});
			} finally {
				running = false;
			}
		};
		const timer = setInterval(tick, RETENTION_CHECK_MS);
		timer.unref();
		const first = setImmediate(tick);
		first.unref();
		this._streamRetention.push({ timer, first });
	}

	_installDrainer(opts) {
		const next = new AuditQueueDrainer(opts);
		const old = this._drainer;
		this._drainer = next;
		if (old) this._retire(old, true);
	}

	_uninstallDrainer(timeoutMs, flush = false) {
		const old = this._drainer;
		this._drainer = null;
		return old
			? this._retire(old, flush, timeoutMs).done
			: Promise.resolve(true);
	}

	// Spec §10: stops a drainer taken out of the slot, after a re-init
	// flushing it for up to 5 s first. Until it has stopped, flush() and
	// close() wait for it. A re-init whose flush timed out, or whose rows
	// were not all stored, emits audit_drain_install_incomplete, and the
	// next close() resolves false if rows were lost.
	_retire(drainer, flush, timeoutMs = 5000) {
		const entry = { drainer, stopped: null };
		// close() stops it with what is left of its own timeout.
		entry.stop = (ms) => {
			entry.stopped = drainer.stop(ms);
			return entry.stopped;
		};
		entry.done = (async () => {
			const before = drainer.unstoredTotal();
			const flushed = flush ? await drainer.flush(5000) : true;
			const ok = await (entry.stopped ?? drainer.stop(timeoutMs));
			const unstored = drainer.unstoredTotal() - before;
			if (flush && (!flushed || unstored > 0)) {
				this._drainerSysLog("warn", "audit_drain_install_incomplete", {
					flushed,
					unstored,
				});
			}
			this._retiring.delete(entry);
			return ok;
		})();
		this._retiring.add(entry);
		return entry;
	}

	// Redacted copy of obj. A value over FASTEN_MAX_DETAIL_BYTES (default
	// 64 KiB) is replaced by a truncation marker, as in Python and Go.
	_redact(obj) {
		const { extraRedactKeys: extra, redactReplacement: repl } = this.#config;
		const json = JSON.stringify(obj, bigintReplacer);
		const cap = _maxDetailBytes();
		const size = Buffer.byteLength(json, "utf8");
		if (size > cap) {
			return {
				_truncated: true,
				_truncated_bytes: size,
				_max_detail_bytes: cap,
				_summary: `<truncated ${size} bytes; cap ${cap}>`,
			};
		}
		return JSON.parse(
			extra.length || repl
				? coreRedactFull(json, JSON.stringify(extra), repl)
				: coreRedact(json),
			bigintReviver,
		);
	}

	_sysLine(stream, level, event, fields = {}) {
		const line = {
			shape: "sys",
			level,
			event,
			request_id: currentRequestID(),
			service_id: this.#config.serviceId || undefined,
			timestamp: new Date().toISOString(),
			// Fields that aren't JSON (none, or a function) log as {}.
			...(JSON.stringify(fields, bigintReplacer) === undefined ? {} : fields),
		};
		// The whole line, as Go and Python do: a secret can be in the event.
		let out = this._redact(line);
		if (out._truncated) {
			// Keep the line's envelope beside the marker. The event is
			// redacted whole, then shortened.
			const head = this._redact({
				shape: "sys",
				level,
				event: String(event),
				request_id: line.request_id,
				service_id: line.service_id,
				timestamp: line.timestamp,
			});
			if (head._truncated) {
				out = { shape: "sys", level, event: "<truncated>", ...out };
			} else {
				head.event = String(head.event).slice(0, 256);
				out = { ...head, ...out };
			}
		}
		stream.write(`${JSON.stringify(out, bigintReplacer)}\n`);
		// The redacted line, without its shape, is the stored row.
		if (this.#streams) {
			const { shape: _shape, ...row } = out;
			this._pushStream("sys", row);
		}
	}

	// Give a stream row a request_id if it has none (spec persistent-streams
	// §7): the boot id until the first row with a real id, then an orphan id.
	_stampRequestId(row) {
		const rid = row.request_id;
		if (typeof rid === "string" && rid) {
			if (!isSentinel(rid)) this.#bootOver = true;
			return row;
		}
		row.request_id =
			this.#bootRequestId && !this.#bootOver
				? this.#bootRequestId
				: mintSentinel("orphan", this.#config.serviceId);
		return row;
	}

	// Push a redacted row to the stream's ring and store.
	_pushStream(name, row) {
		this.#streams?.[name].push(this._stampRequestId(row));
	}

	// A redacted copy of a row from the caller, with its request_id.
	_streamRow(row) {
		if (row === null || typeof row !== "object" || Array.isArray(row)) {
			throw new TypeError("fasten: a stream row must be an object");
		}
		return this._redact(this._stampRequestId({ ...row }));
	}

	/**
	 * Record a sys row written by the app's own logger: redacted, kept in
	 * the ring and stored if a syslog store is attached. Nothing is written
	 * to stdout. Does nothing before init().
	 */
	pushSyslog(row) {
		if (!this.#streams) return;
		this.#streams.sys.push(this._streamRow(row));
	}

	/**
	 * Record an api row (method, path, status, duration_ms, request_id,
	 * timestamp): redacted, kept in the ring, stored if an api store is
	 * attached, and written to stdout with shape "api". Does nothing before
	 * init().
	 */
	writeApi(row) {
		if (!this.#streams) return;
		const r = this._streamRow(row);
		this.#streams.api.push(r);
		this._writeStdout(
			`${JSON.stringify({ shape: "api", ...r }, bigintReplacer)}\n`,
			{ request_id: r.request_id ?? null, shape: "api" },
		);
	}

	/** writeApi() without the stdout line. */
	pushApi(row) {
		if (!this.#streams) return;
		this.#streams.api.push(this._streamRow(row));
	}

	/** Streams with a store attached: "audit", "api", "sys". */
	persistedStreams() {
		const c = this.#config;
		const out = new Set();
		if (c.auditStore) out.add("audit");
		if (c.apiStore) out.add("api");
		if (c.syslogStore) out.add("sys");
		return out;
	}

	/** Whether free-text search (q=, /search) is on. */
	searchEnabled() {
		return this.#config.searchEnabled;
	}

	/** The audit store passed to init(), or null. */
	auditStore() {
		return this.#config.auditStore;
	}

	// What the reader reads: settings, the stream objects, the audit state.
	_readerState() {
		const c = this.#config;
		return {
			serviceId: c.serviceId,
			nodeId: c.nodeId,
			tenantId: c.tenantId,
			failureStrategy: c.failureStrategy,
			searchEnabled: c.searchEnabled,
			auditStore: c.auditStore,
			streams: this.#streams,
			auditDegraded: () =>
				this.#auditWriteSwallowed || (this._drainer?.unstoredTotal() ?? 0) > 0,
			chainUnavailable: !!c.auditStore && !_seals(c.auditStore),
		};
	}

	_drainerSysLog(level, event, fields) {
		this._sysLine(process.stderr, level, event, fields);
	}

	get log() {
		const self = this;
		return {
			_emit(level, event, fields) {
				self._sysLine(process.stdout, level, event, fields);
			},
			info(event, fields) {
				this._emit("info", event, fields);
			},
			warn(event, fields) {
				this._emit("warn", event, fields);
			},
			error(event, fields) {
				this._emit("error", event, fields);
			},
			debug(event, fields) {
				this._emit("debug", event, fields);
			},
		};
	}
}

// --- Default engine -------------------------------------------------------

export const defaultEngine = new Engine();
_setDefaultEngine(defaultEngine);

export function init(opts) {
	return defaultEngine.init(opts);
}
export function emit(opts) {
	return defaultEngine.emit(opts);
}
export function queueStats() {
	return defaultEngine.queueStats();
}
export async function flush(timeoutMs = 5000) {
	return defaultEngine.flush(timeoutMs);
}
export function close(timeoutMs = 5000) {
	return defaultEngine.close(timeoutMs);
}
export async function redactExpired(opts) {
	return defaultEngine.redactExpired(opts);
}
export async function listUnshipped(limit = 100) {
	return defaultEngine.listUnshipped(limit);
}
export async function markShipped(ids) {
	return defaultEngine.markShipped(ids);
}
export async function ingestReplicated(rows) {
	return defaultEngine.ingestReplicated(rows);
}

export const log = defaultEngine.log;

export function pushSyslog(row) {
	return defaultEngine.pushSyslog(row);
}
export function writeApi(row) {
	return defaultEngine.writeApi(row);
}
export function pushApi(row) {
	return defaultEngine.pushApi(row);
}

/**
 * Middleware that records an api row per request, except for paths in
 * `skip`, with the keys Python's and Go's APILogger write: method, path,
 * status, duration_ms, request_id, timestamp. The request id is a usable
 * X-Request-ID header, else the current one, else a new one; it is set on
 * the response and is current for the rest of the request.
 *
 * Works as Express/Connect middleware `(req, res, next)`, or with
 * http.createServer as `apiLogger()(req, res, () => handler(req, res))`.
 */
export function apiLogger({ skip = [], engine = defaultEngine } = {}) {
	const skipped = new Set(skip);
	return (req, res, next) => {
		const path = (req.url ?? "").split("?")[0];
		const header = req.headers?.["x-request-id"];
		const rid =
			typeof header === "string" && _USABLE_REQUEST_ID.test(header)
				? header
				: (currentRequestID() ?? mintID());
		if (skipped.has(path)) return withRequestID(rid, () => next());
		const start = process.hrtime.bigint();
		if (!res.headersSent) res.setHeader("X-Request-ID", rid);
		let done = false;
		const record = () => {
			if (done) return;
			done = true;
			engine.writeApi({
				method: req.method ?? "",
				path,
				status: res.statusCode,
				duration_ms: Number((process.hrtime.bigint() - start) / 1_000_000n),
				request_id: rid,
				timestamp: canonicalTS(),
			});
		};
		res.once("finish", record);
		res.once("close", record);
		return withRequestID(rid, () => next());
	};
}

// --- Catalog yaml ---------------------------------------------------------

export const codes = {
	register,
	async load(path) {
		const m = await import("./codes_yaml.js");
		return m.load(path);
	},
	async reload() {
		const m = await import("./codes_yaml.js");
		return m.reload();
	},
};

export default {
	init,
	emit,
	log,
	register,
	metaOf,
	dump,
	mintID,
	currentRequestID,
	withRequestID,
	codes,
	Engine,
	defaultEngine,
	AuditStoreError,
	queueStats,
	flush,
	close,
	redactExpired,
	listUnshipped,
	markShipped,
	ingestReplicated,
	piiCodes,
	parseDuration,
	Domain,
	Severity,
	RetentionClass,
	ActorKind,
	Method,
	AuditCatalogError,
	CATALOG_ERR,
	AuditOutcomeUnknownError,
	AuditRowRejectedError,
	AuditSealError,
	ChainError,
	CURRENT_CANONICAL_FORM_ID,
	GENESIS,
	JsonNumber,
	canonicalJSON,
	detailCommitment,
	parseJson,
	seal,
	toChainRow,
	verifyChain,
	Checkpoint,
	PartialLastLineError,
	FileCheckpointSink,
	HttpCheckpointSink,
	takeCheckpoints,
	publishCheckpoints,
	loadCheckpoints,
	checkpointsSince,
	pushSyslog,
	writeApi,
	pushApi,
	apiLogger,
	mintSentinel,
	isSentinel,
};
