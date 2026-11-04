// fasten audit and correlation SDK for Node.js. See ../README.md.
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { canonicalTS } from "./canonical_ts.js";
import {
	coreMetaOf,
	coreRedact,
	coreRedactFull,
	coreRegisterCodes,
	coreRegistryClear,
} from "./core.js";

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
	AuditQueueDrainer,
	AuditStoreError,
} from "./audit_queue.js";

export { AuditStoreError };

export class Engine {
	#config = {
		serviceId: "",
		nodeId: "",
		tenantId: null,
		auditStore: null,
		apiStore: null,
		extraRedactKeys: [],
		redactReplacement: null,
		failureStrategy: "queue",
	};
	_drainer = null; // also read by the audit_queue.js helpers
	#closing = null;
	_retentionTimer = null;
	_retentionFirst = null;

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

		this.#config = {
			serviceId: opts.serviceId ?? process.env.FASTEN_SERVICE_ID ?? "",
			nodeId: opts.nodeId ?? process.env.FASTEN_NODE_ID ?? "",
			tenantId: opts.tenantId ?? process.env.FASTEN_TENANT_ID ?? null,
			auditStore: opts.auditStore ?? null,
			apiStore: opts.apiStore ?? null,
			extraRedactKeys: extraKeys ?? [],
			redactReplacement:
				opts.redactReplacement ?? process.env.FASTEN_REDACT_REPLACEMENT ?? null,
			failureStrategy: strategy,
		};
		this._stopRetention();
		if (!this.#config.serviceId || !this.#config.nodeId) {
			throw new Error(
				"fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required",
			);
		}
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

		// Spec §8.1: say once per init that rows are not chained.
		this._drainerSysLog("error", "audit_chain_unavailable", {
			store: this.#config.auditStore?.constructor?.name ?? null,
			reason:
				"the JS SDK does not seal rows (spec 2.1); rows are written unsealed",
		});

		if (strategy === "queue" && this.#config.auditStore) {
			this._installDrainer({
				store: this.#config.auditStore,
				sysLog: (l, e, f) => this._drainerSysLog(l, e, f),
				capacity: opts.queueCapacity ?? 100,
				retryInitialMs: opts.queueRetryInitialMs ?? 100,
				retryMaxMs: opts.queueRetryMaxMs ?? 60_000,
				retryJitter: opts.queueRetryJitter ?? true,
				maxAttempts: opts.queueDrainMaxAttempts ?? 50,
			});
		} else {
			this._uninstallDrainer();
		}
		if (piiRetMs && store) this._startRetention(piiRetMs);
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
					const failed = (err) =>
						this._drainerSysLog("error", "audit_sync_fallback_failed", {
							error: `${err?.name ?? "Error"}: ${err?.message ?? err}`,
							row_id: row?.id ?? null,
						});
					try {
						const p = cfg.auditStore.insert(row);
						if (typeof p?.then === "function") p.then(undefined, failed);
					} catch (err) {
						failed(err);
					}
				}
			} else {
				let p;
				try {
					p = cfg.auditStore.insert(row);
				} catch (err) {
					throw new AuditStoreError(err);
				}
				// An async store fails after emit() returns, so hand the caller a
				// promise for the row that rejects with AuditStoreError.
				if (typeof p?.then === "function") {
					return p.then(
						() => row,
						(err) => {
							throw new AuditStoreError(err);
						},
					);
				}
			}
		}
		return row;
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

		const id = `evt-${randomUUID().replace(/-/g, "").slice(0, 20)}`;
		let outDetail;
		if (meta.piiInDetail) {
			const passthrough = new Set(meta.detailPassthroughKeys ?? []);
			const kept = {};
			for (const [k, v] of Object.entries(detail)) {
				if (passthrough.has(k)) kept[k] = v;
			}
			outDetail = {
				_redacted: REDACT_REPLACEMENT,
				_pii_in_detail: true,
				...this._redact(kept),
			};
		} else {
			outDetail = this._redact(detail);
		}

		const row = {
			wire_version: "1",
			id,
			origin_id: id,
			// Spec §8: JS does not allocate seq or seal, so the row goes out
			// with seq 0, as phase-1 stdout lines do; a store allocates it.
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
		process.stdout.write(`${JSON.stringify({ shape: "audit", ...row })}\n`);

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
				await store.insert(record);
			} catch (err) {
				throw new AuditStoreError(err);
			}
			redacted.push(...(await store.redactRows({ ids: [c.id] })));
		}
		return redacted;
	}

	queueStats() {
		return this._drainer ? this._drainer.stats() : null;
	}

	async flush(timeoutMs = 5000) {
		if (!this._drainer) return true;
		return this._drainer.flush(timeoutMs);
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
		if (!this._drainer) return true;
		const deadline = Date.now() + timeoutMs;
		await this.flush(timeoutMs / 2);
		return this._uninstallDrainer(Math.max(0, deadline - Date.now()));
	}

	resetForTests() {
		this._uninstallDrainer();
		this._stopRetention();
		this.#config = {
			serviceId: "",
			nodeId: "",
			tenantId: null,
			auditStore: null,
			apiStore: null,
			extraRedactKeys: [],
			redactReplacement: null,
			failureStrategy: "queue",
		};
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
					error_type: err?.cause?.name ?? err?.name ?? "Error",
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
	}

	_installDrainer(opts) {
		const next = new AuditQueueDrainer(opts);
		const old = this._drainer;
		this._drainer = next;
		if (old) {
			old.flush(5000).then(() => old.stop());
		}
	}

	_uninstallDrainer(timeoutMs) {
		const old = this._drainer;
		this._drainer = null;
		return old ? old.stop(timeoutMs) : Promise.resolve(true);
	}

	_redact(obj) {
		const { extraRedactKeys: extra, redactReplacement: repl } = this.#config;
		const json = JSON.stringify(obj);
		return JSON.parse(
			extra.length || repl
				? coreRedactFull(json, JSON.stringify(extra), repl)
				: coreRedact(json),
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
			...(JSON.stringify(fields) === undefined ? {} : fields),
		};
		// The whole line, as Go and Python do: a secret can be in the event.
		stream.write(`${JSON.stringify(this._redact(line))}\n`);
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

export const log = defaultEngine.log;

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
	piiCodes,
	parseDuration,
	Domain,
	Severity,
	RetentionClass,
	ActorKind,
	Method,
	AuditCatalogError,
	CATALOG_ERR,
};
