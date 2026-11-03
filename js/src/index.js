// fasten audit and correlation SDK for Node.js. See ../README.md.
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
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

// --- Engine ---------------------------------------------------------------

import {
	AuditQueueDrainer,
	AuditStoreError,
	_setDefaultEngine,
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
	#seq = 0;
	_drainer = null; // also read by the audit_queue.js helpers

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
		if (!this.#config.serviceId || !this.#config.nodeId) {
			throw new Error(
				"fasten.init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required",
			);
		}

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
	}

	emit({
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
		const extraKeys = cfg.extraRedactKeys;
		const redactRepl = cfg.redactReplacement; // null means "***"
		const redact = (obj) => {
			const json = JSON.stringify(obj);
			return JSON.parse(
				extraKeys.length || redactRepl
					? coreRedactFull(json, JSON.stringify(extraKeys), redactRepl)
					: coreRedact(json),
			);
		};
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
				...redact(kept),
			};
		} else {
			outDetail = redact(detail);
		}

		const row = {
			wire_version: "1",
			id,
			origin_id: id,
			monotonic_seq: ++this.#seq,
			timestamp: new Date().toISOString(),
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

		if (cfg.auditStore) {
			if (cfg.failureStrategy === "queue") {
				const d = this._drainer;
				if (d) {
					d.put(row);
				} else {
					try {
						cfg.auditStore.insert(row);
					} catch (err) {
						this._drainerSysLog("error", "audit_sync_fallback_failed", {
							error: `${err?.name ?? "Error"}: ${err?.message ?? err}`,
							row_id: row?.id ?? null,
						});
					}
				}
			} else {
				try {
					cfg.auditStore.insert(row);
				} catch (err) {
					throw new AuditStoreError(err);
				}
			}
		}
		return row;
	}

	queueStats() {
		return this._drainer ? this._drainer.stats() : null;
	}

	async flush(timeoutMs = 5000) {
		if (!this._drainer) return true;
		return this._drainer.flush(timeoutMs);
	}

	resetForTests() {
		this._uninstallDrainer();
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
		this.#seq = 0;
	}

	_installDrainer(opts) {
		const next = new AuditQueueDrainer(opts);
		const old = this._drainer;
		this._drainer = next;
		if (old) {
			old.flush(5000).then(() => old.stop());
		}
	}

	_uninstallDrainer() {
		const old = this._drainer;
		this._drainer = null;
		if (old) old.stop();
	}

	_sysLine(stream, level, event, fields = {}) {
		const line = {
			shape: "sys",
			level,
			event,
			request_id: currentRequestID(),
			service_id: this.#config.serviceId || undefined,
			timestamp: new Date().toISOString(),
			...fields,
		};
		stream.write(`${JSON.stringify(line)}\n`);
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
	Domain,
	Severity,
	RetentionClass,
	ActorKind,
	Method,
	AuditCatalogError,
	CATALOG_ERR,
};
