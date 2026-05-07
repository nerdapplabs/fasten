/**
 * fasten — audit + correlation SDK for Node.js.
 *
 * Same shape as the Python + Go references: 6 anchors (5 Ws + H) +
 * correlation, opt-in shims, pluggable store, mountable reader.
 *
 * See ../README.md for the full design.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

// --- Correlation context --------------------------------------------------

const als = new AsyncLocalStorage();

export function mintID() {
	return randomUUID().replace(/-/g, "").slice(0, 12);
}

export function currentRequestID() {
	return als.getStore()?.requestId ?? null;
}

export function withRequestID(requestId, fn) {
	return als.run({ requestId }, fn);
}

// --- Code catalog ---------------------------------------------------------

const _registry = new Map();
// Codes whose source-of-truth is a yaml file (vs. programmatic register()).
// Tracked so reload() can drop yaml-removed codes while preserving
// programmatic registrations. Exported for ./codes_yaml.js.
export const _yamlCodes = new Set();

export function registry() {
	return _registry;
}

/**
 * Internal helper for the yaml loader's atomic swap on reload. Replaces
 * every entry of the registry and the yaml-codes set. Not part of the
 * public API; codes_yaml.js uses it under the hood.
 */
export function _resetRegistryForReload(newRegistry, newYamlCodes) {
	_registry.clear();
	for (const [k, v] of newRegistry) _registry.set(k, v);
	_yamlCodes.clear();
	for (const k of newYamlCodes) _yamlCodes.add(k);
}

// Domain is a plain string — adopters define their own vocabulary.
// fasten ships no built-in domain constants; use string literals in your codes module.
export const Domain = {}; // kept for import compatibility; intentionally empty

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

export const REDACT_REPLACEMENT = "***";
export const REDACT_PATTERNS = [
	"api[_-]?key",
	"password",
	"passwd",
	"token",
	"secret",
	"authorization",
	"bearer",
	"m2m[_-]?key",
	"cert[_-]?private",
	"private[_-]?key",
	"access_key",
	"session_id",
	"cookie",
	"credential",
];
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

// UPPER_SNAKE_CASE — letters/digits/underscores; starts with a letter.
const CODE_KEY_RE = /^[A-Z][A-Z0-9_]*$/;

/**
 * Register a batch of codes for a domain.
 *
 * Adopters write the code id once — as the dict key. The SDK fills
 * `meta.id` from the key at register time. Setting `meta.id` explicitly
 * is allowed but must match the key (mismatch is a typo, never a feature).
 *
 *     register('user', {
 *         USER_CREATED: { domain: 'user', action: 'create',
 *                         severity: 'info', ... },
 *     });
 *
 * Validation order — first failure throws:
 *   - key shape: UPPER_SNAKE_CASE
 *   - meta.id empty → fill from key; set → must match key
 *   - meta.domain must equal domain
 *   - duplicate code across registrations
 */
export function register(domain, codes) {
	for (const [id, meta] of Object.entries(codes)) {
		if (!CODE_KEY_RE.test(id)) {
			throw new Error(
				`register: code key '${id}' must be UPPER_SNAKE_CASE (letters, digits, underscores; starts with a letter).`,
			);
		}
		if (!meta.id) {
			meta.id = id;
		} else if (meta.id !== id) {
			throw new Error(
				`register: dict key '${id}' disagrees with meta.id='${meta.id}'. Drop meta.id (it fills from the key) or fix the mismatch.`,
			);
		}
		if (meta.domain !== domain) {
			throw new Error(
				`register: code '${id}' declares domain='${meta.domain}' ` +
					`but registered under '${domain}'.`,
			);
		}
		if (_registry.has(id)) {
			throw new Error(`register: duplicate code '${id}'`);
		}
		// Shallow-clone before mutating: the adopter may reuse the
		// same Meta literal across register() calls or hold onto the
		// reference in their own catalog. Earlier code reassigned
		// `meta.retentionClass` directly, silently changing the
		// adopter's object.
		const m = { ...meta };
		if (m.retentionClass === undefined) {
			// Default matches Python / C++: medium retention unless
			// explicitly set. PII force-override below applies AFTER
			// the default so we always warn before downgrading.
			m.retentionClass = RetentionClass.MEDIUM;
		}
		// pii_in_detail forces retention_class='short'. Mirror Python
		// (codes.py) + C++ (fasten.hpp) — warn whenever a PII code
		// arrives with retention != short, INCLUDING the freshly-
		// defaulted Medium above. Adopters who really want PII +
		// longer retention should set retentionClass=SHORT explicitly
		// to silence the warn (i.e., acknowledge the override).
		if (m.piiInDetail && m.retentionClass !== RetentionClass.SHORT) {
			console.warn(
				`fasten: code ${id} has piiInDetail=true; ` +
					`retentionClass forced to SHORT (was ${String(m.retentionClass).toUpperCase()}).`,
			);
			m.retentionClass = RetentionClass.SHORT;
		}
		_registry.set(id, m);
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

// --- Redaction ------------------------------------------------------------
//
// Deep redact: dict values whose keys match REDACT_PATTERNS get replaced
// with REDACT_REPLACEMENT. Arrays + nested dicts are recursed. Patterns
// come from spec/row-schema.json (single source of truth).

const REDACT_RE = new RegExp(`(${REDACT_PATTERNS.join("|")})`, "i");

function redact(value, extraRe) {
	if (Array.isArray(value)) return value.map((v) => redact(v, extraRe));
	if (value !== null && typeof value === "object") {
		const out = {};
		for (const [k, v] of Object.entries(value)) {
			const hit = REDACT_RE.test(k) || extraRe?.test(k);
			out[k] = hit ? REDACT_REPLACEMENT : redact(v, extraRe);
		}
		return out;
	}
	return value;
}

function buildExtraRe(keys) {
	if (!keys || keys.length === 0) return null;
	const escaped = keys
		.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
		.join("|");
	return new RegExp(`(${escaped})`, "i");
}

// --- Engine ---------------------------------------------------------------
//
// Engine holds all runtime state for one fasten deployment context.
// The module-level free functions (init, emit, …) delegate to `defaultEngine`.
// Applications that need multiple isolated fasten configurations in one
// process construct Engine instances directly:
//
//   import { Engine } from 'fasten';
//   const eng = new Engine();
//   eng.init({ serviceId: 'tenant-a', auditStore: storeA });
//   eng.emit({ code: 'ORDER_PLACED', target: 'order/1' });

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
		extraRedactRe: null,
		failureStrategy: "queue",
	};
	#seq = 0;
	_drainer = null; // accessible by audit_queue.js shims via _setDefaultEngine

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
			extraRedactRe: buildExtraRe(extraKeys),
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
				...redact(kept, cfg.extraRedactRe),
			};
		} else {
			outDetail = redact(detail, cfg.extraRedactRe);
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
			extraRedactRe: null,
			failureStrategy: "queue",
		};
		this.#seq = 0;
	}

	// ── Internal ────────────────────────────────────────────────────────────

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

	_drainerSysLog(level, event, fields) {
		const line = {
			shape: "sys",
			level,
			event,
			request_id: currentRequestID(),
			service_id: this.#config.serviceId || undefined,
			timestamp: new Date().toISOString(),
			...fields,
		};
		process.stderr.write(`${JSON.stringify(line)}\n`);
	}

	get log() {
		const self = this;
		return {
			_emit(level, event, fields = {}) {
				const line = {
					shape: "sys",
					level,
					event,
					request_id: currentRequestID(),
					service_id: self.#config.serviceId || undefined,
					timestamp: new Date().toISOString(),
					...fields,
				};
				process.stdout.write(`${JSON.stringify(line)}\n`);
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

// ── Default Engine + free-function API ────────────────────────────────────

export const defaultEngine = new Engine();
_setDefaultEngine(defaultEngine); // wire up audit_queue.js shims

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

// ── Catalog yaml (P1-11) ──────────────────────────────────────────────────
// Lazy: js-yaml is only imported when load() / reload() runs. Adopters
// who stay on programmatic register() never pay the dep.
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
	// P1-15
	AuditStoreError,
	queueStats,
	flush,
	Domain,
	Severity,
	RetentionClass,
	ActorKind,
	Method,
};
