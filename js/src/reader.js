/**
 * HTTP reader for the audit, api and sys streams: the routes Python's
 * fasten.reader.router() and Go's NewReader serve.
 *
 *   import { reader, requireBearer } from 'fasten-sdk/reader';
 *   const handler = reader({ auth: requireBearer() });
 *   http.createServer((req, res) => handler(req, res)).listen(8080);
 *   app.use('/api/v1/logs', handler);   // Express
 *
 * The reader returns raw audit rows, so it needs an explicit auth choice.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { errorType } from "./audit_queue.js";
import { canonicalTS } from "./canonical_ts.js";
import { bigintReplacer, canonicalTimestamp, verifyChain } from "./chain.js";
import { currentRequestID, defaultEngine } from "./index.js";

const NOT_INITIALISED = "transport not initialised — call fasten.init() first";
const NO_AUDIT_STORE = "audit store not initialised — call fasten.init() first";
const MAX_Q = 1024;
const SEARCH_STREAMS = ["audit", "api", "sys"];

class HttpError extends Error {
	constructor(status, detail) {
		super(detail);
		this.status = status;
	}
}

const unprocessable = (detail) => new HttpError(422, detail);

/**
 * `{ bearer }` for reader()'s auth, from the token in `tokenEnv`. Throws
 * when it is unset or empty rather than allowing every request.
 */
export function requireBearer(tokenEnv = "FASTEN_READER_TOKEN") {
	const token = process.env[tokenEnv] ?? "";
	if (!token) {
		throw new Error(
			`fasten reader requireBearer: $${tokenEnv} is unset or empty. Set it to the shared bearer token, or pass your own verify function.`,
		);
	}
	return { bearer: token };
}

function _sha256(s) {
	return createHash("sha256").update(s, "utf8").digest();
}

// The auth check from reader()'s auth option: a function (req) that
// resolves true when the request may read, or null for "none".
function _authCheck(auth) {
	if (auth === "none") return null;
	if (auth && typeof auth === "object") {
		const hasBearer = auth.bearer !== undefined;
		const hasVerify = auth.verify !== undefined;
		if (hasBearer && hasVerify) {
			throw new Error(
				"fasten reader: pass auth.bearer or auth.verify, not both.",
			);
		}
		if (hasBearer) {
			if (typeof auth.bearer !== "string" || !auth.bearer) {
				throw new Error(
					"fasten reader: auth.bearer must be a non-empty string.",
				);
			}
			// Digests, so the comparison takes the same time for any length.
			const want = _sha256(auth.bearer);
			return (req) => {
				const h = req.headers?.authorization;
				if (typeof h !== "string" || !h.startsWith("Bearer ")) return false;
				return timingSafeEqual(_sha256(h.slice(7)), want);
			};
		}
		if (hasVerify) {
			if (typeof auth.verify !== "function") {
				throw new Error("fasten reader: auth.verify must be a function.");
			}
			return auth.verify;
		}
	}
	throw new Error(
		'fasten reader: auth is required. Pass { bearer: token } (or requireBearer()), { verify: (req) => boolean }, or "none" when the routes are authenticated outside the reader. There is no default, so a reader cannot be deployed without auth by mistake.',
	);
}

// Python's repr of a list of strings, for error texts that match Python's.
function _pyRepr(list) {
	const one = (s) =>
		s.includes("'") && !s.includes('"')
			? `"${s.replace(/\\/g, "\\\\")}"`
			: `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
	return `[${list.map(one).join(", ")}]`;
}

const _WINDOW_TS =
	/^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)([Zz]|[+-]\d{2}:\d{2})?$/;

// ?since= / ?until= in the canonical form (spec §4.3), since stored
// timestamps are compared as text. Empty gives null; a timestamp without an
// offset is UTC.
function _windowTS(name, s) {
	if (s === null || s === "") return null;
	const m = _WINDOW_TS.exec(s);
	if (m) {
		const off = !m[3] || m[3] === "Z" || m[3] === "z" ? "+00:00" : m[3];
		// An explicit offset, so a valid stamp always comes back changed.
		const input = `${m[1]}T${m[2]}${off}`;
		const out = canonicalTimestamp(input);
		if (out !== input) return out;
	}
	throw unprocessable(
		`${name} must be RFC3339 (e.g. 2026-08-21T10:00:00Z): invalid timestamp ${JSON.stringify(s)}`,
	);
}

function _int(name, s) {
	if (!/^[+-]?\d+$/.test(s)) throw unprocessable(`${name} must be an integer`);
	const n = Number(s);
	if (!Number.isSafeInteger(n)) {
		throw unprocessable(
			`${name} must be between ${Number.MIN_SAFE_INTEGER} and ${Number.MAX_SAFE_INTEGER}`,
		);
	}
	return n;
}

// The path as sent, up to "?". A path with an empty, "." or ".." segment,
// a backslash, or "%2e", "%2f" or "%5c" is not one the reader serves:
// URL parsing would read it as another path than a router in front sees.
function _rawPath(url) {
	const path = url.split("?")[0];
	if (
		path.includes("//") ||
		path.includes("\\") ||
		/\/\.\.?(\/|$)/.test(path) ||
		/%(2e|2f|5c)/i.test(path)
	) {
		return null;
	}
	return path;
}

function _limit(s, def, max) {
	if (s === null || s === "") return def;
	const n = _int("limit", s);
	if (n < 1 || n > max) {
		throw unprocessable(`limit must be between 1 and ${max}`);
	}
	return n;
}

function _q(s, { required = false } = {}) {
	if (s === null) {
		if (required) throw unprocessable("q is required");
		return null;
	}
	if (s.length === 0) throw unprocessable("q must not be empty");
	if ([...s].length > MAX_Q) {
		throw unprocessable(`q must be at most ${MAX_Q} characters`);
	}
	return s;
}

function _seals(store) {
	return typeof store?.seals === "function" && store.seals() === true;
}

// The type of a drainer error, without its message.
function _errorType(lastError) {
	return typeof lastError === "string" ? lastError.split(":")[0] : lastError;
}

// A stream read from a store passed to reader(), or no stream at all.
function _storeStream(store) {
	if (!store) {
		return {
			source: () => "ring",
			query: () => [],
			countMatching: () => 0,
			search: () => null,
			ring: { length: 0 },
		};
	}
	return {
		source: () => (store.degraded === true ? "store-degraded" : "store"),
		query: (o) => store.query(o),
		countMatching: (f) => store.countMatching(f),
		search: (o) => store.search(o),
		ring: { length: 0 },
	};
}

/**
 * Build the reader: a `(req, res, next?)` handler for http.createServer,
 * Express/Connect middleware, or any framework that hands over Node's
 * request and response. Routes, relative to `prefix` (or to where Express
 * mounted it):
 *
 *   GET /audit          audit rows (filters, limit, offset, after)
 *   GET /audit/doctor   audit pipeline health and a chain spot check
 *   GET /correlate      audit, api and sys rows for one request_id
 *   GET /search         free-text search over stored rows
 *   GET /sys            sys rows (q= search when enabled)
 *   GET /api            api rows
 *   GET /topology       nodes, services and tenants writing audit rows
 *
 * A path it does not serve goes to `next` when given, else gets a 404.
 *
 * @param {object} opts
 * @param {{ bearer: string } | { verify: (req: any) => boolean | Promise<boolean> } | "none"} opts.auth
 *   Required. "none" only when something in front of the reader
 *   authenticates every request.
 * @param {any} [opts.engine] the Engine to read; default the default engine.
 * @param {any} [opts.store] audit store to read; default the engine's;
 *   null for no audit store.
 * @param {{ api?: any, sys?: any }} [opts.streams] stream stores to read;
 *   a stream left out is the engine's, null is no store.
 * @param {(req: any) => string | null | Promise<string | null>} [opts.tenantScope]
 *   resolves the caller's tenant; every route is then limited to it and a
 *   caller without one gets a 401.
 * @param {boolean} [opts.enforceTenantIsolation] refuse to build without
 *   tenantScope.
 * @param {boolean} [opts.searchEnabled] default the engine's setting.
 * @param {string} [opts.nodeId] node whose chain the doctor checks; default
 *   the engine's.
 * @param {string} [opts.prefix] path prefix to strip, e.g. "/api/v1/logs".
 */
export function reader(opts = {}) {
	const check = _authCheck(opts.auth);
	const {
		engine = defaultEngine,
		tenantScope = null,
		enforceTenantIsolation = false,
		prefix = "",
	} = opts;
	if (enforceTenantIsolation && typeof tenantScope !== "function") {
		throw new Error(
			"fasten reader: enforceTenantIsolation requires a tenantScope function. Wire (req) => tenant from your auth layer, or drop enforceTenantIsolation for a single-tenant deployment.",
		);
	}
	if (tenantScope !== null && typeof tenantScope !== "function") {
		throw new Error("fasten reader: tenantScope must be a function.");
	}
	const given = {};
	for (const name of ["api", "sys"]) {
		if (opts.streams && opts.streams[name] !== undefined) {
			given[name] = _storeStream(opts.streams[name]);
		}
	}
	const base = prefix.replace(/\/+$/, "");

	// The streams one request reads: those passed to reader(), the engine's
	// for the rest; null when neither has any.
	const readStreams = (own) => {
		if (!given.api && !given.sys) return own;
		return {
			api: given.api ?? own?.api ?? _storeStream(null),
			sys: given.sys ?? own?.sys ?? _storeStream(null),
		};
	};

	// What one request reads.
	const context = () => {
		const st = engine._readerState();
		const store = opts.store !== undefined ? opts.store : st.auditStore;
		const streams = readStreams(st.streams);
		const source = (name) => {
			if (name === "audit") {
				if (!store) return "ring";
				const degraded =
					store.degraded === true ||
					(store === st.auditStore && st.auditDegraded());
				return degraded ? "store-degraded" : "store";
			}
			return streams ? streams[name].source() : "ring";
		};
		return {
			st,
			store,
			streams,
			source,
			searchOn: opts.searchEnabled ?? st.searchEnabled,
			nodeId: opts.nodeId ?? (st.nodeId || null),
		};
	};

	const log = (event, fields) => {
		try {
			engine._drainerSysLog("error", event, {
				request_id: currentRequestID(),
				...fields,
			});
		} catch {
			// Logging must not turn a response into a crash.
		}
	};

	const routes = {
		"/sys": routeSys,
		"/api": routeApi,
		"/audit": routeAudit,
		"/audit/doctor": routeDoctor,
		"/correlate": routeCorrelate,
		"/search": routeSearch,
		"/topology": routeTopology,
	};

	return async function fastenReader(req, res, next) {
		const rawUrl = req.url ?? "/";
		let path = _rawPath(rawUrl);
		if (path !== null && base) {
			if (path === base || path.startsWith(`${base}/`)) {
				path = path.slice(base.length) || "/";
			} else {
				path = null;
			}
		}
		const route = path === null ? undefined : routes[path];
		if (!route) {
			if (typeof next === "function") return next();
			return send(res, 404, { detail: "Not Found" });
		}
		if (req.method !== "GET") {
			res.setHeader?.("Allow", "GET");
			return send(res, 405, { detail: "Method Not Allowed" });
		}
		try {
			if (check && (await check(req)) !== true) {
				return send(res, 401, { detail: "unauthenticated" });
			}
			// The tenant before the parameters: a caller without one learns
			// nothing from a 422.
			let tenant = null;
			if (tenantScope) {
				const t = await tenantScope(req);
				// An empty tenant would read as no filter.
				if (typeof t !== "string" || !t) {
					throw new HttpError(401, "unauthenticated: tenant scope unresolved");
				}
				tenant = t;
			}
			const qs = rawUrl.indexOf("?");
			const q = _params(
				new URLSearchParams(qs >= 0 ? rawUrl.slice(qs + 1) : ""),
			);
			const run = route(q);
			return send(res, 200, await run(context(), tenant));
		} catch (err) {
			if (err instanceof HttpError) {
				return send(res, err.status, { detail: err.message });
			}
			// Type only: driver errors can quote SQL, row values and the host.
			log("reader_query_failed", { path, error_type: errorType(err) });
			return send(res, 500, { detail: "internal error" });
		}
	};

	// The store's count of rows matching `filters`, or null when it has no
	// count() or it fails: the rows are still worth returning.
	async function countOrNull(store, filters) {
		if (typeof store.count !== "function") return null;
		try {
			return await store.count(filters);
		} catch (err) {
			log("reader_count_failed", { error_type: errorType(err) });
			return null;
		}
	}

	// Doctor check failures go to the log by type; the response gets a fixed
	// text.
	function checkFailed(check, err) {
		log("doctor_check_failed", { check, error_type: errorType(err) });
		return `${check} check failed; see the service log`;
	}

	function searchGuard(ctx, since) {
		if (!ctx.searchOn) {
			return "search disabled — set search.enabled (FASTEN_SEARCH_ENABLED=true) to enable free-text q=";
		}
		if (!since)
			return "q= search requires a 'since' bound (no unbounded scans)";
		return null;
	}

	function routeSys(q) {
		const limit = _limit(q.get("limit"), 100, 1000);
		const text = _q(q.get("q"));
		return async (ctx, tenant) => {
			const completeness = { sys: ctx.source("sys") };
			if (!ctx.streams) {
				return { rows: [], completeness, error: NOT_INITIALISED };
			}
			const since = _windowTS("since", q.get("since"));
			const until = _windowTS("until", q.get("until"));
			const sys = ctx.streams.sys;
			if (text !== null) {
				const err = searchGuard(ctx, since);
				if (err) return { rows: [], completeness, error: err };
				// q= cannot be combined with filters; reject rather than ignore.
				const dropped = ["level", "request_id", "service_id", "event"].filter(
					(n) => q.has(n),
				);
				if (dropped.length) {
					throw new HttpError(
						400,
						`q= is a free-text search and cannot be combined with structured filters (${dropped.join(", ")}). Use one or the other — structured filters run over the store index; q= runs over the raw payload.`,
					);
				}
				const rows = await sys.search({
					q: text,
					since,
					until,
					limit: Math.min(limit, 200),
				});
				if (rows === null) {
					return {
						rows: [],
						completeness,
						error: "search requires sys persistence: configure a syslog store",
					};
				}
				return { rows: scope(rows, tenant), completeness };
			}
			const rows = await sys.query({
				limit,
				level: q.get("level"),
				requestId: q.get("request_id"),
				serviceId: q.get("service_id"),
				event: q.get("event"),
				since,
				until,
			});
			return { rows: scope(rows, tenant), completeness };
		};
	}

	function routeApi(q) {
		const limit = _limit(q.get("limit"), 100, 1000);
		const status = q.get("status");
		// The status column is a 32-bit INTEGER.
		if (status !== null && status !== "") {
			const n = _int("status", status);
			if (n < -2147483648 || n > 2147483647) {
				throw unprocessable(
					"status must be between -2147483648 and 2147483647",
				);
			}
		}
		const text = q.get("q");
		if (text !== null && [...text].length > MAX_Q) {
			throw unprocessable(`q must be at most ${MAX_Q} characters`);
		}
		return async (ctx, tenant) => {
			if (text !== null) {
				throw new HttpError(
					400,
					"free-text q= not accepted on /api — use /search?streams=api (or /logs/sys?q= for syslog only)",
				);
			}
			const completeness = { api: ctx.source("api") };
			if (!ctx.streams) {
				return { rows: [], completeness, error: NOT_INITIALISED };
			}
			const rows = await ctx.streams.api.query({
				limit,
				method: q.get("method"),
				path: q.get("path"),
				requestId: q.get("request_id"),
				status: status === null || status === "" ? null : Number(status),
				since: _windowTS("since", q.get("since")),
				until: _windowTS("until", q.get("until")),
			});
			return { rows: scope(rows, tenant), completeness };
		};
	}

	function routeAudit(q) {
		const limit = _limit(q.get("limit"), 100, 1000);
		const offsetText = q.get("offset");
		const offset =
			offsetText === null || offsetText === "" ? 0 : _int("offset", offsetText);
		if (offset < 0) throw unprocessable("offset must be non-negative");
		const afterText = q.get("after");
		let after = null;
		if (afterText !== null && afterText !== "") {
			after = _int("after", afterText);
			if (after < 1) {
				throw unprocessable(
					"after must be >= 1 (monotonic_seq starts at 1; 0 is not a valid cursor)",
				);
			}
		}
		const since = _windowTS("since", q.get("since"));
		const until = _windowTS("until", q.get("until"));
		return async (ctx, tenant) => {
			const completeness = { audit: ctx.source("audit") };
			const s = ctx.store;
			if (!s) {
				return {
					rows: [],
					total: 0,
					limit,
					offset,
					next_after: null,
					completeness,
					error: NO_AUDIT_STORE,
				};
			}
			// A scoped caller's tenant replaces any ?tenant_id=.
			const filters = {
				requestId: q.get("request_id"),
				code: q.get("code"),
				domain: q.get("domain"),
				sourceNodeId: q.get("source_node_id"),
				tenantId: tenant ?? q.get("tenant_id"),
				actor: q.get("actor"),
				target: q.get("target"),
				since,
				until,
			};
			const rows = scope(
				await s.query({
					...filters,
					limit,
					offset,
					afterSeq: after ?? 0,
				}),
				tenant,
			);
			const total = await countOrNull(s, filters);
			// Rows are newest first, so next_after is the smallest seq.
			return {
				rows,
				total,
				limit,
				offset,
				next_after: rows.length ? rows.at(-1).monotonic_seq : null,
				completeness,
			};
		};
	}

	function routeCorrelate(q) {
		const rid = q.get("request_id");
		if (!rid) throw unprocessable("request_id is required");
		const limit = _limit(q.get("limit"), 100, 1000);
		return async (ctx, tenant) => {
			const s = ctx.store;
			const streams = ctx.streams;
			// Every stream is scoped, so a known request_id cannot reach another
			// tenant's rows.
			const audit = s
				? scope(
						await s.query({ limit, requestId: rid, tenantId: tenant }),
						tenant,
					)
				: [];
			const auditTotal = s
				? await countOrNull(s, { requestId: rid, tenantId: tenant })
				: null;
			const counts = { audit: audit.length };
			const totals = { audit: auditTotal };
			const truncated = {
				audit: auditTotal === null ? null : audit.length < auditTotal,
			};
			const out = {};
			for (const name of ["api", "sys"]) {
				if (!streams) {
					out[name] = [];
					counts[name] = 0;
					totals[name] = 0;
					truncated[name] = false;
					continue;
				}
				const fetched = await streams[name].query({ limit, requestId: rid });
				const rows = scope(fetched, tenant);
				out[name] = rows;
				counts[name] = rows.length;
				if (tenant === null) {
					totals[name] = await streams[name].countMatching({ requestId: rid });
					truncated[name] = counts[name] < totals[name];
				} else {
					// Stream counts cannot take a tenant, so a scoped caller's
					// totals count its own rows, as Python and Go do.
					totals[name] = rows.length;
					truncated[name] = false;
				}
			}
			const { api, sys } = out;
			return {
				request_id: rid,
				audit,
				api,
				sys,
				counts,
				totals,
				truncated,
				completeness: {
					audit: ctx.source("audit"),
					api: ctx.source("api"),
					sys: ctx.source("sys"),
				},
			};
		};
	}

	function routeSearch(q) {
		const text = _q(q.get("q"), { required: true });
		if (q.get("since") === null) throw unprocessable("since is required");
		const limit = _limit(q.get("limit"), 50, 200);
		return async (ctx, tenant) => {
			const raw = q.get("streams");
			const parsed = new Set(
				(raw ? raw.split(",") : ["sys"]).map((s) => s.trim()).filter(Boolean),
			);
			const unknown = [...parsed].filter((s) => !SEARCH_STREAMS.includes(s));
			if (unknown.length) {
				throw new HttpError(
					400,
					`streams=${_pyRepr([...parsed].sort())}: unknown stream(s) ${_pyRepr(unknown.sort())}. Valid: ${_pyRepr([...SEARCH_STREAMS].sort())}.`,
				);
			}
			if (!parsed.size) parsed.add("sys");
			const completeness = {};
			const emptyCounts = {};
			for (const s of parsed) {
				completeness[s] = ctx.source(s);
				emptyCounts[s] = 0;
			}
			const since = _windowTS("since", q.get("since")) ?? "";
			const until = _windowTS("until", q.get("until"));
			const fail = (error) => ({
				matches: [],
				counts: emptyCounts,
				completeness,
				error,
			});
			const guard = searchGuard(ctx, since);
			if (guard) return fail(guard);
			if (!ctx.streams) return fail(NOT_INITIALISED);

			const matches = [];
			const counts = {};
			const errors = {};
			const opts = { q: text, since, until, limit };
			// Fixed order: sys, api, audit.
			for (const stream of ["sys", "api", "audit"]) {
				if (!parsed.has(stream)) continue;
				if (stream === "audit") {
					const s = ctx.store;
					if (!s || typeof s.search !== "function") {
						errors.audit = "requires an audit store with a search method";
						counts.audit = 0;
						continue;
					}
					const rows = scope(
						await s.search({ ...opts, tenantId: tenant }),
						tenant,
					);
					counts.audit = rows.length;
					for (const row of rows) {
						matches.push({
							stream: "audit",
							request_id: row.request_id,
							ts: row.timestamp ? canonicalTimestamp(row.timestamp) : null,
							summary: row.code,
							row,
						});
					}
					continue;
				}
				let rows = await ctx.streams[stream].search(opts);
				if (rows === null) {
					errors[stream] =
						stream === "sys"
							? "requires sys persistence: configure a syslog store"
							: "requires api persistence: configure an api store";
					counts[stream] = 0;
					continue;
				}
				rows = scope(rows, tenant);
				counts[stream] = rows.length;
				for (const row of rows) {
					matches.push({
						stream,
						request_id: row.request_id ?? null,
						ts: row.timestamp ?? null,
						summary:
							stream === "sys"
								? (row.event ?? null)
								: `${row.method ?? ""} ${row.path ?? ""}`.trim(),
						row,
					});
				}
			}
			const out = { matches, counts, completeness };
			if (Object.keys(errors).length) out.errors = errors;
			return out;
		};
	}

	function routeTopology(q) {
		const since = _windowTS("since", q.get("since"));
		const until = _windowTS("until", q.get("until"));
		return async (ctx, tenant) => {
			const empty = { sources: [], nodes: 0, services: 0, tenants: 0 };
			const s = ctx.store;
			if (!s) return { ...empty, error: NO_AUDIT_STORE };
			if (typeof s.sources !== "function") {
				return {
					...empty,
					error: "store does not support topology aggregation",
				};
			}
			let sources = await s.sources({
				since: since ?? undefined,
				until: until ?? undefined,
			});
			if (tenant !== null) {
				sources = sources.filter((x) => x.tenant_id === tenant);
			}
			return {
				sources,
				nodes: new Set(sources.map((x) => x.source_node_id)).size,
				services: new Set(sources.map((x) => x.service_id)).size,
				tenants: new Set(sources.map((x) => x.tenant_id).filter(Boolean)).size,
			};
		};
	}

	function routeDoctor() {
		return async (ctx, tenant) => {
			const { st, store: s } = ctx;
			// A scoped caller gets its own rows' data, not the host's.
			const scoped = tenant !== null;
			const storeBlock = {
				kind: s && !scoped ? (s.constructor?.name ?? null) : null,
				reachable: false,
				degraded: s ? ctx.source("audit") === "store-degraded" : false,
				rows: null,
				last_insert_at: null,
				last_error: null,
			};
			if (s && typeof s.count === "function") {
				try {
					storeBlock.rows = scoped
						? await s.count({ tenantId: tenant })
						: await s.count();
					storeBlock.reachable = true;
				} catch (err) {
					storeBlock.last_error = checkFailed("store", err);
				}
			}

			let queueBlock = null;
			let transportBlock = null;
			if (!scoped) {
				const stats = engine.queueStats();
				queueBlock = stats
					? { ...stats, last_error: _errorType(stats.last_error) }
					: null;
				const own = st.streams;
				transportBlock = {
					stdout_active: own !== null,
					syslog_ring_depth: own ? own.sys.ring.length : 0,
					api_ring_depth: own ? own.api.ring.length : 0,
				};
			}

			const chainUnavailable = !!s && !_seals(s);
			let chainBlock = {
				verified: null,
				breaks: null,
				sealed_rows: null,
				last_verified_at: null,
				chain_unavailable: chainUnavailable,
			};
			const node = ctx.nodeId;
			// Rows read as stored, so detail numbers are the tokens that were
			// hashed: query() rows parse them with JSON.parse and would read
			// as breaks.
			const tail =
				typeof s?.chainTail === "function"
					? () => s.chainTail(node, 50)
					: typeof s?.chainRows === "function"
						? async () => (await s.chainRows(node)).slice(-50)
						: null;
			if (s && (node === null || tail === null)) {
				// A store that does not seal can never be verified.
				if (chainUnavailable) chainBlock.verified = false;
				chainBlock.reason =
					node === null
						? "no node id to check"
						: "the store has no chainTail or chainRows";
			} else if (s) {
				try {
					// By seq: a timestamp-ordered sample skips seqs after a clock
					// step back and reads as a break.
					const recent = await tail();
					storeBlock.reachable = true;
					const result = verifyChain(recent);
					const sealed = result.sealedRows;
					chainBlock = {
						verified: chainUnavailable ? false : sealed ? result.ok : null,
						breaks: chainUnavailable || !sealed ? null : result.ok ? 0 : 1,
						sealed_rows: sealed,
						first_break_at: result.firstBreakAt,
						reason: sealed ? result.reason : "no sealed rows in sample",
						last_verified_at: sealed ? canonicalTS() : null,
						chain_unavailable: chainUnavailable,
					};
					// The sample is this node's chain, which can hold other
					// tenants' rows: a scoped caller gets the verdict only.
					if (scoped && !result.ok) {
						chainBlock.first_break_at = null;
						chainBlock.reason = "chain break in this node's recent rows";
					}
				} catch (err) {
					chainBlock = {
						verified: null,
						breaks: null,
						sealed_rows: null,
						error: errorType(err),
						reason: checkFailed("chain", err),
						last_verified_at: null,
						chain_unavailable: chainUnavailable,
					};
				}
			}

			return {
				store: storeBlock,
				queue: queueBlock,
				transport: transportBlock,
				redactor: { active: !!st.serviceId },
				init: {
					service_id: scoped ? null : st.serviceId || null,
					node_id: scoped ? null : st.nodeId || null,
					// The host's own tenant is not a scoped caller's to read.
					tenant_id: scoped ? null : (st.tenantId ?? null),
					failure_strategy: st.failureStrategy,
					worker_pid: scoped ? null : process.pid,
				},
				chain: chainBlock,
			};
		};
	}
}

// sys and api rows carry tenant_id in the payload, not a column, so they
// are filtered here. A row without one is left out of a scoped read.
function scope(rows, tenant) {
	if (tenant === null) return rows;
	return rows.filter((r) => r?.tenant_id === tenant);
}

// Query parameters: the last value of a repeated one, as FastAPI reads it.
// The query parameters; a value read with a NUL in it is a 422, since a
// Postgres text value cannot hold one.
function _params(sp) {
	return {
		get: (name) => {
			const all = sp.getAll(name);
			const v = all.length ? all[all.length - 1] : null;
			if (v?.includes("\0")) {
				throw unprocessable(`${name} must not contain a NUL character`);
			}
			return v;
		},
		has: (name) => sp.has(name),
	};
}

function send(res, status, body) {
	const text = JSON.stringify(body, bigintReplacer);
	res.statusCode = status;
	res.setHeader("Content-Type", "application/json");
	res.setHeader("Content-Length", Buffer.byteLength(text, "utf8"));
	res.end(text);
}
