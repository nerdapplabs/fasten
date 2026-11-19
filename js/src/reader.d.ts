// Types for fasten-sdk/reader.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuditRepository, Engine, StreamStore } from "./index.js";

/**
 * How the reader authenticates. Required: a shared bearer token, a verify
 * function, or "none" when something in front of the reader authenticates
 * every request.
 */
export type ReaderAuth =
	| { bearer: string }
	| { verify: (req: IncomingMessage) => boolean | Promise<boolean> }
	| "none";

export interface ReaderOptions {
	auth: ReaderAuth;
	/** The engine to read. Defaults to the default engine. */
	engine?: Engine;
	/**
	 * Audit store to read; defaults to the engine's. /search on audit needs
	 * search(), /topology sources(), and the doctor uses chainTail().
	 */
	store?: AuditRepository | null;
	/** Stream stores to read instead of the engine's rings and stores. */
	streams?: { api?: StreamStore | null; sys?: StreamStore | null };
	/**
	 * The caller's tenant. Every route is then limited to it; null or ""
	 * is a 401.
	 */
	tenantScope?: (
		req: IncomingMessage,
	) => string | null | undefined | Promise<string | null | undefined>;
	/** Refuse to build without tenantScope. */
	enforceTenantIsolation?: boolean;
	/** Defaults to the engine's searchEnabled. */
	searchEnabled?: boolean;
	/** Node whose chain the doctor checks. Defaults to the engine's. */
	nodeId?: string;
	/** Path prefix to strip, e.g. "/api/v1/logs". */
	prefix?: string;
}

export type ReaderHandler = (
	req: IncomingMessage,
	res: ServerResponse,
	next?: (err?: unknown) => unknown,
) => Promise<unknown>;

/**
 * The reader: GET /audit, /audit/doctor, /correlate, /search, /sys, /api
 * and /topology. Throws when auth is missing or not one of the forms above.
 */
export function reader(opts: ReaderOptions): ReaderHandler;

/**
 * `{ bearer }` from the token in `tokenEnv` (default FASTEN_READER_TOKEN).
 * Throws when it is unset or empty.
 */
export function requireBearer(tokenEnv?: string): { bearer: string };
