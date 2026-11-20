// @ts-check
// Lost connections on node-postgres, for the Postgres stores.
import { errorType, sysLog } from "../audit_queue.js";

/**
 * Whether `err` means the connection is gone, so a new one can help: a
 * socket error, a client pg has closed, or a SQLSTATE of class 08
 * (connection exception) or 57 (operator intervention, such as a server
 * shutdown or pg_terminate_backend). The rule of the Python stores.
 * @param {any} err
 */
export function connectionLost(err) {
	const code = err?.code;
	// pg's DatabaseError, an answer from the server.
	if (typeof err?.severity === "string" && typeof code === "string") {
		return code.startsWith("08") || code.startsWith("57");
	}
	if (typeof err?.syscall === "string") return true;
	return /^Connection terminated|is not queryable/.test(err?.message ?? "");
}

/**
 * Run fn() and, while it fails on a lost connection, again, as the Python
 * stores reconnect and retry. A client that failed is dropped from the
 * pool, but the pool's other idle clients may be dead too, so fn() runs
 * again at most once per client idle at the first failure, plus once on a
 * new connection. Use it only where running fn() again is safe. An error
 * `final` accepts is thrown as it is.
 * @template T
 * @param {{ idleCount?: number }} pool
 * @param {() => Promise<T>} fn
 * @param {(err: any) => boolean} [final]
 * @returns {Promise<T>}
 */
export async function retryLost(pool, fn, final = () => false) {
	let left = -1;
	for (;;) {
		try {
			return await fn();
		} catch (err) {
			if (final(err) || !connectionLost(err)) throw err;
			if (left < 0) left = (Number(pool.idleCount) || 0) + 1;
			if (left-- === 0) throw err;
		}
	}
}

const _ignore = () => {};

/**
 * A client from the pool for a transaction. pg listens for errors only on
 * idle clients, so while this one is out an error between its queries (a
 * dropped connection) would end the process; here it is left to the next
 * query, which fails. Give it back with `release`.
 * @param {any} pool
 */
export async function checkout(pool) {
	const client = await pool.connect();
	client.on("error", _ignore);
	return client;
}

/**
 * Give back a client from `checkout`. With `err` the pool drops it.
 * @param {any} client
 * @param {unknown} [err]
 */
export function release(client, err) {
	client.removeListener("error", _ignore);
	client.release(err);
}

// An idle client lost: logged by error type only, since a driver message
// can name the host.
const _idleLost = (/** @type {unknown} */ err) =>
	sysLog("debug", "pg_idle_connection_lost", { error_type: errorType(err) });

/**
 * Listen for errors on the pool's idle clients. pg drops such a client
 * itself; without a listener the error would be thrown and end the
 * process. Each is logged at debug level by error type.
 * @template {{ on: Function }} P
 * @param {P} pool
 * @returns {P}
 */
export function watchPool(pool) {
	pool.on("error", _idleLost);
	return pool;
}
