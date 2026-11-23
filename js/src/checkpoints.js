/**
 * Chain checkpoints (spec/chain-replication.md §9).
 *
 * A checkpoint records a node's latest sealed row: its seq and hash.
 * Published somewhere the store's operator cannot rewrite, it lets
 * `verifyChain` detect a chain cut short at the end, or re-sealed from
 * genesis:
 *
 *     await publishCheckpoints(store, new FileCheckpointSink("/mnt/cp.jsonl"));
 *     ...
 *     const checkpoints = await loadCheckpoints("/mnt/cp.jsonl");
 *     verifyChain(await store.allChainRows(), { checkpoints });
 *
 * The rows there must be the whole chain; pass `partial: true` to verify a
 * page or one node. With retention, checkpoints taken before a purge fail a
 * whole-chain verify; pass only the checkpoints taken since the latest purge
 * finished (see checkpointsSince).
 */
import { open, readFile } from "node:fs/promises";
import { canonicalTS } from "./canonical_ts.js";
import {
	canonicalJSON,
	compareCodePoints,
	JsonNumber,
	parseJson,
} from "./chain.js";

const _FIELDS = ["anchored_at", "hash", "monotonic_seq", "source_node_id"];
const _CANONICAL_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const _HEX64 = /^[0-9a-f]{64}$/;

// Passed by Checkpoint.parse, which checks only the types.
const _UNCHECKED = Symbol("unchecked");

// The longest unfinished last line FileCheckpointSink truncates. A
// checkpoint line is under 200 bytes plus the node id, so a longer tail is
// not one cut short, and the sink refuses to append rather than drop it.
const MAX_UNFINISHED_LINE = 4096;

/**
 * A node's latest sealed row at `anchored_at`. The constructor needs a
 * `hash` of 64 lowercase hex digits and an `anchored_at` in the canonical
 * form, YYYY-MM-DDTHH:MM:SS.ffffffZ, and throws TypeError otherwise.
 */
export class Checkpoint {
	constructor({ source_node_id, monotonic_seq, hash, anchored_at }, mode) {
		if (
			typeof source_node_id !== "string" ||
			typeof hash !== "string" ||
			typeof anchored_at !== "string" ||
			!Number.isSafeInteger(monotonic_seq) ||
			monotonic_seq < 0
		) {
			throw new TypeError(
				"Checkpoint: source_node_id, hash and anchored_at must be strings and monotonic_seq a non-negative integer",
			);
		}
		if (mode !== _UNCHECKED) {
			if (!_HEX64.test(hash)) {
				throw new TypeError(
					`Checkpoint of node ${JSON.stringify(source_node_id)} at seq ${monotonic_seq}: hash is not 64 lowercase hex digits`,
				);
			}
			if (!_isCanonical(anchored_at)) {
				throw new TypeError(
					`Checkpoint of node ${JSON.stringify(source_node_id)} at seq ${monotonic_seq}: anchored_at is not the canonical timestamp form: ${JSON.stringify(anchored_at)}`,
				);
			}
		}
		this.source_node_id = source_node_id;
		this.monotonic_seq = monotonic_seq;
		this.hash = hash;
		this.anchored_at = anchored_at;
		Object.freeze(this);
	}

	/**
	 * Parse one line of a checkpoint file: an object with exactly the four
	 * fields, each of its type. A repeated key keeps its last value. Unlike
	 * the constructor, the hash and anchored_at are not checked further.
	 * Throws TypeError.
	 */
	static parse(line) {
		const bad = () => new TypeError(`not a checkpoint: ${line.trim()}`);
		let v;
		try {
			v = parseJson(line);
		} catch {
			throw bad();
		}
		if (v === null || typeof v !== "object" || Array.isArray(v)) throw bad();
		const keys = Object.keys(v).sort();
		if (keys.length !== 4 || keys.some((k, i) => k !== _FIELDS[i])) throw bad();
		const seq = v.monotonic_seq;
		if (
			!(seq instanceof JsonNumber) ||
			!/^\d+$/.test(seq.token) ||
			!Number.isSafeInteger(Number(seq.token))
		) {
			throw bad();
		}
		try {
			return new Checkpoint(
				{ ...v, monotonic_seq: Number(seq.token) },
				_UNCHECKED,
			);
		} catch {
			throw bad();
		}
	}

	/**
	 * The checkpoint as one line of a checkpoint file, without the newline:
	 * the bytes Python's FileCheckpointSink writes (keys sorted, ", " and
	 * ": " separators, non-ASCII escaped).
	 */
	toLine() {
		const s = (x) => canonicalJSON(x);
		return `{"anchored_at": ${s(this.anchored_at)}, "hash": ${s(this.hash)}, "monotonic_seq": ${this.monotonic_seq}, "source_node_id": ${s(this.source_node_id)}}`;
	}

	toJSON() {
		return {
			source_node_id: this.source_node_id,
			monotonic_seq: this.monotonic_seq,
			hash: this.hash,
			anchored_at: this.anchored_at,
		};
	}
}

/**
 * A checkpoint file whose last line is cut short: no newline after it and
 * not valid JSON, as a crash in the middle of an append leaves it.
 * `checkpoints` holds the whole lines before it; a caller that accepts the
 * file without its last line takes them from here.
 */
export class PartialLastLineError extends Error {
	constructor(path, line, checkpoints) {
		super(
			`checkpoint file ${path}: line ${line}, the last, is cut short (${checkpoints.length} whole checkpoints before it)`,
		);
		this.name = "PartialLastLineError";
		this.path = path;
		this.line = line;
		this.checkpoints = checkpoints;
	}
}

function _isJson(text) {
	try {
		parseJson(text);
		return true;
	} catch {
		return false;
	}
}

// Writes a sys line to stderr, as the engine does. Imported lazily so this
// module does not load the engine.
async function _sysLog(level, event, fields) {
	const { defaultEngine } = await import("./index.js");
	defaultEngine._drainerSysLog(level, event, fields);
}

/**
 * Appends one JSON line per checkpoint to `path` and fsyncs it.
 *
 * If the file ends in an unfinished line, as a crash mid-append leaves it,
 * that line is dropped before the append, with a
 * `checkpoint_unfinished_line_dropped` warning on stderr giving the path and
 * the bytes dropped; a complete last line without a newline gets one. An
 * unfinished last line longer than 4 KiB is not a checkpoint line cut
 * short: the publish throws and leaves the file as it is. The file is
 * opened for reading and writing and may be truncated, so a path that only
 * accepts appends does not work. One publisher per file: concurrent
 * publishes to the same file are not supported.
 */
export class FileCheckpointSink {
	constructor(path) {
		this.path = path;
	}

	async publish(checkpoints) {
		if (!checkpoints.length) return;
		const lines = checkpoints.map((cp) => `${_asCheckpoint(cp).toLine()}\n`);
		const f = await open(this.path, "a+");
		let failure = null;
		try {
			const lead = await this._endLastLine(f);
			await f.appendFile(lead + lines.join(""));
			await f.sync();
		} catch (err) {
			failure = err;
		}
		// A failed close after a failed write reports the write.
		try {
			await f.close();
		} catch (err) {
			failure ??= err;
		}
		if (failure) throw failure;
	}

	// Make the file end at a line break, as loadCheckpoints reads it:
	// truncate an unfinished last line (not valid JSON), or return the
	// newline a complete one lacks.
	async _endLastLine(f) {
		const end = (await f.stat()).size;
		let start = end;
		const chunk = Buffer.alloc(4096);
		while (start > 0) {
			const n = Math.min(chunk.length, start);
			const from = start - n;
			await f.read(chunk, 0, n, from);
			const i = chunk.subarray(0, n).lastIndexOf(0x0a);
			if (i >= 0) {
				start = from + i + 1;
				break;
			}
			start = from;
		}
		if (start === end) return "";
		const last = Buffer.alloc(end - start);
		await f.read(last, 0, last.length, start);
		if (_isJson(last.toString("utf8"))) return "\n";
		if (last.length > MAX_UNFINISHED_LINE) {
			throw new Error(
				`checkpoint file ${this.path}: the last line has no newline, is not JSON and is ${last.length} bytes, longer than a checkpoint line; not truncating it`,
			);
		}
		await _sysLog("warn", "checkpoint_unfinished_line_dropped", {
			path: String(this.path),
			bytes_dropped: last.length,
		});
		await f.truncate(start);
		return "";
	}
}

// `scheme://host[:port]/path`, without userinfo, query or fragment.
function _redactURL(u) {
	return `${u.protocol}//${u.host}${u.pathname}`;
}

/**
 * POSTs the checkpoints as one JSON array to `url` with Node's fetch.
 * Userinfo in the url (`https://user:pass@host/path`) is sent as Basic auth
 * and left out of the request url. Anything but a 2xx response is an error,
 * and redirects are not followed. Errors name the url without userinfo or
 * query; a failed request's error has the fetch error as its `cause`.
 */
export class HttpCheckpointSink {
	constructor(url, { timeoutMs = 10_000 } = {}) {
		let u;
		try {
			u = new URL(url);
		} catch {
			throw new TypeError("checkpoint sink url is not a valid url");
		}
		if (u.protocol !== "http:" && u.protocol !== "https:") {
			throw new TypeError(
				`checkpoint sink url must be http or https: ${_redactURL(u)}`,
			);
		}
		this._where = _redactURL(u);
		this._headers = { "Content-Type": "application/json" };
		if (u.username || u.password) {
			const cred = `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`;
			this._headers.Authorization = `Basic ${Buffer.from(cred).toString("base64")}`;
			u.username = "";
			u.password = "";
		}
		this._url = u.href;
		this._timeoutMs = timeoutMs;
	}

	async publish(checkpoints) {
		if (!checkpoints.length) return;
		const body = JSON.stringify(checkpoints.map((cp) => _asCheckpoint(cp)));
		let res;
		try {
			res = await fetch(this._url, {
				method: "POST",
				headers: this._headers,
				body,
				redirect: "manual",
				signal: AbortSignal.timeout(this._timeoutMs),
			});
		} catch (err) {
			// The cause names the failure (ECONNREFUSED, a timeout), not the url.
			const why = err?.cause?.code ?? err?.name ?? "Error";
			throw new Error(`checkpoint sink ${this._where}: ${why}`, {
				cause: err,
			});
		}
		await res.body?.cancel().catch(() => {});
		if (res.status < 200 || res.status >= 300) {
			throw new Error(`checkpoint sink ${this._where}: HTTP ${res.status}`);
		}
	}
}

function _asCheckpoint(cp) {
	return cp instanceof Checkpoint ? cp : new Checkpoint(cp);
}

/**
 * One checkpoint per node with a sealed row, ordered by node id, from
 * `store.chainTips()`: each node's sealed row with the highest seq. For a
 * node given more than once the tip with the highest seq is kept (the first
 * of them when two share it, which verifyChain reports as a duplicate seq),
 * and a tip with no hash is left out.
 */
export async function takeCheckpoints(store) {
	const tips = await store.chainTips();
	const anchoredAt = canonicalTS();
	const latest = new Map();
	for (const tip of tips) {
		if (!tip.hash) continue;
		// A pg BIGINT can come back as a string.
		const seq = Number(tip.monotonic_seq);
		const kept = latest.get(tip.source_node_id);
		if (!kept || seq > kept.seq) {
			latest.set(tip.source_node_id, { seq, hash: tip.hash });
		}
	}
	return [...latest.keys()].sort(compareCodePoints).map((node) => {
		const tip = latest.get(node);
		return new Checkpoint({
			source_node_id: node,
			monotonic_seq: tip.seq,
			hash: tip.hash,
			anchored_at: anchoredAt,
		});
	});
}

/**
 * Take checkpoints of `store`, publish them to `sink` and return them. When
 * reading the tips fails nothing is published. A store with no sealed row
 * publishes nothing and logs a `checkpoint_no_sealed_rows` warning on
 * stderr.
 */
export async function publishCheckpoints(store, sink) {
	const checkpoints = await takeCheckpoints(store);
	if (!checkpoints.length) {
		await _sysLog("warn", "checkpoint_no_sealed_rows", {
			reason: "the store has no sealed rows, so there is nothing to checkpoint",
		});
	}
	await sink.publish(checkpoints);
	return checkpoints;
}

/**
 * Read back a file written by FileCheckpointSink, or by the Python, Go or
 * Rust one. Blank lines are skipped. A line that is not a checkpoint throws
 * TypeError naming the path and line. An unfinished last line (no trailing
 * newline, not valid JSON), as a crash mid-append leaves it, throws
 * PartialLastLineError, which carries the checkpoints read before it.
 */
export async function loadCheckpoints(path) {
	const text = await readFile(path, "utf8");
	const lines = text.split("\n");
	// The text after the last newline; empty when the file ends with one.
	const last = lines.pop();
	const parse = (line, number) => {
		try {
			return Checkpoint.parse(line);
		} catch (err) {
			throw new TypeError(
				`checkpoint file ${path}, line ${number}: ${err.message}`,
			);
		}
	};
	const out = [];
	lines.forEach((line, i) => {
		if (line.trim()) out.push(parse(line, i + 1));
	});
	if (last.trim()) {
		const number = lines.length + 1;
		if (!_isJson(last)) throw new PartialLastLineError(path, number, out);
		out.push(parse(last, number));
	}
	return out;
}

/**
 * The checkpoints anchored at or after `cutoff` (a Date or a canonical
 * timestamp), in their order. Throws TypeError for an `anchored_at` not in
 * the canonical form.
 *
 * For a whole-chain verify of a store with retention, pass the time the
 * latest purge finished: a checkpoint taken before it can fall among the
 * rows it removed, or belong to a node with no rows left, and fails the
 * verify. The retention period alone is not a safe cutoff, since a node's
 * last checkpoint can be taken just before its rows are purged.
 */
export function checkpointsSince(checkpoints, cutoff) {
	const at = cutoff instanceof Date ? canonicalTS(cutoff) : cutoff;
	if (!_isCanonical(at)) {
		throw new TypeError(
			`checkpointsSince: cutoff is not a Date or canonical timestamp: ${JSON.stringify(at)}`,
		);
	}
	const out = [];
	for (const cp of checkpoints) {
		if (!_isCanonical(cp.anchored_at)) {
			throw new TypeError(
				`checkpoint of node '${cp.source_node_id}' at seq ${cp.monotonic_seq}: not the canonical timestamp form: ${JSON.stringify(cp.anchored_at)}`,
			);
		}
		if (cp.anchored_at >= at) out.push(cp);
	}
	return out;
}

// Whether `s` is YYYY-MM-DDTHH:MM:SS.ffffffZ and a real date and time.
function _isCanonical(s) {
	if (typeof s !== "string" || !_CANONICAL_TS.test(s)) return false;
	const t = new Date(`${s.slice(0, 23)}Z`);
	return (
		!Number.isNaN(t.getTime()) &&
		t.toISOString().slice(0, 19) === s.slice(0, 19)
	);
}
