// @ts-check
/**
 * Replication ingest shared by the bundled stores (spec §4): verify a batch
 * of rows sealed on other nodes, check it against what the store holds, and
 * store the verified prefix. The same steps as Python's store/repo.py and
 * Go's ingest.go.
 */
import {
	ChainError,
	compareCodePoints,
	toChainRow,
	verifyChain,
} from "./chain.js";

/**
 * @typedef {{ inserted: number, rejectedFromSeq: number | null, reason: string | null }} IngestResult
 * @typedef {ReturnType<typeof toChainRow>} ChainRow
 */

/**
 * The batch as chain rows. Throws ChainError naming the index of a row it
 * cannot read.
 * @param {Iterable<unknown>} rows
 * @returns {ChainRow[]}
 */
export function readBatch(rows) {
	return [...rows].map((r, i) => {
		try {
			return toChainRow(/** @type {any} */ (r));
		} catch (err) {
			throw new ChainError(`rows[${i}]: ${err.message}`);
		}
	});
}

/**
 * The longest verified run of the batch from the chain start: its sealed
 * rows below the first break, sorted by seq, each identical copy once.
 * Unsealed rows are left out.
 * @param {ChainRow[]} rows
 */
export function verifiedPrefix(rows) {
	const sorted = [...rows].sort((a, b) => a.monotonic_seq - b.monotonic_seq);
	const res = verifyChain(sorted);
	const breakAt = res.ok ? null : res.firstBreakAt;
	const seen = new Set();
	const prefix = [];
	for (const r of sorted) {
		if (!r.hash || (breakAt !== null && r.monotonic_seq >= breakAt)) continue;
		const key = JSON.stringify([r.id, r.source_node_id, r.hash]);
		if (seen.has(key)) continue;
		seen.add(key);
		prefix.push(r);
	}
	return { prefix, rejectedFromSeq: breakAt, reason: res.reason };
}

/**
 * The unsealed rows verifiedPrefix left out without a break: those below
 * the batch's first break, if any.
 * @param {ChainRow[]} rows
 * @param {number | null} rejectedFromSeq
 */
export function skippedUnsealed(rows, rejectedFromSeq) {
	return rows.filter(
		(r) =>
			!r.hash &&
			(rejectedFromSeq === null || r.monotonic_seq < rejectedFromSeq),
	);
}

/**
 * The first row of a verified prefix that disagrees with what the store
 * holds (spec §4), as [seq, reason], or null. It yields each lookup it
 * needs and is resumed with the answer, so one copy serves a synchronous
 * store and an asynchronous one (see conflictSync and conflictAsync):
 *
 * - ["byId", id]: the stored row's hash, or null;
 * - ["atSeq", node, seq]: the stored { id, hash, prev_hash }, or null;
 * - ["sealedBelow", node, seq]: whether a sealed row is stored below seq.
 *
 * @param {ChainRow[]} prefix
 * @param {ChainRow[]} unsealed
 * @returns {Generator<any[], [number, string] | null, any>}
 */
function* _conflict(prefix, unsealed) {
	// The stored neighbours are checked even when the batch holds one too:
	// the batch neighbour may be cut by a later break, and if both are kept
	// they must agree anyway.
	const ordered = [...prefix, ...unsealed].sort(
		(a, b) =>
			a.monotonic_seq - b.monotonic_seq ||
			compareCodePoints(a.source_node_id, b.source_node_id),
	);
	const seen = new Map();
	for (const row of ordered) {
		const node = row.source_node_id;
		const seq = row.monotonic_seq;
		if (!row.hash) {
			if (yield ["sealedBelow", node, seq]) {
				return [seq, `row ${row.id}: no hash after the node's chain started`];
			}
			continue;
		}
		// id is unique, so the store could keep only one row with it.
		const first = seen.get(row.id);
		if (first) {
			return [
				seq,
				`row ${row.id}: also in this batch at seq ${first.monotonic_seq} on node '${first.source_node_id}'`,
			];
		}
		seen.set(row.id, row);
		const held = yield ["byId", row.id];
		if (held !== null) {
			if (held !== row.hash) {
				return [seq, `row ${row.id}: differs from the stored row with that id`];
			}
			continue;
		}
		const other = yield ["atSeq", node, seq];
		if (other) {
			return [
				seq,
				`row ${row.id}: seq ${seq} on node '${node}' is stored as row ${other.id}`,
			];
		}
		// After an unsealed row the store links to "genesis" (spec §2).
		const before = yield ["atSeq", node, seq - 1];
		if (before && row.prev_hash !== (before.hash || "genesis")) {
			return [
				seq,
				`row ${row.id}: prev_hash does not match stored row ${before.id}`,
			];
		}
		const after = yield ["atSeq", node, seq + 1];
		if (after && after.prev_hash !== row.hash) {
			return [seq, `row ${row.id}: stored row ${after.id} does not link to it`];
		}
	}
	return null;
}

/**
 * _conflict with synchronous lookups.
 * @param {ChainRow[]} prefix
 * @param {ChainRow[]} unsealed
 * @param {Record<string, (...args: any[]) => any>} look
 */
export function conflictSync(prefix, unsealed, look) {
	const gen = _conflict(prefix, unsealed);
	let step = gen.next();
	while (!step.done) {
		const [name, ...args] = step.value;
		step = gen.next(look[name](...args));
	}
	return step.value;
}

/**
 * _conflict with lookups that may return promises.
 * @param {ChainRow[]} prefix
 * @param {ChainRow[]} unsealed
 * @param {Record<string, (...args: any[]) => any>} look
 */
export async function conflictAsync(prefix, unsealed, look) {
	const gen = _conflict(prefix, unsealed);
	let step = gen.next();
	while (!step.done) {
		const [name, ...args] = step.value;
		step = gen.next(await look[name](...args));
	}
	return step.value;
}

/**
 * The prefix shortened to the rows before a stored conflict.
 * @param {{ prefix: ChainRow[], rejectedFromSeq: number | null, reason: string | null }} v
 * @param {[number, string] | null} conflict
 */
export function cutAtConflict(v, conflict) {
	if (!conflict) return v;
	const [seq, reason] = conflict;
	return {
		prefix: v.prefix.filter((r) => r.monotonic_seq < seq),
		rejectedFromSeq: seq,
		reason,
	};
}

/**
 * Another writer stored a row with this id after the stored-row checks ran,
 * so the insert was skipped. The ingest checks again.
 */
export class StoredMeanwhile extends Error {
	/** @param {string} id */
	constructor(id) {
		super(`row ${id}: stored by another writer meanwhile`);
		this.name = "StoredMeanwhile";
	}
}

/**
 * Run `ingest` on the rows before the lowest-seq one whose source_node_id
 * is `localNodeId`, and report that row as the break unless `ingest` finds
 * an earlier one. A node's own rows come from its emit path, never from
 * replication. Other nodes' rows from that seq on are left for the sender
 * to resend. An empty `localNodeId` skips the check.
 * @param {(rows: ChainRow[]) => Promise<IngestResult>} ingest
 * @param {ChainRow[]} rows
 * @param {string | undefined | null} localNodeId
 * @returns {Promise<IngestResult>}
 */
export async function ingestWithoutLocalNode(ingest, rows, localNodeId) {
	let first = null;
	for (const r of rows) {
		if (
			localNodeId &&
			r.source_node_id === localNodeId &&
			(first === null || r.monotonic_seq < first.monotonic_seq)
		) {
			first = r;
		}
	}
	if (!first) return ingest(rows);
	const seq = first.monotonic_seq;
	const result = await ingest(rows.filter((r) => r.monotonic_seq < seq));
	if (result.rejectedFromSeq !== null) return result;
	return {
		...result,
		rejectedFromSeq: seq,
		reason: `row ${first.id}: source_node_id '${localNodeId}' is this node`,
	};
}
