#!/usr/bin/env node
// Writes spec/js-sealed-form2.json and spec/js-sealed-stdout.jsonl from the
// JS SDK's own engine and PostgresStore, not by hand. Python and Go verify
// both files; js/test/chain.test.mjs checks them too.
//
//   cd js && npm install
//   FASTEN_TEST_POSTGRES_DSN=postgresql://... node ../scripts/gen_js_vectors.mjs
//
// The salts are random, so each run gives new files; commit them and the
// tests that read them move together.
//
// js-sealed-stdout.jsonl is every audit line the engine wrote, in order:
// for each row the unsealed line at emit, then the sealed line after the
// insert (spec §8). js-sealed-form2.json is the rows as the store holds
// them: the sealed lines without "shape", with the row redacted after
// sealing as the store holds it (detail and salt null). The row with an
// unpaired surrogate in its detail is on a node of its own, node-js-u16,
// so a reader that cannot keep one still verifies node-js.
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Engine, parseJson, register, verifyChain } from "../js/src/index.js";
import { PostgresStore } from "../js/src/store/postgres.js";

const dsn = process.env.FASTEN_TEST_POSTGRES_DSN;
if (!dsn) {
	console.error("set FASTEN_TEST_POSTGRES_DSN");
	process.exit(2);
}
const root = new URL("../", import.meta.url);
const table = `js_vector_${randomUUID().replace(/-/g, "").slice(0, 8)}`;

register("vector", {
	VECTOR_EVENT: {
		domain: "vector",
		action: "write",
		severity: "info",
		retentionClass: "long",
	},
});

// Each value's String(n) differs from what Python's repr writes for it.
const NUMBERS = {
	tiny: 5e-5,
	micro: 1e-6,
	e16: 1e16,
	p60: 2 ** 60,
	e21: 1e21,
	neg0: -0,
	sum: 0.1 + 0.2,
	big: 2n ** 70n,
	whole: 75,
	half: 75.5,
	neg: -1.5,
};
const TEXT = "opé\x7f\u{1f600}";

const store = new PostgresStore(dsn, { table });
const lines = [];
const write = process.stdout.write;
process.stdout.write = (chunk, ...rest) => {
	if (typeof chunk === "string" && chunk.startsWith('{"shape":"audit"')) {
		lines.push(...chunk.split("\n").filter(Boolean));
		rest.find((x) => typeof x === "function")?.();
		return true;
	}
	return write.call(process.stdout, chunk, ...rest);
};

const engine = (nodeId) => {
	const e = new Engine();
	e.init({
		serviceId: "gateway",
		nodeId,
		tenantId: `ténant-\x7f-\u{1f600}`,
		auditStore: store,
		auditStoreFailureStrategy: "raise",
	});
	return e;
};

let redactedId;
try {
	const main = engine("node-js");
	const emit = (e, target, detail, actor = "system") =>
		e.emit({ code: "VECTOR_EVENT", target, actor, detail });
	await emit(main, "sensor/0", NUMBERS);
	await emit(
		main,
		`sensor/${TEXT}`,
		{
			"\u{1f600}": 1,
			"": 2,
			del: "a\x7fb",
			text: "café ✓ 日本",
		},
		TEXT,
	);
	await emit(main, "sensor/2", {
		nested: { list: [1, 2.5, { x: 0.0001 }], none: null, ok: true },
		ints: [2n ** 64n, -(2n ** 53n) - 1n, -3],
	});
	redactedId = (
		await emit(main, "sensor/3", { note: "to be redacted", n: 1.25 })
	).id;
	await emit(main, "sensor/4", { count: 7 });
	await main.resetForTests();

	const u16 = engine("node-js-u16");
	await emit(u16, "file/0", { name: "\udcff.txt", tail: "a\udfffb" });
	await u16.resetForTests();

	await store.redactRows({ ids: [redactedId] });
} finally {
	process.stdout.write = write;
}

// The sealed lines, as the store holds the rows.
const rows = [];
for (const line of lines) {
	const row = parseJson(line);
	if (!row.hash) continue;
	let text = line.replace(/^\{"shape":"audit",/, "{");
	if (row.id === redactedId) {
		text = text
			.replace(/"detail_salt":"[0-9a-f]{64}"/, '"detail_salt":null')
			.replace(/,"detail":.*\}$/, ',"detail":null}');
	}
	rows.push(text);
}

const stored = [
	...(await store.chainRows("node-js")),
	...(await store.chainRows("node-js-u16")),
];
const mine = rows.map((t) => parseJson(t));
for (const [i, r] of stored.entries()) {
	const m = mine[i];
	if (r.id !== m.id || r.hash !== m.hash || (r.detail === null) !== (m.detail === null)) {
		throw new Error(`row ${i}: the store holds ${r.id}, the vector ${m.id}`);
	}
}
for (const [label, input] of [
	["rows", rows],
	["stdout", lines],
	["store", stored],
]) {
	const res = verifyChain(input);
	if (!res.ok || res.sealedRows !== mine.length) {
		throw new Error(`${label}: ${res.reason ?? `${res.sealedRows} sealed`}`);
	}
}

await store._pool.query(`DROP TABLE ${table}`);
await store.close();

writeFileSync(
	new URL("spec/js-sealed-form2.json", root),
	`[\n${rows.join(",\n")}\n]\n`,
);
writeFileSync(
	new URL("spec/js-sealed-stdout.jsonl", root),
	`${lines.join("\n")}\n`,
);
console.log(`${rows.length} rows, ${lines.length} stdout lines`);
