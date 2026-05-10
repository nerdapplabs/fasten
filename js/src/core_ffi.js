// core_ffi.js — thin JS wrapper over libfasten_store_core via koffi.
//
// Uses buffer-based ABI variants (fasten_*_buf) — caller-supplied Buffers,
// no heap allocation on the Rust side, no char** ownership issues with koffi.
//
// Set FASTEN_CORE_LIB to the full path of the .so/.dylib/.dll, or ensure the
// default relative path (../../store-core/target/release/) is populated
// (run `cargo build --release --features all` in store-core/).

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import koffi from "koffi";

const _dir = dirname(fileURLToPath(import.meta.url));

function _findLib() {
	const env = process.env.FASTEN_CORE_LIB;
	if (env && existsSync(env)) return env;
	const ext =
		process.platform === "darwin"
			? ".dylib"
			: process.platform === "win32"
				? ".dll"
				: ".so";
	const name = `libfasten_store_core${ext}`;
	for (const base of [
		join(_dir, "../../store-core/target/release"),
		join(process.cwd(), "store-core/target/release"),
	]) {
		const p = join(base, name);
		if (existsSync(p)) return p;
	}
	throw new Error(
		"fasten: libfasten_store_core not found. " +
			"Build: cd store-core && cargo build --release --features all. " +
			"Or set FASTEN_CORE_LIB to the library path.",
	);
}

const _lib = koffi.load(_findLib());

// Buffer-based functions — uint8_t* params work cleanly with Node.js Buffers.
// Return convention:
//   fasten_redact_buf / fasten_redact_full_buf / fasten_meta_of_buf:
//     >= 0 → bytes written; < 0 → -(FastenErrorCode), error in _ERR_BUF
//   fasten_register_codes_buf:
//     0 → OK; > 0 → FastenErrorCode, error in _ERR_BUF
const _redactBuf = _lib.func(
	"int32_t fasten_redact_buf(string in_json, uint8_t *out_buf, uint32_t buf_len, uint8_t *out_err_buf, uint32_t err_buf_len)",
);
const _redactFullBuf = _lib.func(
	"int32_t fasten_redact_full_buf(string in_json, string extra_keys_json, string replacement, string extra_value_patterns_json, uint8_t *out_buf, uint32_t buf_len, uint8_t *out_err_buf, uint32_t err_buf_len)",
);
const _registerBuf = _lib.func(
	"int32_t fasten_register_codes_buf(string domain, string codes_json, uint8_t *out_err_buf, uint32_t err_buf_len)",
);
const _metaOfBuf = _lib.func(
	"int32_t fasten_meta_of_buf(string code, uint8_t *out_buf, uint32_t buf_len, uint8_t *out_err_buf, uint32_t err_buf_len)",
);
const _regClear = _lib.func("void fasten_registry_clear()");

// Pre-allocated reusable buffers. Safe because Node.js/V8 is single-threaded.
const _OUT_BUF = Buffer.alloc(1 * 1024 * 1024); // 1 MB — ample for any JSON response
const _ERR_BUF = Buffer.alloc(4096);

function _readErr() {
	const nul = _ERR_BUF.indexOf(0);
	return nul > 0 ? _ERR_BUF.toString("utf8", 0, nul) : null;
}

export function coreRedact(inJson) {
	_ERR_BUF[0] = 0;
	const n = _redactBuf(
		inJson,
		_OUT_BUF,
		_OUT_BUF.length,
		_ERR_BUF,
		_ERR_BUF.length,
	);
	if (n < 0) throw new Error(_readErr() ?? "fasten_redact failed");
	return _OUT_BUF.toString("utf8", 0, n);
}

export function coreRedactFull(inJson, extraKeysJson, replacement) {
	_ERR_BUF[0] = 0;
	const n = _redactFullBuf(
		inJson,
		extraKeysJson ?? "[]",
		replacement ?? "",
		"[]",
		_OUT_BUF,
		_OUT_BUF.length,
		_ERR_BUF,
		_ERR_BUF.length,
	);
	if (n < 0) throw new Error(_readErr() ?? "fasten_redact_full failed");
	return _OUT_BUF.toString("utf8", 0, n);
}

export function coreRegisterCodes(domain, codesJson) {
	_ERR_BUF[0] = 0;
	const rc = _registerBuf(domain, codesJson, _ERR_BUF, _ERR_BUF.length);
	if (rc !== 0) {
		const e = new Error(_readErr() ?? "fasten_register_codes failed");
		e.rustCode = rc;
		throw e;
	}
}

export function coreMetaOf(code) {
	_ERR_BUF[0] = 0;
	const n = _metaOfBuf(
		code,
		_OUT_BUF,
		_OUT_BUF.length,
		_ERR_BUF,
		_ERR_BUF.length,
	);
	if (n <= 0) return null; // not found (0) or error (< 0)
	return _OUT_BUF.toString("utf8", 0, n);
}

export function coreRegistryClear() {
	_regClear();
}
