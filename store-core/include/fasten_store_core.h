/**
 * fasten_store_core.h — C ABI for the shared fasten audit-store library.
 *
 * Supported platforms
 * -------------------
 * Linux   x86_64, aarch64  (.so)
 * macOS   x86_64, arm64    (.dylib)
 * Windows x86_64           (.dll)
 *
 * Backends
 * --------
 * "sqlite"   — SQLite 3 (bundled; no system dep required)
 * "postgres" — PostgreSQL 15+ via pure-Rust wire protocol (no libpq)
 *
 * Ownership rules
 * ---------------
 * 1. A handle returned by fasten_store_open() is owned by the caller.
 *    Release it with fasten_store_close().
 * 2. Error strings written into *out_err are heap-allocated by the library.
 *    The caller must free them with fasten_store_free_str().
 * 3. The library never retains pointers passed by the caller after the
 *    function returns.
 *
 * Thread safety
 * -------------
 * A single FastenStore handle may be shared across threads. All operations
 * are serialised internally via a per-handle Mutex.
 */

#ifndef FASTEN_STORE_CORE_H
#define FASTEN_STORE_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handle ─────────────────────────────────────────────────────────── */

/**
 * Opaque audit-store handle. Do not inspect or allocate directly.
 * Obtain one via fasten_store_open(); release via fasten_store_close().
 */
typedef struct FastenStore FastenStore;

/* ── Lifecycle ─────────────────────────────────────────────────────────────── */

/**
 * Open an audit store.
 *
 * @param backend  "sqlite" or "postgres" (NUL-terminated UTF-8).
 * @param connstr  SQLite path (or ":memory:") / PostgreSQL DSN.
 *                 PostgreSQL DSN examples:
 *                   "host=db.prod user=audit dbname=audit sslmode=require"
 *                   "postgresql://audit:pass@db.prod/audit?sslmode=require"
 *                 Pass application_name=fasten_store_core for visibility in
 *                 pg_stat_activity.
 * @param table    Plain name ("audit_log") or schema-qualified
 *                 ("audit.audit_log"). Both parts must match
 *                 [A-Za-z_][A-Za-z0-9_]*.
 *                 The schema and table are auto-created if absent.
 * @param out_err  On failure: set to a heap-allocated error string (free with
 *                 fasten_store_free_str). May be NULL if not needed.
 *
 * @return  Non-null handle on success; NULL on failure (out_err set).
 */
FastenStore* fasten_store_open(
    const char* backend,
    const char* connstr,
    const char* table,
    char**      out_err
);

/**
 * Close the store and release all associated resources.
 *
 * Safe to call with NULL. After this call the handle is invalid; do not
 * pass it to any other function.
 */
void fasten_store_close(FastenStore* store);

/* ── Write path ────────────────────────────────────────────────────────────── */

/**
 * Insert a single audit row.
 *
 * Duplicate rows (same `id`) are silently ignored — the operation is
 * idempotent.
 *
 * @param store    Non-null handle returned by fasten_store_open().
 * @param row_json UTF-8 JSON object matching the fasten wire schema.
 *                 Required fields: id, wire_version, origin_id,
 *                 monotonic_seq, timestamp, code, action, severity,
 *                 service_id, source_node_id, actor, actor_kind, target,
 *                 category, domain, method, request_id, detail.
 *                 Optional: tenant_id, pii_in_detail, shipped_at.
 * @param out_err  Set on error; may be NULL.
 *
 * @return  0 on success, 1 on error (out_err set).
 */
int fasten_store_insert(
    FastenStore* store,
    const char*  row_json,
    char**       out_err
);

/* ── Health ─────────────────────────────────────────────────────────────────── */

/**
 * Verify the backend is reachable.
 *
 * Executes a lightweight query (SELECT 1). On PostgreSQL, a lost connection
 * is automatically re-established before the check.
 *
 * @param store    Non-null handle.
 * @param out_err  Set on error; may be NULL.
 *
 * @return  0 if reachable, 1 on error (out_err set).
 */
int fasten_store_ping(FastenStore* store, char** out_err);

/* ── Memory management ─────────────────────────────────────────────────────── */

/**
 * Free an error string returned by this library.
 *
 * Safe to call with NULL.
 */
void fasten_store_free_str(char* s);

/* ── Metadata ──────────────────────────────────────────────────────────────── */

/**
 * Return a NUL-terminated version string (e.g. "0.1.0").
 *
 * The pointer is valid for the lifetime of the process; do not free it.
 */
const char* fasten_store_version(void);

#ifdef __cplusplus
}
#endif

#endif /* FASTEN_STORE_CORE_H */
