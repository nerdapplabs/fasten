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
 * 2. Error strings written into *out_err, and JSON output strings written into
 *    *out_rows_json, are heap-allocated by the library.  The caller must free
 *    them with fasten_store_free_str().
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

/* ── Error codes ───────────────────────────────────────────────────────────── */

/**
 * Typed return codes from all fasten_store_* functions (except open/close/
 * free_str/version, which use pointer or void returns).
 *
 * Check `rc == FASTEN_OK` for success; any other value indicates an error
 * and *out_err (if non-NULL) contains a heap-allocated detail string.
 *
 * Discriminant values are stable across library versions; new variants will
 * only ever be added with new values, never by renumbering existing ones.
 */
typedef enum {
    FASTEN_OK            = 0,   /**< Operation succeeded.                      */
    FASTEN_ERR_BACKEND   = 1,   /**< SQLite or PostgreSQL backend error.        */
    FASTEN_ERR_BAD_TABLE = 2,   /**< Invalid table or schema name.              */
    FASTEN_ERR_BAD_JSON  = 3,   /**< JSON parse or schema validation error.     */
    FASTEN_ERR_NULL_ARG  = 4,   /**< Null pointer or invalid UTF-8 argument.   */
    FASTEN_ERR_BAD_BACKEND = 5, /**< Unknown backend string.                   */
    FASTEN_ERR_UNKNOWN   = 99   /**< Internal panic or unexpected error.        */
} FastenErrorCode;

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
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_insert(
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
 * @return  FASTEN_OK if reachable, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_ping(FastenStore* store, char** out_err);

/* ── Read path ─────────────────────────────────────────────────────────────── */

/**
 * Query rows matching an optional JSON filter object.
 *
 * @param store         Non-null handle.
 * @param filter_json   Optional JSON object (may be NULL = match all rows).
 *                      Recognised keys (all optional):
 *                        "request_id"    — exact match
 *                        "code"          — exact match
 *                        "domain"        — exact match
 *                        "source_node_id"— exact match
 *                        "since"         — timestamp >= value (ISO-8601)
 *                        "until"         — timestamp <= value (ISO-8601)
 *                        "limit"         — max rows (0 = no limit)
 *                        "offset"        — skip this many matching rows
 * @param out_rows_json On success: set to a heap-allocated UTF-8 JSON array
 *                      of row objects, ordered by monotonic_seq ASC.
 *                      Free with fasten_store_free_str(). May be NULL.
 * @param out_err       Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_query(
    FastenStore* store,
    const char*  filter_json,
    char**       out_rows_json,
    char**       out_err
);

/**
 * Count rows matching an optional JSON filter object.
 *
 * @param store       Non-null handle.
 * @param filter_json Optional filter (see fasten_store_query); may be NULL.
 * @param out_count   Set to the row count on success; must be non-null.
 * @param out_err     Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_count(
    FastenStore* store,
    const char*  filter_json,
    uint64_t*    out_count,
    char**       out_err
);

/**
 * Return unshipped rows (rows where shipped_at IS NULL), ordered by
 * monotonic_seq ASC.
 *
 * @param store         Non-null handle.
 * @param limit         Maximum rows to return; 0 = all unshipped rows.
 * @param out_rows_json On success: heap-allocated UTF-8 JSON array.
 *                      Free with fasten_store_free_str(). May be NULL.
 * @param out_err       Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_list_unshipped(
    FastenStore* store,
    uint32_t     limit,
    char**       out_rows_json,
    char**       out_err
);

/**
 * Mark rows as shipped by setting shipped_at to the current UTC time.
 *
 * @param store    Non-null handle.
 * @param ids_json UTF-8 JSON array of ID strings: ["id1","id2",...].
 *                 IDs that do not exist are silently ignored.
 * @param out_err  Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_mark_shipped(
    FastenStore* store,
    const char*  ids_json,
    char**       out_err
);

/**
 * Delete rows whose timestamp is before `before_iso8601`.
 *
 * @param store             Non-null handle.
 * @param before_iso8601    ISO-8601 UTC timestamp; rows strictly older are
 *                          deleted.
 * @param respect_unshipped Non-zero: preserve rows with shipped_at IS NULL.
 *                          Zero: delete all matching rows regardless of
 *                          shipping status.
 * @param out_deleted       Set to the count of deleted rows; may be NULL.
 * @param out_err           Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_purge(
    FastenStore* store,
    const char*  before_iso8601,
    int          respect_unshipped,
    uint64_t*    out_deleted,
    char**       out_err
);

/**
 * Return the maximum monotonic_seq across all stored rows, or 0 if empty.
 *
 * @param store   Non-null handle.
 * @param out_seq Set to the maximum sequence number on success; must be
 *                non-null.
 * @param out_err Set on error; may be NULL.
 *
 * @return  FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_store_max_monotonic_seq(
    FastenStore* store,
    uint64_t*    out_seq,
    char**       out_err
);

/* ── Memory management ─────────────────────────────────────────────────────── */

/**
 * Free a string returned by this library (error strings and JSON output
 * strings are both allocated by the same mechanism and freed here).
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
