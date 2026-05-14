/**
 * fasten_core.h — C ABI for the shared fasten audit-store + drainer library.
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

#ifndef FASTEN_CORE_H
#define FASTEN_CORE_H

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
 *                 Pass application_name=fasten_core for visibility in
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

/* ── Redaction ─────────────────────────────────────────────────────────────── */

/**
 * Redact a JSON value using the global default key-pattern + value-shape rules.
 *
 * Default key patterns (case-insensitive): api_key, password, token, secret,
 * authorization, bearer, m2m_key, private_key, access_key, session_id,
 * cookie, credential, and variants.
 *
 * Default value shapes: JWT, PEM private key, AWS key, GitHub token,
 * Stripe live key, OpenAI key, credit-card (Luhn-validated).
 *
 * @param in_json   NUL-terminated UTF-8 JSON (object, array, or scalar).
 * @param out_json  On success: set to heap-allocated redacted JSON.
 *                  Free with fasten_store_free_str(). May be NULL.
 * @param out_err   Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_redact(
    const char* in_json,
    char**      out_json,
    char**      out_err
);

/**
 * Redact a JSON value with fully-custom key patterns, replacement token, and
 * extra value-shape patterns.  Use this when fasten.init() is called with
 * extra_redact_keys or extra_value_redact_patterns.
 *
 * @param in_json                   NUL-terminated UTF-8 JSON.
 * @param extra_keys_json           Optional: JSON array of plain key strings,
 *                                  e.g. ["my_field","other_field"]. NULL = none.
 * @param replacement               Optional: replacement token. NULL = "***".
 * @param extra_value_patterns_json Optional: JSON array of objects:
 *                                  [{"pattern":"<regex>","replacement":"***X***"},...]
 *                                  Appended after built-in value patterns. NULL = none.
 * @param out_json                  On success: heap-allocated redacted JSON.
 *                                  Free with fasten_store_free_str(). May be NULL.
 * @param out_err                   Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_redact_full(
    const char* in_json,
    const char* extra_keys_json,
    const char* replacement,
    const char* extra_value_patterns_json,
    char**      out_json,
    char**      out_err
);

/* ── Code catalog ──────────────────────────────────────────────────────────── */

/**
 * Register a batch of audit codes for a domain.
 *
 * @param domain     NUL-terminated domain string (e.g. "user", "billing").
 * @param codes_json NUL-terminated UTF-8 JSON object:
 *   {
 *     "USER_CREATED": {
 *       "domain":"user","category":"auth","action":"create",
 *       "severity":"info","description":"...","emitter":"auth-svc"
 *     }
 *   }
 *   Optional fields: retention_class ("short"|"medium"|"long", default "medium"),
 *   high_volume (bool), pii_in_detail (bool, forces retention_class="short"),
 *   declared_unused (bool), detail_passthrough_keys ([str]).
 * @param out_err    Set on error; may be NULL.
 *
 * Error codes:
 *   FASTEN_ERR_INVALID_KEY    — code key is not UPPER_SNAKE_CASE
 *   FASTEN_ERR_ID_MISMATCH    — Meta.id disagrees with the dict key
 *   FASTEN_ERR_DOMAIN_MISMATCH — Meta.domain disagrees with domain argument
 *   FASTEN_ERR_DUPLICATE_CODE — code was already registered
 *
 * @return FASTEN_OK on success, error code otherwise (out_err set).
 */
FastenErrorCode fasten_register_codes(
    const char* domain,
    const char* codes_json,
    char**      out_err
);

/**
 * Look up a single code in the global registry.
 *
 * @param code      NUL-terminated code key (e.g. "USER_CREATED").
 * @param out_json  On success: heap-allocated UTF-8 JSON Meta object, or
 *                  "{}" if the code is not registered.
 *                  Free with fasten_store_free_str(). May be NULL.
 * @param out_err   Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_meta_of(
    const char* code,
    char**      out_json,
    char**      out_err
);

/**
 * Dump the entire registry as sorted `id,domain,severity` CSV, one code
 * per line.  Identical to the Python `fasten.codes.dump()` output.
 *
 * @param out_csv  On success: heap-allocated UTF-8 CSV string.
 *                 Free with fasten_store_free_str(). May be NULL.
 * @param out_err  Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_registry_dump(
    char** out_csv,
    char** out_err
);

/**
 * Clear the global registry.  Intended for test teardown and re-init.
 * Thread-safe.
 */
void fasten_registry_clear(void);

/* ── Buffer-based variants (no heap allocation) ───────────────────────────── */

/**
 * Buffer-based variant of fasten_redact.  No heap allocation; the caller
 * supplies pre-allocated output and error buffers.
 *
 * @param in_json     NUL-terminated UTF-8 JSON.
 * @param out_buf     Caller-supplied buffer for the redacted JSON (NUL-terminated).
 * @param buf_len     Size of out_buf in bytes.
 * @param out_err_buf Caller-supplied buffer for the error message (NUL-terminated).
 * @param err_buf_len Size of out_err_buf in bytes.
 *
 * @return Bytes written (exclusive of NUL) on success.
 *         -(FastenErrorCode) on error (error message in out_err_buf).
 */
int32_t fasten_redact_buf(
    const char* in_json,
    uint8_t*    out_buf,
    uint32_t    buf_len,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

/**
 * Buffer-based variant of fasten_redact_full.
 *
 * extra_keys_json and extra_value_patterns_json must be valid JSON arrays
 * (use "[]" for empty rather than NULL).
 * replacement may be empty string to use the default "***".
 *
 * @return Bytes written (exclusive of NUL) on success.
 *         -(FastenErrorCode) on error.
 */
int32_t fasten_redact_full_buf(
    const char* in_json,
    const char* extra_keys_json,
    const char* replacement,
    const char* extra_value_patterns_json,
    uint8_t*    out_buf,
    uint32_t    buf_len,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

/**
 * Buffer-based variant of fasten_register_codes.
 *
 * @return FASTEN_OK (0) on success, positive FastenErrorCode on error
 *         (error message in out_err_buf).
 */
int32_t fasten_register_codes_buf(
    const char* domain,
    const char* codes_json,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

/**
 * Buffer-based variant of fasten_meta_of.
 *
 * @return Bytes written (exclusive of NUL) on success (0 = code not found).
 *         -(FastenErrorCode) on error.
 */
int32_t fasten_meta_of_buf(
    const char* code,
    uint8_t*    out_buf,
    uint32_t    buf_len,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

/* ── SDK-store callback bridge ─────────────────────────────────────────────── */

/**
 * Callback invoked by the drainer for each row insert.
 * `row_json` is valid only for the duration of the call.
 * Return 0 = success; any other value = error (drainer will retry).
 */
typedef int32_t (*FastenInsertCallbackFn)(const char* row_json, void* userdata);

/**
 * Create a store handle backed by a C insert callback.
 *
 * Use this to bridge an SDK-owned store into the fasten drainer without
 * migrating the store to fasten_store_open().  Always returns a non-null handle.
 *
 * @param fn       Insert callback; must be non-null.
 * @param userdata Passed to every `fn` invocation unchanged.
 * @param out_err  Reserved; currently always succeeds.
 */
FastenStore* fasten_store_from_callback(
    FastenInsertCallbackFn fn,
    void*                  userdata,
    char**                 out_err
);

/* ── Drainer ───────────────────────────────────────────────────────────────── */

/**
 * Attach a background-drain queue to an existing store handle.
 *
 * Must be called before fasten_drainer_enqueue. The drainer shares the
 * store already held by `store`. Re-calling replaces any existing drainer
 * (previous pending rows are flushed with a 2-second timeout first).
 *
 * @param store            Non-null handle returned by fasten_store_open().
 * @param capacity         Max queued + in-flight slots (0 = default 100).
 * @param retry_initial_ms First backoff window ms (0 = default 100).
 * @param retry_max_ms     Backoff ceiling ms (0 = default 60 000).
 * @param retry_jitter     Non-zero = apply ±20% uniform jitter.
 * @param max_attempts     Dead-letter threshold (0 = default 50).
 * @param out_err          Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_drainer_install(
    FastenStore* store,
    uint64_t     capacity,
    uint64_t     retry_initial_ms,
    uint64_t     retry_max_ms,
    int          retry_jitter,
    uint32_t     max_attempts,
    char**       out_err
);

/**
 * Enqueue a row JSON for asynchronous insertion.
 *
 * Blocks under back-pressure (queue full + store slow). Returns
 * FASTEN_ERR_NULL_ARG when no drainer is installed.
 *
 * @param store    Non-null handle.
 * @param row_json UTF-8 JSON object matching the fasten wire schema.
 * @param out_err  Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_drainer_enqueue(
    FastenStore* store,
    const char*  row_json,
    char**       out_err
);

/**
 * Block until all currently-queued rows have drained, or `timeout_ms` elapses.
 *
 * @param store            Non-null handle.
 * @param timeout_ms       Maximum wait time; 0 = wait indefinitely.
 * @param out_fully_drained Set to 1 if fully drained, 0 if timed out. May be NULL.
 * @param out_err          Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_drainer_flush(
    FastenStore* store,
    uint64_t     timeout_ms,
    int*         out_fully_drained,
    char**       out_err
);

/**
 * Return queue stats as a JSON object string.
 *
 * Returns "null" when no drainer is installed. Free the result with
 * fasten_store_free_str().
 *
 * @param store    Non-null handle.
 * @param out_json On success: heap-allocated UTF-8 JSON stats object.
 * @param out_err  Set on error; may be NULL.
 *
 * @return FASTEN_OK on success, error code otherwise.
 */
FastenErrorCode fasten_drainer_stats_json(
    FastenStore* store,
    char**       out_json,
    char**       out_err
);

/**
 * Shut down the drainer: signal the background thread to stop and
 * perform a best-effort drain (2-second timeout). Safe to call with NULL
 * or when no drainer is installed.
 */
void fasten_drainer_close(FastenStore* store);

/* ── Additional error codes (catalog) ─────────────────────────────────────── */

/* These values extend the FastenErrorCode enum defined above. */
#define FASTEN_ERR_INVALID_KEY     6  /**< Code key not UPPER_SNAKE_CASE.           */
#define FASTEN_ERR_ID_MISMATCH     7  /**< Meta.id disagrees with dict key.         */
#define FASTEN_ERR_DOMAIN_MISMATCH 8  /**< Meta.domain disagrees with domain arg.   */
#define FASTEN_ERR_DUPLICATE_CODE  9  /**< Code already registered.                 */

#ifdef __cplusplus
}
#endif

#endif /* FASTEN_CORE_H */
