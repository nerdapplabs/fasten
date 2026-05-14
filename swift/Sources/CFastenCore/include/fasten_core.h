#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Buffer-based catalog + redaction functions from libfasten_core.
 * No heap allocation on the Rust side; caller provides pre-allocated buffers.
 *
 * Return convention:
 *   fasten_redact_buf, fasten_redact_full_buf, fasten_meta_of_buf:
 *     >= 0  bytes written to out_buf (exclusive of NUL); 0 = not found
 *     < 0   -(FastenErrorCode), error message in out_err_buf
 *
 *   fasten_register_codes_buf:
 *     == 0  FASTEN_OK
 *     > 0   FastenErrorCode, error message in out_err_buf
 */

int32_t fasten_redact_buf(
    const char* in_json,
    uint8_t*    out_buf,
    uint32_t    buf_len,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

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

int32_t fasten_register_codes_buf(
    const char* domain,
    const char* codes_json,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

int32_t fasten_meta_of_buf(
    const char* code,
    uint8_t*    out_buf,
    uint32_t    buf_len,
    uint8_t*    out_err_buf,
    uint32_t    err_buf_len
);

void fasten_registry_clear(void);

/* Opaque store + drainer handle */
typedef struct FastenStore FastenStore;

FastenStore* fasten_store_open(const char* backend, const char* connstr, const char* table, char** out_err);
void         fasten_store_close(FastenStore* store);
void         fasten_store_free_str(char* s);

/* SDK-store callback bridge */
typedef int32_t (*FastenInsertCallbackFn)(const char* row_json, void* userdata);
FastenStore* fasten_store_from_callback(FastenInsertCallbackFn fn, void* userdata, char** out_err);

int32_t fasten_drainer_install(
    FastenStore* store, uint64_t capacity, uint64_t retry_initial_ms,
    uint64_t retry_max_ms, int retry_jitter, uint32_t max_attempts, char** out_err
);
int32_t fasten_drainer_enqueue(FastenStore* store, const char* row_json, char** out_err);
int32_t fasten_drainer_flush(FastenStore* store, uint64_t timeout_ms, int* out_fully_drained, char** out_err);
int32_t fasten_drainer_stats_json(FastenStore* store, char** out_json, char** out_err);
void    fasten_drainer_close(FastenStore* store);

#define FASTEN_ERR_INVALID_KEY      6
#define FASTEN_ERR_ID_MISMATCH      7
#define FASTEN_ERR_DOMAIN_MISMATCH  8
#define FASTEN_ERR_DUPLICATE_CODE   9

#ifdef __cplusplus
}
#endif
