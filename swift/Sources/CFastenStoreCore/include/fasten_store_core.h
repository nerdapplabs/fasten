#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Buffer-based catalog + redaction functions from libfasten_store_core.
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

#define FASTEN_ERR_INVALID_KEY      6
#define FASTEN_ERR_ID_MISMATCH      7
#define FASTEN_ERR_DOMAIN_MISMATCH  8
#define FASTEN_ERR_DUPLICATE_CODE   9

#ifdef __cplusplus
}
#endif
