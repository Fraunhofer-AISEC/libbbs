#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>
#include "compat-string.h"

/* SHA256 */
typedef struct sha256 {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t n_bits;
    uint8_t buffer_counter;
} sha256_t;
void sha256_init(sha256_t *sha);
void sha256_update(sha256_t *sha, const void *data, size_t n_bytes);
void sha256_finalize(sha256_t *sha, void *dst_bytes32);

/* XMD-SHA256 */
void xmd_sha256_init(sha256_t *sha);
#define xmd_sha256_update sha256_update
void xmd_sha256_finalize(sha256_t *sha, void *out, uint16_t outlen, const void *dst, size_t dst_len);

#endif
