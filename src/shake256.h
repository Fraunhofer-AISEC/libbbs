// SPDX-License-Identifier: Apache-2.0
// Based on sha3.h by Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

// state context
typedef struct {
    union {                                 // state:
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;                    // these don't overflow
} shake256_t;

// SHAKE256
void shake256_init(shake256_t *c);
void shake256_update(shake256_t *c, const void *data, size_t len);
void shake256_finalize(shake256_t *c, void *out, size_t outlen);    // digest goes to md

// RFC 9380 expand_message XOF, deals correctly with oversized DSTs
#define xof_shake256_init shake256_init
#define xof_shake256_update shake256_update
void xof_shake256_finalize(shake256_t *shake, void *out, uint16_t outlen, const void *dst, size_t dst_len);

#endif

