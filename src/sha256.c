#include "sha256.h"
#include <arpa/inet.h>

#define SHA_N 256
#define SHA_WORD uint32_t
#define SHA_ROUNDS 64
#define SHA_ROT1 6
#define SHA_ROT2 11
#define SHA_ROT3 25
#define SHA_ROT4 2
#define SHA_ROT5 13
#define SHA_ROT6 22
#define SHA_ROT7 7
#define SHA_ROT8 18
#define SHA_ROT9 3
#define SHA_ROTA 17
#define SHA_ROTB 19
#define SHA_ROTC 10
#define SHA_TYPE sha256_t
#define SHA_INIT sha256_init
#define SHA_INITIAL sha256_initial_state
#define SHA_UPDATE sha256_update
#define SHA_FINALIZE sha256_finalize
#define SHA_FULL sha256_full
#define HMAC_TYPE hmac_sha256_t
#define HMAC_INIT hmac_sha256_init
#define HMAC_UPDATE hmac_sha256_update
#define HMAC_FINALIZE hmac_sha256_finalize
#define EXPANDX_FINALIZE hkdf_expand32_sha256_finalize
#define EXPAND_FULL hkdf_expand_sha256_full
#define XMD_INIT xmd_sha256_init
#define XMD_FINALIZE xmd_sha256_finalize
static const SHA_WORD k[SHA_ROUNDS] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const SHA_TYPE sha256_initial_state = {
    .state = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
    .buffer = {0,},
    .n_bits = 0,
    .buffer_counter = 0,
};

static inline SHA_WORD rotr(SHA_WORD x, int n){
    return (x >> n) | (x << (8*sizeof(SHA_WORD) - n));
}

static inline SHA_WORD step1(SHA_WORD e, SHA_WORD f, SHA_WORD g){
    return (rotr(e, SHA_ROT1) ^ rotr(e, SHA_ROT2) ^ rotr(e, SHA_ROT3)) + ((e & f) ^ ((~ e) & g));
}

static inline SHA_WORD step2(SHA_WORD a, SHA_WORD b, SHA_WORD c){
    return (rotr(a, SHA_ROT4) ^ rotr(a, SHA_ROT5) ^ rotr(a, SHA_ROT6)) + ((a & b) ^ (a & c) ^ (b & c));
}

static void sha_block(SHA_TYPE *sha) {
    SHA_WORD a = sha->state[0];
    SHA_WORD b = sha->state[1];
    SHA_WORD c = sha->state[2];
    SHA_WORD d = sha->state[3];
    SHA_WORD e = sha->state[4];
    SHA_WORD f = sha->state[5];
    SHA_WORD g = sha->state[6];
    SHA_WORD h = sha->state[7];

    SHA_WORD w[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    size_t i, j;
    size_t ws = sizeof(SHA_WORD);
    for (j = 0; j < 16; j++){
	for(i=0; i<ws; i++){
	    w[j] |= (SHA_WORD)sha->buffer[ws*j+i] << (ws-i-1)*8;
	}
    }

    for (i = 0; i < SHA_ROUNDS; i += 16){
        if (i){
            for (j = 0; j < 16; j++){
		    /* TODO: Doublecheck that this really is a register */
                register SHA_WORD ax = w[(j + 1) & 15];
                register SHA_WORD bx = w[(j + 14) & 15];
                register SHA_WORD s0 = (rotr(ax,  SHA_ROT7) ^ rotr(ax, SHA_ROT8) ^ (ax >> SHA_ROT9));
                register SHA_WORD s1 = (rotr(bx, SHA_ROTA) ^ rotr(bx, SHA_ROTB) ^ (bx >> SHA_ROTC));
                w[j] += w[(j + 9) & 15] + s0 + s1;
            }
        }

        for (j = 0; j < 16; j += 4){
            register SHA_WORD temp;
            temp = h + step1(e, f, g) + k[i + j + 0] + w[j + 0];
            h = temp + d;
            d = temp + step2(a, b, c);
            temp = g + step1(h, e, f) + k[i + j + 1] + w[j + 1];
            g = temp + c;
            c = temp + step2(d, a, b);
            temp = f + step1(g, h, e) + k[i + j + 2] + w[j + 2];
            f = temp + b;
            b = temp + step2(c, d, a);
            temp = e + step1(f, g, h) + k[i + j + 3] + w[j + 3];
            e = temp + a;
            a = temp + step2(b, c, d);
        }
    }

    sha->state[0] += a;
    sha->state[1] += b;
    sha->state[2] += c;
    sha->state[3] += d;
    sha->state[4] += e;
    sha->state[5] += f;
    sha->state[6] += g;
    sha->state[7] += h;

    memset_explicit(&a, 0, sizeof(SHA_WORD));
    memset_explicit(&b, 0, sizeof(SHA_WORD));
    memset_explicit(&c, 0, sizeof(SHA_WORD));
    memset_explicit(&d, 0, sizeof(SHA_WORD));
    memset_explicit(&e, 0, sizeof(SHA_WORD));
    memset_explicit(&f, 0, sizeof(SHA_WORD));
    memset_explicit(&g, 0, sizeof(SHA_WORD));
    memset_explicit(&h, 0, sizeof(SHA_WORD));
    memset_explicit(w, 0, sizeof(w));
}

void SHA_INIT(SHA_TYPE *sha){
	memcpy(sha, &SHA_INITIAL, sizeof(SHA_TYPE));
}
void SHA_UPDATE(SHA_TYPE *sha, const void *src, size_t n_bytes){
    uint8_t *srcb = (uint8_t*)src;
    sha->n_bits += 8 * n_bytes;

    if(n_bytes + sha->buffer_counter < SHA_N/4) {
    	memcpy(sha->buffer + sha->buffer_counter, srcb, n_bytes);
	sha->buffer_counter += n_bytes;
	return;
    }

    memcpy(sha->buffer + sha->buffer_counter, srcb, SHA_N/4 - sha->buffer_counter);
    sha_block(sha);
    n_bytes -= SHA_N/4 - sha->buffer_counter;
    srcb += SHA_N/4 - sha->buffer_counter;

    while(n_bytes >= SHA_N/4) {
    	memcpy(sha->buffer, srcb, SHA_N/4);
        sha_block(sha);
	n_bytes -= SHA_N/4;
	srcb += SHA_N/4;
    }
    memcpy(sha->buffer, srcb, n_bytes);
    sha->buffer_counter = n_bytes;
}

void SHA_FINALIZE(SHA_TYPE *sha, void *dst){
    uint8_t *ptr = (uint8_t*)dst;
    ssize_t i, j;

    sha->buffer[sha->buffer_counter++] = 0x80;
    if(sha->buffer_counter > SHA_N/4 * 7/8) {
	    (void)memset(sha->buffer + sha->buffer_counter, 0, SHA_N/4 - sha->buffer_counter);
    	    sha_block(sha);
	    sha->buffer_counter = 0;
    }
    (void)memset(sha->buffer + sha->buffer_counter, 0, SHA_N/4-8 - sha->buffer_counter);
    sha->buffer_counter = SHA_N/4-8;
    for (i = 7; i >= 0; i--){
        uint8_t byte = (sha->n_bits >> 8 * i) & 0xff;
    	sha->buffer[sha->buffer_counter++] = byte;
    }
    sha_block(sha);

    for (i = 0; i < 8; i++){
        for (j = (ssize_t)(sizeof(SHA_WORD)-1); j >= 0; j--){
            *ptr++ = (sha->state[i] >> j * 8) & 0xff;
        }
    }
}

void XMD_INIT(SHA_TYPE *sha) {
	SHA_INIT(sha);
	sha_block(sha); /* Z_pad */
	sha->n_bits = SHA_N/4 * 8;
}

void XMD_FINALIZE(SHA_TYPE *sha, void *out, uint16_t outlen, const void *dst, size_t dst_len) {
	uint8_t b_0[SHA_N/8], b_i[SHA_N/8], ctr = 0, dst2[SHA_N/8], dst_len1;
	uint16_t outlen_be = htons(outlen);
	uint8_t *outb = (uint8_t*)out;

	/* I intentionally do not return an error when outlen > 255 * SHA_N/8
	 * This is still an error for any application to do, but will not occur
	 * in decently designed protocols, and error propagation would
	 * complicate applications unnecessarily */

	if(dst_len > 255) {
		SHA_TYPE sha_dst;
		SHA_INIT(&sha_dst);
		SHA_UPDATE(&sha_dst, "H2C-OVERSIZE-DST-", 17);
		SHA_UPDATE(&sha_dst, dst, dst_len);
		SHA_FINALIZE(&sha_dst, dst2);
		dst = dst2;
		dst_len = SHA_N/8;
	}
	dst_len1 = dst_len; /* Low order byte */

	SHA_UPDATE(sha, &outlen_be, 2);
	SHA_UPDATE(sha, &ctr, 1);
	SHA_UPDATE(sha, dst, dst_len);
	SHA_UPDATE(sha, &dst_len1, 1);
	SHA_FINALIZE(sha, b_0);

	(void)memset(b_i, 0, sizeof(b_i));
	for(ctr = 1; outlen && ctr; ctr++) {
		for(size_t i=0; i < sizeof(b_i); i++) b_i[i] ^= b_0[i];
		SHA_INIT(sha);
		SHA_UPDATE(sha, b_i, sizeof(b_i));
		SHA_UPDATE(sha, &ctr, 1);
		SHA_UPDATE(sha, dst, dst_len);
		SHA_UPDATE(sha, &dst_len1, 1);
		SHA_FINALIZE(sha, b_i);
		size_t to_move = (outlen < SHA_N/8) ? outlen : SHA_N/8;
		memcpy(outb, b_i, to_move);
		outb += to_move;
		outlen -= to_move;
	}

	memset_explicit(b_0, 0, sizeof(b_0));
	memset_explicit(b_i, 0, sizeof(b_i));
}
