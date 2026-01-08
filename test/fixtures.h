// SPDX-License-Identifier: Apache-2.0
#ifndef FIXTURES_H
#define FIXTURES_H

#include "bbs.h"

#include <stddef.h>
#include <stdio.h>

// This header file defines several extern constants, which are generated per
// ciphersuite by genfixtures. 

// Helpful macros to print and compare memory
#define PRINT(p, a, l)  do { puts (p); for (size_t xx = 0; xx<l; xx++) printf ("%02x ", ((uint8_t*)a)[xx]); \
			     puts (""); } while (0);
#define ASSERT_EQ_PTR(purpose, actual, ref, len) \
	for (size_t assert_eq_index = 0; assert_eq_index < len; assert_eq_index++) { \
		if (((uint8_t*)actual)[assert_eq_index] != ((uint8_t*)ref)[assert_eq_index]) { \
			puts ("Mismatch in " purpose); \
			printf ("actual[%zu]: %02x\n", assert_eq_index, ((uint8_t*)actual)[assert_eq_index]); \
			printf ("ref[%zu]: %02x\n",    assert_eq_index, ((uint8_t*)ref)[assert_eq_index]); \
			PRINT ("Should be:", ref,    len); \
			PRINT ("Is:",        actual, len); \
			return 1; \
		} \
	}

extern const bbs_ciphersuite *const *const fixture_ciphersuite;

extern const struct fixture_hash_to_scalar {
	const void *msg;
	size_t      msg_len;
	const void *dst;
	size_t      dst_len;
	uint8_t     result[32];
} *const vectors_hash_to_scalar;
extern const size_t vectors_hash_to_scalar_len;

extern const struct fixture_generators {
	const uint8_t (*result)[48]; // Includes Q_1, H_1, ... H_(result_len-1)
	size_t          result_len;
} *const vectors_generators;
extern const size_t vectors_generators_len;

extern const struct fixture_keygen {
	const void *key_material;
	size_t      key_material_len;
	const void *key_info;
	size_t      key_info_len;
	const void *key_dst;
	size_t      key_dst_len;
	uint8_t     result_sk[32];
	uint8_t     result_pk[96];
} *const vectors_keygen;
extern const size_t vectors_keygen_len;

extern const struct fixture_signature {
	uint8_t            sk[32];
	uint8_t            pk[96];
	const void        *header;
	size_t             header_len;
	size_t             num_messages;
	const void *const *msgs;
	const size_t      *msg_lens;
	uint8_t            result[80];
	int                result_valid;
} *const vectors_signature;
extern const size_t vectors_signature_len;

// The proof_gen fixtures use mocked scalars
extern const struct fixture_mocked_scalars {
	const void     *seed;
	size_t          seed_len;
	const void     *dst;
	size_t          dst_len;
	const uint8_t (*result)[32];
	size_t          result_len;
} *const vectors_mocked_scalars;
extern const size_t vectors_mocked_scalars_len;

extern const struct fixture_proof {
	uint8_t            pk[96];
	uint8_t            signature[80];
	const void        *header;
	size_t             header_len;
	const void        *presentation_header;
	size_t             presentation_header_len;
	size_t             num_messages;
	const void *const *msgs;
	const size_t      *msg_lens;
	const size_t      *disclosed_indexes;
	size_t             disclosed_indexes_len;
	const void        *mocking_seed;
	size_t             mocking_seed_len;
	const void        *mocking_dst;
	size_t             mocking_dst_len;
	const void        *result;
	size_t             result_len;
	int                result_valid;
} *const vectors_proof;
extern const size_t vectors_proof_len;

#endif /* FIXTURES_H */
