// SPDX-License-Identifier: Apache-2.0
#ifndef FIXTURES_H
#define FIXTURES_H

#include "bbs.h"

#include <stddef.h>
#include <stdio.h>

// This header file defines several extern constants, which are generated per
// ciphersuite by fixtures_transpiler.c

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
extern const char *const fixture_ciphersuite_name;

extern const struct fixture_hash_to_scalar {
	bbs_message msg;
	bbs_message dst;
	uint8_t     result[32];
} *const vectors_hash_to_scalar;
extern const size_t vectors_hash_to_scalar_len;

extern const struct fixture_generators {
	const uint8_t (*result)[48]; // Includes Q_1, H_1, ... H_(result_len-1)
	size_t          result_len;
} *const vectors_generators;
extern const size_t vectors_generators_len;

extern const struct fixture_keygen {
	bbs_message key_material;
	bbs_message key_info;
	bbs_message key_dst;
	uint8_t     result_sk[32];
	uint8_t     result_pk[96];
} *const vectors_keygen;
extern const size_t vectors_keygen_len;

extern const struct fixture_signature {
	uint8_t      sk[32];
	uint8_t      pk[96];
	bbs_message  header;
	size_t       num_messages;
	const bbs_message *msgs;
	uint8_t      result[80];
	int          result_valid;
} *const vectors_signature;
extern const size_t vectors_signature_len;

// The proof_gen fixtures use mocked scalars
extern const struct fixture_mocked_scalars {
	bbs_message     seed;
	bbs_message     dst;
	const uint8_t (*result)[32];
	size_t          result_len;
} *const vectors_mocked_scalars;
extern const size_t vectors_mocked_scalars_len;

extern const struct fixture_proof {
	uint8_t       pk[96];
	uint8_t       signature[80];
	bbs_message   header;
	bbs_message   presentation_header;
	size_t        num_messages;
	const bbs_message *msgs;
	const size_t *disclosed_indexes;
	size_t        disclosed_indexes_len;
	bbs_message   mocking_seed;
	bbs_message   mocking_dst;
	bbs_message   result;
	int           result_valid;
} *const vectors_proof;
extern const size_t vectors_proof_len;

#endif /* FIXTURES_H */
