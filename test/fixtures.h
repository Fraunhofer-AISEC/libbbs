// SPDX-License-Identifier: Apache-2.0
#ifndef FIXTURES_H
#define FIXTURES_H

#include "bbs.h"
#include "bbs_blind.h"
#include "bbs_blind_with_nym.h"

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

// Blind BBS extension fixtures

extern const struct blind_fixture_generators {
	const uint8_t (*signer_result)[48]; // Q_1, H_0 .. H_(L-1)
	size_t          signer_result_len;
	const uint8_t (*prover_result)[48]; // Q_2, J_0 .. J_(M-1)
	size_t          prover_result_len;
} *const vectors_blind_generators;
extern const size_t vectors_blind_generators_len;

extern const struct blind_fixture_commit {
	// random init values
	const void *mocking_seed;
	size_t mocking_seed_len;
	const void *mocking_dst;
	size_t mocking_dst_len;
	size_t mocking_count;

	// input
	size_t num_committed_messages;
	const void *const *committed_msgs;
	const size_t *committed_msg_lens;

	// output
	uint8_t prover_blind[32];
	const void *result;
	size_t result_len;
	int result_valid;
} *const vectors_blind_commit;
extern const size_t vectors_blind_commit_len;

extern const struct blind_fixture_signature {
	uint8_t sk[32];
	uint8_t pk[96];

	const void *header;
	size_t header_len;

	// commitment
	const void *commitment_with_proof;
	size_t commitment_with_proof_len;

	// signer-known messages
	size_t num_messages;
	const void *const *msgs;
	const size_t *msg_lens;

	// committed messages
	size_t num_committed_messages;
	const void *const *committed_msgs;
	const size_t *committed_msg_lens;

	uint8_t prover_blind[32];

	// expected output
	uint8_t result[80];
	int result_valid;
} *const vectors_blind_signature;
extern const size_t vectors_blind_signature_len;

extern const struct blind_fixture_proof {
	uint8_t pk[96];
	uint8_t signature[80];

	const void *header;
	size_t header_len;
	const void *presentation_header;
	size_t presentation_header_len;

	// commitment
	//const void *commitment_with_proof;
	//size_t commitment_with_proof_len;
	uint8_t prover_blind[32];

	// signer-known messages
	size_t num_messages;
	const void *const *msgs;
	const size_t *msg_lens;

	// committed messages
	size_t num_committed_messages;
	const void *const *committed_msgs;
	const size_t *committed_msg_lens;

	// subset of signer messages to disclose
	const size_t *disclosed_indexes;
	size_t disclosed_indexes_len;

	// subset of committed messages to disclose
	const size_t *disclosed_committed_indexes;
	size_t disclosed_committed_indexes_len;

	// num_signer_known_messages
	size_t L;

	// mocked rng for the proof
	const void *proof_mocking_seed;
	size_t proof_mocking_seed_len;
	const void *proof_mocking_dst;
	size_t proof_mocking_dst_len;
	//size_t proof_mocking_count;

    // disclosed message content (filtered subset, for verify)
    const void *const *disclosed_msgs;
    const size_t *disclosed_msg_lens;
    size_t disclosed_msgs_len;
    const void *const *disclosed_committed_msgs;
    const size_t *disclosed_committed_msg_lens;
    size_t disclosed_committed_msgs_len;

	// expected output
	const void *result;
	size_t result_len;
	int result_valid;
} *const vectors_blind_proof;
extern const size_t vectors_blind_proof_len;

// Blind BBS with pseudonyms

extern const struct blind_with_nym_fixture_generators {
	const uint8_t (*signer_result)[48]; // Q_1, H_0 .. H_(L-1)
	size_t          signer_result_len;
	const uint8_t (*prover_result)[48]; // Q_2, J_0 .. J_(M-1)
	size_t          prover_result_len;
} *const vectors_blind_with_nym_generators;
extern const size_t vectors_blind_with_nym_generators_len;

extern const struct blind_with_nym_fixture_commit {
	// random init values
    const void *mocking_seed;
    size_t mocking_seed_len;
    const void *mocking_dst;
    size_t mocking_dst_len;

    // input
    size_t num_committed_messages;
    const void *const *committed_msgs;
    const size_t *committed_msg_lens;

    // pseudonym stuff
    size_t num_prover_nyms;
    const void *const *prover_nyms;

    // output
    uint8_t prover_blind[32];
    const void *result;
    size_t result_len;
    int result_valid;
} *const vectors_blind_with_nym_commit;
extern const size_t vectors_blind_with_nym_commit_len;

extern const struct blind_with_nym_fixture_signature {
    uint8_t sk[32];
    uint8_t pk[96];

    uint8_t signer_nym_entropy[32];

    const void *header;
    size_t header_len;

	// commitment
    const void *commitment_with_proof;
    size_t commitment_with_proof_len;

	// signer-known messages
    size_t num_messages;
    const void *const *msgs;
    const size_t *msg_lens;

	// committed messages
    size_t num_committed_messages;
    const void *const *committed_msgs;
    const size_t *committed_msg_lens;

    // pseudonym stuff
    size_t num_prover_nyms;
    const void *const *prover_nyms;

    // output
    size_t num_nym_secrets;
    const void *const *nym_secrets;
    uint8_t prover_blind[32];
    uint8_t result[80];
    int     result_valid;
} *const vectors_blind_with_nym_signature;
extern const size_t vectors_blind_with_nym_signature_len;

extern const struct blind_with_nym_fixture_proof {
    uint8_t pk[96];
    uint8_t signature[80];

    uint8_t signer_nym_entropy[32];

    const void *header;
    size_t header_len;
    const void *presentation_header;
    size_t presentation_header_len;

    const void *context_id;
    size_t context_id_len;

    uint8_t pseudonym[48];

    const void *commitment_with_proof;
    size_t commitment_with_proof_len;
    uint8_t prover_blind[32];

    // all signer messages
    size_t num_messages;
    const void *const *msgs;
    const size_t *msg_lens;

    // all committed messages
    size_t num_committed_messages;
    const void *const *committed_msgs;
    const size_t *committed_msg_lens;

    // prover nyms and nym secrets
    size_t num_prover_nyms;
    const void *const *prover_nyms;
    size_t num_nym_secrets;
    const void *const *nym_secrets;

    // disclosed subsets
    const size_t *disclosed_indexes;
    size_t disclosed_indexes_len;
    const void *const *disclosed_msgs;
    const size_t *disclosed_msg_lens;

    const size_t *disclosed_committed_indexes;
    size_t disclosed_committed_indexes_len;
    const void *const *disclosed_committed_msgs;
    const size_t *disclosed_committed_msg_lens;

    // total number of signer known messages
    size_t L;

    // proof mocking only
    const void *proof_mocking_seed;
    size_t proof_mocking_seed_len;
    const void *proof_mocking_dst;
    size_t proof_mocking_dst_len;

    const void *result;
    size_t result_len;
    int result_valid;
} *const vectors_blind_with_nym_proof;
extern const size_t vectors_blind_with_nym_proof_len;

#endif /* FIXTURES_H */
