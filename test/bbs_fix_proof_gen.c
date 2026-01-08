// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include "bbs_util.h"
#include <stdbool.h>

/* Note:
 * We cannot test the main bbs_proof_gen here, because it involves randomness
 * and thus cannot have fixed test vectors. Rather, the BBS draft has a custom
 * procedure to test most of the subfunctions, which are supposed to be static.
 * Therefore, we link against a custom version of libbbs, in which these
 * functions are not static, and mock the PRF to use the fixed values from the
 * draft. Not ideal, I know... */

// BEGIN declarations of bbs.c
// These are usually static, but made global in a modified library
typedef struct {
	const bbs_ciphersuite   *cipher_suite;
	uint8_t                generator_ctx[48 + 8];
	union bbs_hash_context dom_ctx;
	blst_p1 Q_1;
	// Final output
	blst_p1 B;
	// Temporary outputs
	blst_p1 H_i;
	blst_scalar msg_scalar; // Also used for domain
} bbs_acc_ctx;
typedef struct {
	bbs_acc_ctx acc;
	blst_p1 T2;
	union bbs_hash_context ch_ctx;
	uint64_t disclosed_ctr;
	uint64_t undisclosed_ctr;
	bbs_bn_prf           *prf;
	void                 *prf_cookie;
} bbs_proof_gen_ctx;
void
bbs_proof_gen_init (
	bbs_proof_gen_ctx *ctx,
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	);
void
bbs_proof_gen_update (
	bbs_proof_gen_ctx *ctx,
	void *proof,
	const void *msg,
	size_t msg_len,
	bool disclosed
	);
int
bbs_proof_gen_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_signature   signature,
	void              *proof,
	const void        *header,
	size_t                header_len,
	const void        *presentation_header,
	size_t                presentation_header_len,
	uint64_t              num_messages,
	size_t                num_disclosed
	);
// END declarations of bbs.c

// Mocked random scalars for bbs_proof_gen_det
// The randomness-array contains r1, r3^-1, e~, r1~, r3~, and the m~
// We return on (input_type, input):
// (0,x) -> rand[x+2], (1,0) -> rand[0], (2,0) -> rand[1]
void
mocked_prf (
	const bbs_ciphersuite *cipher_suite,
	blst_scalar              *out,
	uint8_t             input_type,
	uint64_t            input,
	void               *seed
	)
{
	(void)cipher_suite;
	uint8_t *rand = (uint8_t*) seed;

	if (0 == input_type && 10 > input)      rand += (2 + input) * 48;
	else if (0 == input && 2 >= input_type) rand += (input_type - 1) * 48;
	else return; // Will most likely violate the fixtures

	blst_scalar_from_be_bytes(out, rand, 48);
}


// This function should be almost identical to bbs_proof_gen, except that it
// also prepares some randomness and uses mocked_prf instead of bbs_proof_prf.
int
mocked_proof_gen (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	void                  *proof,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	uint64_t               num_messages,
	const void *const     *messages,
	const size_t          *messages_lens,
	const void            *mocking_seed,
	size_t                 mocking_seed_len,
	const void            *mocking_dst,
	size_t                 mocking_dst_len
	)
{
	union bbs_hash_context h_ctx;
	uint8_t seed[(5 + num_messages - disclosed_indexes_len) * 48];
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	bool disclosed;

	cipher_suite->expand_message_init(&h_ctx);
	cipher_suite->expand_message_update(&h_ctx, mocking_seed, mocking_seed_len);
	cipher_suite->expand_message_finalize(&h_ctx, seed,
			(5 + num_messages - disclosed_indexes_len) * 48,
			mocking_dst, mocking_dst_len);

	bbs_proof_gen_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len, mocked_prf, seed);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_proof_gen_update(&ctx, proof, messages[i], messages_lens[i], disclosed);
		if(disclosed) di_idx++;
	}

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}


int
bbs_fix_proof_gen ()
{
	union bbs_hash_context ctx;
	blst_scalar s;
	uint8_t s_buffer[BBS_SCALAR_LEN];

	// First test the mocking PRF
	for(size_t i=0; i < vectors_mocked_scalars_len; i++) {
		uint8_t rand[vectors_mocked_scalars[i].result_len * 48];

		(*fixture_ciphersuite)->expand_message_init(&ctx);
		(*fixture_ciphersuite)->expand_message_update(&ctx,
				vectors_mocked_scalars[i].seed,
				vectors_mocked_scalars[i].seed_len);
		(*fixture_ciphersuite)->expand_message_finalize(&ctx, rand,
				vectors_mocked_scalars[i].result_len * 48,
				vectors_mocked_scalars[i].dst,
				vectors_mocked_scalars[i].dst_len);

		for (size_t j = 0; j < vectors_mocked_scalars[i].result_len; j++) {
			if(j<2) mocked_prf(*fixture_ciphersuite, &s, j+1, 0, rand);
			else    mocked_prf(*fixture_ciphersuite, &s, 0, j-2, rand);
			bn_write_bbs (s_buffer, &s);

			ASSERT_EQ_PTR ("mocked scalar",
					s_buffer,
					vectors_mocked_scalars[i].result[j],
					sizeof(vectors_mocked_scalars[i].result[j]));
		}
	}

	// Now test the actual proof_gen routines
	for(size_t i=0; i < vectors_proof_len; i++) {
		// Do not try to recreate invalid proofs
		if(!vectors_proof[i].result_valid) continue;
		uint8_t proof[vectors_proof[i].result_len];

		if (BBS_OK != mocked_proof_gen(*fixture_ciphersuite,
					vectors_proof[i].pk,
					vectors_proof[i].signature,
					proof,
					vectors_proof[i].header,
					vectors_proof[i].header_len,
					vectors_proof[i].presentation_header,
					vectors_proof[i].presentation_header_len,
					vectors_proof[i].disclosed_indexes,
					vectors_proof[i].disclosed_indexes_len,
					vectors_proof[i].num_messages,
					vectors_proof[i].msgs,
					vectors_proof[i].msg_lens,
					vectors_proof[i].mocking_seed,
					vectors_proof[i].mocking_seed_len,
					vectors_proof[i].mocking_dst,
					vectors_proof[i].mocking_dst_len))
		{
			puts ("Error during proof generation");
			return 1;
		}
		ASSERT_EQ_PTR ("proof generation",
			       proof,
			       vectors_proof[i].result,
			       vectors_proof[i].result_len);
	}

	return 0;
}
