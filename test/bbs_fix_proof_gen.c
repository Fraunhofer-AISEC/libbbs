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
				vectors_mocked_scalars[i].seed);
		(*fixture_ciphersuite)->expand_message_finalize(&ctx,
				BBS_OUTMSG(rand, vectors_mocked_scalars[i].result_len * 48),
				vectors_mocked_scalars[i].dst);

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
		uint8_t proof[vectors_proof[i].result.len];

		// Expand pseudorandom test tape
		uint8_t rand[(5 + vectors_proof[i].num_messages
				- vectors_proof[i].disclosed_indexes_len) * 48];
		(*fixture_ciphersuite)->expand_message_init(&ctx);
		(*fixture_ciphersuite)->expand_message_update(&ctx,
				vectors_proof[i].mocking_seed);
		(*fixture_ciphersuite)->expand_message_finalize(&ctx,
				BBS_OUTMSG(rand, sizeof(rand)),
				vectors_proof[i].mocking_dst);

		if (BBS_OK != __bbs_proof_gen_deterministic(*fixture_ciphersuite,
					vectors_proof[i].pk,
					vectors_proof[i].signature,
					BBS_OUTMSG(proof, sizeof(proof)),
					vectors_proof[i].header,
					vectors_proof[i].presentation_header,
					vectors_proof[i].disclosed_indexes,
					vectors_proof[i].disclosed_indexes_len,
					vectors_proof[i].msgs,
					vectors_proof[i].num_messages,
					mocked_prf, rand))
		{
			puts ("Error during proof generation");
			return 1;
		}
		ASSERT_EQ_PTR ("proof generation",
			       proof,
			       vectors_proof[i].result.loc,
			       vectors_proof[i].result.len);
	}

	return 0;
}
