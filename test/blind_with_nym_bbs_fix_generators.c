// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include "bbs_util.h"

#define BBS_BLIND_API_ID_PREFIX "BLIND_"

int
blind_with_nym_bbs_fix_generators(void)
{
	uint8_t state[48 + 8];
	blst_p1 g;
	uint8_t g_buffer[BBS_G1_ELEM_LEN];

	for (size_t i = 0; i < vectors_blind_with_nym_generators_len; i++) {
		// Signer generators — normal api_id, no prefix
		create_generator_init(*fixture_ciphersuite, state, NULL, 0);
		for (size_t j = 0; j < vectors_blind_with_nym_generators[i].signer_result_len; j++) {
			create_generator_next(*fixture_ciphersuite, state, &g, NULL, 0);
			ep_write_bbs(g_buffer, &g);
			ASSERT_EQ_PTR("signer generator",
				g_buffer,
				vectors_blind_with_nym_generators[i].signer_result[j],
				BBS_G1_ELEM_LEN);
		}

		// blind generators with BLIND_ prefix
		create_generator_init(*fixture_ciphersuite, state, (uint8_t*)BBS_BLIND_API_ID_PREFIX, sizeof(BBS_BLIND_API_ID_PREFIX) - 1);
		for (size_t j = 0; j < vectors_blind_with_nym_generators[i].prover_result_len; j++) {
			create_generator_next(*fixture_ciphersuite, state, &g, (uint8_t*)BBS_BLIND_API_ID_PREFIX, sizeof(BBS_BLIND_API_ID_PREFIX) - 1);
			ep_write_bbs(g_buffer, &g);
			ASSERT_EQ_PTR("prover generator",
				g_buffer,
				vectors_blind_with_nym_generators[i].prover_result[j],
				BBS_G1_ELEM_LEN);
		}
	}

	return 0;
}
