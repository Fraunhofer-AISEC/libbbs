#include "fixtures.h"
#include "bbs_util.h"

int
bbs_blind_commit_with_nym_inner(
    const bbs_ciphersuite  *cipher_suite,
    uint8_t                *commitment_with_proof,
    uint8_t                *secret_prover_blind,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *messages_lens,
    size_t                  num_prover_nyms,
    const void *const      *prover_nyms,
    bbs_bn_prf              prf,
    void                   *prf_cookie
);

void blind_commit_mocked_prf(
	const bbs_ciphersuite   *cipher_suite,
	blst_scalar             *out,
	uint8_t                 input_type,
	uint64_t                input,
	void                    *cookie
) {
	(void)cipher_suite;
	uint8_t *rand = (uint8_t*) cookie;

    // secret_prover_blind = 0

    // s~ = 1
    if (input_type == 1) {
        rand += 48;
    }

    // message = index = input
    if (input_type == 2) {
        rand += (2 * 48) + (input * 48);
    }

	blst_scalar_from_be_bytes(out, rand, 48);
}

int mocked_bbs_blind_commit(
    const bbs_ciphersuite *cipher_suite,
    uint8_t *commitment_with_proof,
    uint8_t *secret_prover_blind,
    uint64_t num_blinded_messages,
    const void *const *messages,
	const size_t *messages_lens,
    const void *mocking_seed,
	size_t mocking_seed_len,
	const void *mocking_dst,
	size_t mocking_dst_len
) {
    // space for 2 + 5 random scalars at max because there is no test vector with more
    union bbs_hash_context h_ctx;
    uint8_t randomness[7 * 48];
    int ret = BBS_OK;

    cipher_suite->expand_message_init(&h_ctx);
	cipher_suite->expand_message_update(&h_ctx, mocking_seed, mocking_seed_len);
	cipher_suite->expand_message_finalize(&h_ctx, randomness, (2 + num_blinded_messages) * 48, mocking_dst, mocking_dst_len);

    ret = bbs_blind_commit_with_nym_inner(
        cipher_suite,
        commitment_with_proof,
        secret_prover_blind,
        num_blinded_messages,
        messages,
        messages_lens,
        0,
        NULL,
        blind_commit_mocked_prf,
        randomness
    );

    return ret;
}

int blind_bbs_fix_commit(void) {
    for(size_t i=0; i < vectors_blind_commit_len; i++) {
		// Do not try to recreate invalid commits
		if(!vectors_blind_commit[i].result_valid) continue;
		uint8_t blind_commit[vectors_blind_commit[i].result_len];
        uint8_t secret_prover_blind[BBS_BLIND_SECRET_PROVER_BLIND_LEN];

		if (BBS_OK != mocked_bbs_blind_commit(*fixture_ciphersuite,
                    blind_commit,
                    secret_prover_blind,
                    vectors_blind_commit[i].num_committed_messages,
                    vectors_blind_commit[i].committed_msgs,
                    vectors_blind_commit[i].committed_msg_lens,
                    vectors_blind_commit[i].mocking_seed,
                    vectors_blind_commit[i].mocking_seed_len,
                    vectors_blind_commit[i].mocking_dst,
                    vectors_blind_commit[i].mocking_dst_len))
		{
			puts ("Error during blind commit generation");
			return 1;
		}

		ASSERT_EQ_PTR ("commit generation",
			       blind_commit,
			       vectors_blind_commit[i].result,
			       vectors_blind_commit[i].result_len);

        ASSERT_EQ_PTR ("commit generation secret_prover_blind",
			       secret_prover_blind,
			       vectors_blind_commit[i].prover_blind,
			       BBS_BLIND_SECRET_PROVER_BLIND_LEN);
	}


    return 0;
}
