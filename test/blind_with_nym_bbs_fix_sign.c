#include "fixtures.h"

int blind_with_nym_bbs_fix_sign(void) {
	bbs_signature sig;

    for(size_t i=0; i < vectors_blind_with_nym_signature_len; i++) {
        //printf("testing test vector %lu\n", i);

        if(vectors_blind_with_nym_signature[i].result_valid) {
            // sign
            if (BBS_OK != bbs_blind_sign_with_nym(*fixture_ciphersuite,
                    vectors_blind_with_nym_signature[i].sk,
                    vectors_blind_with_nym_signature[i].pk,
                    vectors_blind_with_nym_signature[i].signer_nym_entropy,
                    vectors_blind_with_nym_signature[i].num_prover_nyms,
                    sig,
                    vectors_blind_with_nym_signature[i].commitment_with_proof_len,
                    vectors_blind_with_nym_signature[i].commitment_with_proof,
                    vectors_blind_with_nym_signature[i].header_len,
                    vectors_blind_with_nym_signature[i].header,
                    vectors_blind_with_nym_signature[i].num_messages,
                    vectors_blind_with_nym_signature[i].msgs,
                    vectors_blind_with_nym_signature[i].msg_lens))
		    {
			    puts ("Error during blind with nym signature generation");
			    return 1;
		    }

            ASSERT_EQ_PTR ("blind with nym signature creation",
			       sig,
			       vectors_blind_with_nym_signature[i].result,
			       sizeof(vectors_blind_with_nym_signature[i].result));
        }

        uint8_t nym_secret_bufs[vectors_blind_with_nym_signature[i].num_nym_secrets][32];
        void *nym_secret_ptrs[vectors_blind_with_nym_signature[i].num_prover_nyms];
        for(size_t k = 0; k < vectors_blind_with_nym_signature[i].num_prover_nyms; k++)
            nym_secret_ptrs[k] = nym_secret_bufs[k];

        if (vectors_blind_with_nym_signature[i].result_valid != (
            // verify
            BBS_OK == bbs_blind_verify_with_nym(
                *fixture_ciphersuite,
                vectors_blind_with_nym_signature[i].pk,
                sig,
                vectors_blind_with_nym_signature[i].header_len,
                vectors_blind_with_nym_signature[i].header,
                vectors_blind_with_nym_signature[i].num_messages,
                vectors_blind_with_nym_signature[i].msgs,
                vectors_blind_with_nym_signature[i].msg_lens,
                vectors_blind_with_nym_signature[i].num_committed_messages,
                vectors_blind_with_nym_signature[i].committed_msgs,
                vectors_blind_with_nym_signature[i].committed_msg_lens,
                vectors_blind_with_nym_signature[i].prover_blind,
                vectors_blind_with_nym_signature[i].signer_nym_entropy,
                vectors_blind_with_nym_signature[i].num_prover_nyms,
                vectors_blind_with_nym_signature[i].prover_nyms,
                nym_secret_ptrs
        ))) {
            puts("failed blind with nym signature verification");
            return 1;
        }

        for(size_t k = 0; k < vectors_blind_with_nym_signature[i].num_nym_secrets; k++) {
            ASSERT_EQ_PTR("blind with nym signature verification nym_secrets",
                nym_secret_bufs[k],
                vectors_blind_with_nym_signature[i].nym_secrets[k],
                32);
        }
	}

    return 0;
}
