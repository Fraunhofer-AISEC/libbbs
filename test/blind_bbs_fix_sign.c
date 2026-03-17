#include "fixtures.h"

int blind_bbs_fix_sign(void) {
	bbs_signature sig;

    for(size_t i=0; i < vectors_blind_signature_len; i++) {
        //printf("testing test vector %lu\n", i);

        if(vectors_blind_signature[i].result_valid) {
            // sign
            if (BBS_OK != bbs_blind_sign(*fixture_ciphersuite,
                    vectors_blind_signature[i].sk,
                    vectors_blind_signature[i].pk,
                    sig,
                    vectors_blind_signature[i].header,
                    vectors_blind_signature[i].header_len,
                    vectors_blind_signature[i].commitment_with_proof,
                    vectors_blind_signature[i].commitment_with_proof_len,
                    vectors_blind_signature[i].num_messages,
                    vectors_blind_signature[i].msgs,
                    vectors_blind_signature[i].msg_lens))
		    {
			    puts ("Error during blind signature generation");
			    return 1;
		    }

            ASSERT_EQ_PTR ("blind signature creation",
			       sig,
			       vectors_blind_signature[i].result,
			       sizeof(vectors_blind_signature[i].result));
        }

        if (vectors_blind_signature[i].result_valid != (BBS_OK == bbs_blind_verify(
            *fixture_ciphersuite,
            vectors_blind_signature[i].pk,
            sig,
            vectors_blind_signature[i].header,
            vectors_blind_signature[i].header_len,
            vectors_blind_signature[i].num_messages,
            vectors_blind_signature[i].msgs,
            vectors_blind_signature[i].msg_lens,
            vectors_blind_signature[i].num_committed_messages,
            vectors_blind_signature[i].committed_msgs,
            vectors_blind_signature[i].committed_msg_lens,
            vectors_blind_signature[i].prover_blind

        ))) {
            puts("failed blind signature verification");
            return 1;
        }
	}

    return 0;
}
