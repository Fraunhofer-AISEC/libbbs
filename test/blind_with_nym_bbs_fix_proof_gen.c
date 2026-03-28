#include "fixtures.h"
#include "bbs_util.h"

// forward declaration
int
bbs_blind_proof_gen_with_nym_inner(
    const bbs_ciphersuite  *s,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    void                   *proof,                  // OUT
    bbs_pseudonym           pseudonym,              // OUT
    const void             *header,
    size_t                  header_len,
    const void             *presentation_header,
    size_t                  presentation_header_len,
    const void             *context_id,
    size_t                  context_id_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens,
    size_t                  num_committed_messages,
    const void *const      *committed_messages,
    const size_t           *committed_message_lens,
    size_t                  num_disclosed_indexes,
    const size_t           *disclosed_indexes,
    size_t                  num_disclosed_committed_indexes,
    const size_t           *disclosed_committed_indexes,
    const uint8_t          *secret_prover_blind,    // optional, NULL = zero
    size_t                  num_nym_secrets,
    const void *const      *nym_secrets,
    bbs_bn_prf              prf,
    void                   *prf_cookie
);

void bbs_blind_proof_gen_with_nym_prf(
	const bbs_ciphersuite   *cipher_suite,
	blst_scalar             *out,
	uint8_t                 input_type,
	uint64_t                input,
	void                    *cookie
) {
    // input_type 0: input=0=r1 input=1=r2 input=2=e~ input=3=r1~ input=4=r2~
    // input_type 1: input=i=m~_i

	(void)cipher_suite;
	uint8_t *rand = (uint8_t*) cookie;

    if (input_type == 0) {
        rand += (input * 48);
    }

    if (input_type == 1) {
        rand += (5 * 48) + (input * 48);
    }

	blst_scalar_from_be_bytes(out, rand, 48);
}

int
bbs_blind_proof_gen_with_nym_mock(
    const bbs_ciphersuite  *cipher_suite,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    void                   *proof,                  // OUT
    bbs_pseudonym           pseudonym,              // OUT
    const void             *header,
    size_t                  header_len,
    const void             *presentation_header,
    size_t                  presentation_header_len,
    const void             *context_id,
    size_t                  context_id_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens,
    size_t                  num_committed_messages,
    const void *const      *committed_messages,
    const size_t           *committed_message_lens,
    size_t                  num_disclosed_indexes,
    const size_t           *disclosed_indexes,
    size_t                  num_disclosed_committed_indexes,
    const size_t           *disclosed_committed_indexes,
    const uint8_t          *secret_prover_blind,    // optional, NULL = zero
    size_t                  num_nym_secrets,
    const void *const      *nym_secrets,
    const void             *mocking_seed,
	size_t                  mocking_seed_len,
	const void             *mocking_dst,
	size_t                  mocking_dst_len
) {
    // space for 5 + n random scalars at max
    union bbs_hash_context h_ctx;
    size_t count = 5;
    count += num_messages - num_disclosed_indexes;
    count += num_committed_messages - num_disclosed_committed_indexes;
    count += 1; // secret_prover_blind
    count += num_nym_secrets;
    uint8_t seed[count * 48];
    int ret = BBS_OK;

    //printf("rnd mock count = %ld\n", count);
    //printf("rnd mock seed = %.*s\n", (int)mocking_seed_len, (char*)mocking_seed);
    //printf("rnd mock dst = %.*s\n", (int)mocking_dst_len, (char*)mocking_dst);

    cipher_suite->expand_message_init(&h_ctx);
	cipher_suite->expand_message_update(&h_ctx, mocking_seed, mocking_seed_len);
	cipher_suite->expand_message_finalize(&h_ctx, seed, count * 48, mocking_dst, mocking_dst_len);

    ret = bbs_blind_proof_gen_with_nym_inner(
        cipher_suite,
        pk,
        signature,
        proof,
        pseudonym,
        header,
        header_len,
        presentation_header,
        presentation_header_len,
        context_id,
        context_id_len,
        num_messages,
        messages,
        message_lens,
        num_committed_messages,
        committed_messages,
        committed_message_lens,
        num_disclosed_indexes,
        disclosed_indexes,
        num_disclosed_committed_indexes,
        disclosed_committed_indexes,
        secret_prover_blind,
        num_nym_secrets,
        nym_secrets,
        bbs_blind_proof_gen_with_nym_prf,
        seed
    );

    return ret;
}

int blind_with_nym_bbs_fix_proof_gen(void) {
	for(size_t i=0; i < vectors_blind_with_nym_proof_len; i++) {
		uint8_t proof[vectors_blind_with_nym_proof[i].result_len];
        bbs_pseudonym nym;

        printf("\nBLIND PROOF GEN WITH NYM %lu\n\n", i);

        // only generate valid proofs
		if (vectors_blind_with_nym_proof[i].result_valid &&
            BBS_OK != bbs_blind_proof_gen_with_nym_mock(*fixture_ciphersuite,
					vectors_blind_with_nym_proof[i].pk,
					vectors_blind_with_nym_proof[i].signature,
					proof,
                    nym,
					vectors_blind_with_nym_proof[i].header,
					vectors_blind_with_nym_proof[i].header_len,
					vectors_blind_with_nym_proof[i].presentation_header,
					vectors_blind_with_nym_proof[i].presentation_header_len,
					vectors_blind_with_nym_proof[i].context_id,
					vectors_blind_with_nym_proof[i].context_id_len,
                    vectors_blind_with_nym_proof[i].num_messages,
					vectors_blind_with_nym_proof[i].msgs,
					vectors_blind_with_nym_proof[i].msg_lens,
                    vectors_blind_with_nym_proof[i].num_committed_messages,
					vectors_blind_with_nym_proof[i].committed_msgs,
					vectors_blind_with_nym_proof[i].committed_msg_lens,
					vectors_blind_with_nym_proof[i].disclosed_indexes_len,
					vectors_blind_with_nym_proof[i].disclosed_indexes,
					vectors_blind_with_nym_proof[i].disclosed_committed_indexes_len,
                    vectors_blind_with_nym_proof[i].disclosed_committed_indexes,
					vectors_blind_with_nym_proof[i].prover_blind,
					vectors_blind_with_nym_proof[i].num_nym_secrets,
					vectors_blind_with_nym_proof[i].nym_secrets,
					vectors_blind_with_nym_proof[i].proof_mocking_seed,
					vectors_blind_with_nym_proof[i].proof_mocking_seed_len,
					vectors_blind_with_nym_proof[i].proof_mocking_dst,
					vectors_blind_with_nym_proof[i].proof_mocking_dst_len))
		{
			puts ("Error during blind proof with nym generation");
			return 1;
		}

		ASSERT_EQ_PTR ("blind proof with nym generation",
			       proof,
			       vectors_blind_with_nym_proof[i].result,
			       vectors_blind_with_nym_proof[i].result_len);

        ASSERT_EQ_PTR ("blind proof with nym generation pseudonym",
			       nym, vectors_blind_with_nym_proof[i].pseudonym, 48);

        printf("\nBLIND PROOF VERIFY WITH NYM %lu\n\n", i);

        if (vectors_blind_with_nym_proof[i].result_valid !=
            (BBS_OK == bbs_blind_proof_verify_with_nym(
                *fixture_ciphersuite,
                vectors_blind_with_nym_proof[i].pk,
                nym,
                proof,
                vectors_blind_with_nym_proof[i].result_len,

                vectors_blind_with_nym_proof[i].header,
                vectors_blind_with_nym_proof[i].header_len,
                vectors_blind_with_nym_proof[i].presentation_header,
                vectors_blind_with_nym_proof[i].presentation_header_len,

                vectors_blind_with_nym_proof[i].context_id,
				vectors_blind_with_nym_proof[i].context_id_len,
				vectors_blind_with_nym_proof[i].num_prover_nyms,
				vectors_blind_with_nym_proof[i].L,

                vectors_blind_with_nym_proof[i].disclosed_indexes_len,
                vectors_blind_with_nym_proof[i].disclosed_msgs,
                vectors_blind_with_nym_proof[i].disclosed_msg_lens,
                vectors_blind_with_nym_proof[i].disclosed_indexes,

                vectors_blind_with_nym_proof[i].disclosed_committed_indexes_len,
                vectors_blind_with_nym_proof[i].disclosed_committed_msgs,
                vectors_blind_with_nym_proof[i].disclosed_committed_msg_lens,
                vectors_blind_with_nym_proof[i].disclosed_committed_indexes
        ))) {
            puts("failed blind proof with nym verification");
            return 1;
        }
	}

    return 0;
}
