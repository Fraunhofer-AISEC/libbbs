#include "fixtures.h"
#include "test_util.h"
#include <string.h>

int bbs_e2e_sign_n_proof() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	bbs_secret_key sk;
	bbs_public_key pk;

        BBS_BENCH_START()
	if(BBS_OK != bbs_keygen_full(sk, pk)) {
		puts("Error during key generation");
		return 1;
	}
        BBS_BENCH_END("bbs_keygen_full")

	bbs_signature sig;
	static char msg1[] = "I am a message";
	static char msg2[] = "And so am I. Crazy...";
	static char header[] = "But I am a header!";

        BBS_BENCH_START()
	if(BBS_OK != bbs_sign(
				sk,
				pk,
				sig,
				(uint8_t*)header,
				strlen(header),
				2,
				msg1,
				strlen(msg1),
				msg2,
				strlen(msg2))) {
		puts("Error during signing");
		return 1;
	}
        BBS_BENCH_END("bbs_sign (2 messages, 1 header)")

        BBS_BENCH_START()
	if(BBS_OK != bbs_verify(
				pk,
				sig,
				(uint8_t*)header,
				strlen(header),
				2,
				msg1,
				strlen(msg1),
				msg2,
				strlen(msg2))) {
		puts("Error during signature verification");
		return 1;
	}
        BBS_BENCH_END("bbs_verify (2 messages, 1 header)")

	uint8_t  proof[BBS_PROOF_LEN(1)];
	uint64_t disclosed_indexes[] = {0};
	static char ph[] = "I am a challenge nonce!";

        BBS_BENCH_START()
	if(BBS_OK != bbs_proof_gen(
				pk,
				sig,
				proof,
				(uint8_t*)header,
				strlen(header),
				(uint8_t*)ph,
				strlen(ph),
				disclosed_indexes,
				1,
				2,
				msg1,
				strlen(msg1),
				msg2,
				strlen(msg2))) {
		puts("Error during proof generation");
		return 1;
	}
        BBS_BENCH_END("bbs_proof_gen (2 messages, 1 header, 1 disclosed index)")

        BBS_BENCH_START()
	if(BBS_OK != bbs_proof_verify(
				pk,
				proof,
				BBS_PROOF_LEN(1),
				(uint8_t*)header,
				strlen(header),
				(uint8_t*)ph,
				strlen(ph),
				disclosed_indexes,
				1,
				2,
				msg1,
				strlen(msg1))) {
		puts("Error during proof verification");
		return 1;
	}
        BBS_BENCH_END("bbs_proof_verify (2 messages, 1 header, 1 disclosed index)")

	return 0;
}

