#include "fixtures.h"
#include "test_util.h"
#include <string.h>

int
bbs_e2e_sign_n_proof ()
{
	bbs_cipher_suite_t *cipher_suites[] = { bbs_sha256_cipher_suite, bbs_shake256_cipher_suite };

	for (int cipher_suite_index = 0; cipher_suite_index < 2; cipher_suite_index++)
	{
		char *cipher_suite_names[] = {"SHA256", "SHAKE256"};
		bbs_cipher_suite_t *suite = cipher_suites[cipher_suite_index];
		printf("Testing cipher suite %s\n", cipher_suite_names[cipher_suite_index]);
		if (core_init () != RLC_OK)
		{
			core_clean ();
			return 1;
		}
		if (pc_param_set_any () != RLC_OK)
		{
			core_clean ();
			return 1;
		}

		bbs_secret_key sk;
		bbs_public_key pk;

		BBS_BENCH_START (keygen)
		if (BBS_OK != bbs_keygen_full (suite, sk, pk))
		{
			puts ("Error during key generation");
			return 1;
		}
		BBS_BENCH_END (keygen, "bbs_keygen_full")

		bbs_signature sig;
		static char msg1[]   = "I am a message";
		static char msg2[]   = "And so am I. Crazy...";
		static char header[] = "But I am a header!";

		BBS_BENCH_START (sign)
		if (BBS_OK != bbs_sign (suite, sk, pk, sig, (uint8_t*) header, strlen (header), 2, msg1,
				       strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during signing");
			return 1;
		}
		BBS_BENCH_END (sign, "bbs_sign (2 messages, 1 header)")

		BBS_BENCH_START (verify)
		if (BBS_OK != bbs_verify (suite, pk, sig, (uint8_t*) header, strlen (header), 2, msg1,
					 strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during signature verification");
			return 1;
		}
		BBS_BENCH_END (verify, "bbs_verify (2 messages, 1 header)")

		uint8_t proof[BBS_PROOF_LEN (1)];
		uint64_t    disclosed_indexes[] = {0};
		static char ph[]                = "I am a challenge nonce!";

		BBS_BENCH_START (proof_gen)
		if (BBS_OK != bbs_proof_gen(suite, pk, sig, proof, (uint8_t*) header, strlen (header),
					    (uint8_t*) ph, strlen (ph), disclosed_indexes, 1, 2,
					    msg1, strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during proof generation");
			return 1;
		}
		BBS_BENCH_END (proof_gen, "bbs_proof_gen (2 messages, 1 header, 1 disclosed index)")

		BBS_BENCH_START (proof_verify)
		if (BBS_OK != bbs_proof_verify(suite, pk, proof, BBS_PROOF_LEN (1), (uint8_t*) header,
					       strlen (header), (uint8_t*) ph, strlen (ph),
					       disclosed_indexes, 1, 2, msg1, strlen (msg1)))
		{
			puts ("Error during proof verification");
			return 1;
		}
		BBS_BENCH_END (proof_verify, "bbs_proof_verify (2 messages, 1 header, 1 disclosed index)")

	}
	return 0;
}
