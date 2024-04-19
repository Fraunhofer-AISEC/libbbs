#include "fixtures.h"
#include "test_util.h"
#include <string.h>

int
bbs_e2e_sign_n_proof ()
{
	int (*bbs_keygen_full[]) (
		bbs_secret_key      sk,
		bbs_public_key      pk
		) = {
		bbs_sha256_keygen_full, bbs_shake256_keygen_full
	};

	int (*sign[])(
		const bbs_secret_key  sk,
		const bbs_public_key  pk,
		bbs_signature         signature,
		const uint8_t        *header,
		uint64_t              header_len,
		uint64_t              num_messages,
		...
		) = {
		bbs_sha256_sign, bbs_shake256_sign
	};
	int (*verify[])(
		const bbs_public_key  pk,
		const bbs_signature   signature,
		const uint8_t        *header,
		uint64_t              header_len,
		uint64_t              num_messages,
		...
		) = {
		bbs_sha256_verify, bbs_shake256_verify
	};
	int (*proof_gen[])(
		const bbs_public_key  pk,
		const bbs_signature   signature,
		uint8_t              *proof,
		const uint8_t        *header,
		uint64_t              header_len,
		const uint8_t        *presentation_header,
		uint64_t              presentation_header_len,
		const uint64_t       *disclosed_indexes,
		uint64_t              disclosed_indexes_len,
		uint64_t              num_messages,
		...
		) = {
		bbs_sha256_proof_gen, bbs_shake256_proof_gen
	};
	int (*proof_verify[])(
		const bbs_public_key  pk,
		const uint8_t        *proof,
		uint64_t              proof_len,
		const uint8_t        *header,
		uint64_t              header_len,
		const uint8_t        *challenge,
		uint64_t              challenge_len,
		const uint64_t       *disclosed_indexes,
		uint64_t              num_disclosed_indexes,
		uint64_t              num_messages,
		...
		) = {
		bbs_sha256_proof_verify, bbs_shake256_proof_verify
	};

	for (int cipher_suite_index = 0; cipher_suite_index < 2; cipher_suite_index++)
	{
		char *cipher_suite_names[] = {"SHA256", "SHAKE256"};
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

		BBS_BENCH_START ()
		if (BBS_OK != bbs_keygen_full[cipher_suite_index] (sk, pk))
		{
			puts ("Error during key generation");
			return 1;
		}
		BBS_BENCH_END ("bbs_keygen_full")

		bbs_signature sig;
		static char msg1[]   = "I am a message";
		static char msg2[]   = "And so am I. Crazy...";
		static char header[] = "But I am a header!";

		BBS_BENCH_START ()
		if (BBS_OK != sign[cipher_suite_index] (sk, pk, sig, (uint8_t*) header, strlen (header), 2, msg1,
				       strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during signing");
			return 1;
		}
		BBS_BENCH_END ("bbs_sign (2 messages, 1 header)")

		BBS_BENCH_START ()
		if (BBS_OK != verify[cipher_suite_index] (pk, sig, (uint8_t*) header, strlen (header), 2, msg1,
					 strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during signature verification");
			return 1;
		}
		BBS_BENCH_END ("bbs_verify (2 messages, 1 header)")

		uint8_t proof[BBS_PROOF_LEN (1)];
		uint64_t    disclosed_indexes[] = {0};
		static char ph[]                = "I am a challenge nonce!";

		BBS_BENCH_START ()
		if (BBS_OK != proof_gen[cipher_suite_index] (pk, sig, proof, (uint8_t*) header, strlen (header),
					    (uint8_t*) ph, strlen (ph), disclosed_indexes, 1, 2,
					    msg1, strlen (msg1), msg2, strlen (msg2)))
		{
			puts ("Error during proof generation");
			return 1;
		}
		BBS_BENCH_END ("bbs_proof_gen (2 messages, 1 header, 1 disclosed index)")

		BBS_BENCH_START ()
		if (BBS_OK != proof_verify[cipher_suite_index] (pk, proof, BBS_PROOF_LEN (1), (uint8_t*) header,
					       strlen (header), (uint8_t*) ph, strlen (ph),
					       disclosed_indexes, 1, 2, msg1, strlen (msg1)))
		{
			puts ("Error during proof verification");
			return 1;
		}
		BBS_BENCH_END ("bbs_proof_verify (2 messages, 1 header, 1 disclosed index)")

	}
	return 0;
}
