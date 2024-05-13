#include "fixtures.h"
#include "test_util.h"
#include <string.h>

int
bbs_bench_e2e ()
{
	#define ITERATIONS_START 100
	#define ITERATIONS_END   110
	#define ITERATIONS_STEP  10
	#define MSG_LEN_START    1024
	#define MSG_LEN_END      135168
	#define MSG_LEN_STEP     1024
	#define USE_HEADER       0
	char msg1[MSG_LEN_END];
	char msg2[MSG_LEN_END];
	for (int j = 0; j < MSG_LEN_END; j++)
	{
		msg1[j] = (char) rand ();
		msg2[j] = (char) rand ();
	}
	for (int iterations_count = ITERATIONS_START;
	     iterations_count < ITERATIONS_END;
	     iterations_count += ITERATIONS_STEP)
	{
		for (int msg_len = MSG_LEN_START; msg_len < MSG_LEN_END; msg_len += MSG_LEN_STEP)
		{
			printf (
				"%d iterations BBS e2e sign and proof (2 messages, each %d bytes, include header %d, reveal message 0 (1/2).",
				iterations_count,
				msg_len,
				USE_HEADER);
			BBS_BENCH_START (e2e)

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

			for (int i = 0; i < iterations_count; i++)
			{
				bbs_secret_key sk;
				bbs_public_key pk;

				if (BBS_OK != bbs_sha256_keygen_full (sk, pk))
				{
					puts ("Error during key generation");
					return 1;
				}

				bbs_signature sig;
		#if USE_HEADER
				static char   header[] = "But I am a header!";
		#else
				static char   header[] = "";
		#endif

				if (BBS_OK != bbs_sha256_sign (sk, pk, sig, (uint8_t*) header,
							       strlen (header), 2, msg1, msg_len,
							       msg2, msg_len))
				{
					puts ("Error during signing");
					return 1;
				}

				if (BBS_OK != bbs_sha256_verify (pk, sig, (uint8_t*) header,
								 strlen (header), 2, msg1,
								 msg_len, msg2, msg_len))
				{
					puts ("Error during signature verification");
					return 1;
				}

				uint8_t     proof[BBS_PROOF_LEN (1)];
				uint64_t    disclosed_indexes[] = {0};
				static char ph[]                = "I am a challenge nonce!";

				if (BBS_OK != bbs_sha256_proof_gen (pk, sig, proof,
								    (uint8_t*) header,
								    strlen (header), (uint8_t*) ph,
								    strlen (ph), disclosed_indexes,
								    1, 2, msg1, msg_len, msg2,
								    msg_len))
				{
					puts ("Error during proof generation");
					return 1;
				}

				if (BBS_OK != bbs_sha256_proof_verify (pk, proof, BBS_PROOF_LEN (1),
								       (uint8_t*) header,
								       strlen (header),
								       (uint8_t*) ph, strlen (ph),
								       disclosed_indexes, 1, 2,
								       msg1, msg_len))
				{
					puts ("Error during proof verification");
					return 1;
				}
			}
			BBS_BENCH_END (e2e, "bbs_e2e_sign_n_proof")
		}
	}

	return 0;
}