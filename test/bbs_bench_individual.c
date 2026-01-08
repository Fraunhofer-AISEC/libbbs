// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#define BBS_NO_UTIL
#include "test_util.h"
#include <string.h>
#include <stdlib.h>

#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY (x)

int
bbs_bench_individual ()
{
	const bbs_ciphersuite *cipher_suite = *fixture_ciphersuite;

	#define USE_HEADER                          0

	printf ("Include header: %d \n", USE_HEADER);

	#define ITERATIONS 1000

	// - MARK: Key generation
	bbs_secret_key sk[ITERATIONS];
	bbs_public_key pk[ITERATIONS];

	printf ("key generation %d iterations.\n", ITERATIONS);

	BBS_BENCH_START (key_gen)
	for (int i = 0; i < ITERATIONS; i++)
	{
		if (BBS_OK != bbs_keygen_full (cipher_suite, sk[i], pk[i]))
		{
			puts ("Error during key generation");
			return 1;
		}
	}
	BBS_BENCH_END (key_gen, "Key generation (SK & PK)")

	// - MARK: Signing

	#define MSG_LEN 64

	char msg1[ITERATIONS][MSG_LEN];
	char          msg2[ITERATIONS][MSG_LEN];
	bbs_signature sig[ITERATIONS];

	for (int i = 0; i < ITERATIONS; i++)
	{
		for (int j = 0; j < MSG_LEN; j++)
		{
			msg1[i][j] = (char) rand ();
			msg2[i][j] = (char) rand ();
		}
	}
	#if USE_HEADER
	static char header[] = "But I am a header!";
	#else
	static char header[] = "";
	#endif

	printf ("signing %d iterations of %d messages each of size %d bytes.\n",
		ITERATIONS, 2, MSG_LEN);

	BBS_BENCH_START (sign)
	for (int i = 0; i < ITERATIONS; i++)
	{
		if (BBS_OK != bbs_sign_v (cipher_suite, sk[i], pk[i], sig[i],
							       (uint8_t*) header, strlen (header),
							       2, msg1[i], MSG_LEN, msg2[i],
							       MSG_LEN))
		{
			puts ("Error during signing");
			return 1;
		}
	}
	BBS_BENCH_END (sign, "Signing")

	// - MARK: Verification
	printf ("verification %d iterations of %d messages each of size %d bytes.\n",
		ITERATIONS, 2, MSG_LEN);
	BBS_BENCH_START (verify)
	for (int i = 0; i < ITERATIONS; i++)
	{
		if (BBS_OK != bbs_verify_v (cipher_suite, pk[i], sig[i], (uint8_t*) header, strlen (header),
						 2, msg1[i], MSG_LEN, msg2[i], MSG_LEN))
		{
			puts ("Error during signature verification");
			return 1;
		}
	}
	BBS_BENCH_END (verify, "Verification")

	// - MARK: Proof generation
	uint8_t proof[ITERATIONS][BBS_PROOF_LEN (1)];
	size_t       disclosed_indexes[] = {0};
	#define RANDOM_NONCE_SIZE 23
	static uint8_t random_nonces[ITERATIONS][RANDOM_NONCE_SIZE];
	for (int i = 0; i < ITERATIONS; i++)
	{
		for (int j = 0; j < 23; j++)
		{
			random_nonces[i][j] = (uint8_t) rand ();
		}
	}

	printf (
		"proof generation %d iterations of %d messages each of size %d bytes disclosing first message only.\n",
		ITERATIONS,
		2,
		MSG_LEN);
	BBS_BENCH_START (proof_gen)
	for (int i = 0; i < ITERATIONS; i++)
	{
		if (BBS_OK != bbs_proof_gen_v (cipher_suite, pk[i], sig[i], proof[i],
								    (uint8_t*) header,
								    strlen (header),
								    (uint8_t*) random_nonces[i],
								    RANDOM_NONCE_SIZE,
								    disclosed_indexes, 1, 2,
								    msg1[i], MSG_LEN, msg2[i],
								    MSG_LEN))
		{
			puts ("Error during proof generation");
			return 1;
		}
	}
	BBS_BENCH_END (proof_gen, "Proof generation")

	// - MARK: Proof verification
	printf (
		"proof verification %d iterations of %d messages each of size %d bytes disclosing first message only.\n",
		ITERATIONS,
		2,
		MSG_LEN);
	BBS_BENCH_START (proof_verify)
	for (int i = 0; i < ITERATIONS; i++)
	{
		if (BBS_OK != bbs_proof_verify_v (cipher_suite, pk[i], proof[i], BBS_PROOF_LEN (1),
						       (uint8_t*) header, strlen (header),
						       (uint8_t*) random_nonces[i],
						       RANDOM_NONCE_SIZE, disclosed_indexes, 1, 2,
						       msg1[i], MSG_LEN))
		{
			puts ("Error during proof verification");
			return 1;
		}
	}
	BBS_BENCH_END (proof_verify, "Proof verification")

	return 0;
}
