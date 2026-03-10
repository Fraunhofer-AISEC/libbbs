// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <string.h>

int
bbs_e2e_sign_n_proof ()
{
	const bbs_ciphersuite *suite = *fixture_ciphersuite;

	bbs_secret_key sk;
	bbs_public_key pk;

	if (BBS_OK != bbs_keygen_full (suite, sk, pk))
	{
		puts ("Error during key generation");
		return 1;
	}

	bbs_signature sig;
	static char msg1[]   = "I am a message";
	static char msg2[]   = "And so am I. Crazy...";
	static char header[] = "But I am a header!";

	if (BBS_OK != bbs_sign_v (suite, sk, pk, sig, BBS_SMSG(header),
				BBS_SMSG(msg1), BBS_SMSG(msg2)))
	{
		puts ("Error during signing");
		return 1;
	}

	if (BBS_OK != bbs_verify_v (suite, pk, sig, BBS_SMSG(header),
				BBS_SMSG(msg1), BBS_SMSG(msg2)))
	{
		puts ("Error during signature verification");
		return 1;
	}

	uint8_t proof[BBS_PROOF_LEN (1)];
	size_t disclosed_indexes[] = {0};
	static char ph[]                = "I am a challenge nonce!";

	if (BBS_OK != bbs_proof_gen_v(suite, pk, sig, BBS_OUTMSG(proof, sizeof(proof)),
				BBS_SMSG(header), BBS_SMSG(ph), disclosed_indexes, 1,
				BBS_SMSG(msg1), BBS_SMSG(msg2)))
	{
		puts ("Error during proof generation");
		return 1;
	}

	if (BBS_OK != bbs_proof_verify_v(suite, pk, BBS_MSG(proof, sizeof(proof)),
				BBS_SMSG(header), BBS_SMSG(ph), disclosed_indexes, 1,
				BBS_SMSG(msg1), BBS_UNDISCLOSED_MSG))
	{
		puts ("Error during proof verification");
		return 1;
	}
	return 0;
}
