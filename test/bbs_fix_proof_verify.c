#include "fixtures.h"
#include "test_util.h"

typedef struct
{
	bbs_cipher_suite_t *cipher_suite;
	uint8_t  *proof_SEED;
	size_t    proof_SEED_len;
	uint8_t  *proof_DST;
	size_t    proof_DST_len;
	uint8_t  *proof_random_scalar_1;
	size_t    proof_random_scalar_1_len;
	uint8_t  *proof_random_scalar_2;
	size_t    proof_random_scalar_2_len;
	uint8_t  *proof_random_scalar_3;
	size_t    proof_random_scalar_3_len;
	uint8_t  *proof_random_scalar_4;
	size_t    proof_random_scalar_4_len;
	uint8_t  *proof_random_scalar_5;
	size_t    proof_random_scalar_5_len;
	uint8_t  *proof_random_scalar_6;
	size_t    proof_random_scalar_6_len;
	uint8_t  *proof_random_scalar_7;
	size_t    proof_random_scalar_7_len;
	uint8_t  *proof_random_scalar_8;
	size_t    proof_random_scalar_8_len;
	uint8_t  *proof_random_scalar_9;
	size_t    proof_random_scalar_9_len;
	uint8_t  *proof_random_scalar_10;
	size_t    proof_random_scalar_10_len;

	uint8_t  *proof1_public_key;
	uint8_t  *proof1_signature;
	size_t    proof1_signature_len;
	uint8_t  *proof1_header;
	size_t    proof1_header_len;
	uint8_t  *proof1_presentation_header;
	size_t    proof1_presentation_header_len;
	uint64_t *proof1_revealed_indexes;
	size_t    proof1_revealed_indexes_len;
	uint8_t  *proof1_m_1;
	size_t    proof1_m_1_len;
	uint8_t  *proof1_proof;
	size_t    proof1_proof_len;

	uint8_t  *proof2_public_key;
	uint8_t  *proof2_signature;
	size_t    proof2_signature_len;
	uint8_t  *proof2_header;
	size_t    proof2_header_len;
	uint8_t  *proof2_presentation_header;
	size_t    proof2_presentation_header_len;
	uint64_t *proof2_revealed_indexes;
	size_t    proof2_revealed_indexes_len;
	uint8_t  *proof2_m_1;
	size_t    proof2_m_1_len;
	uint8_t  *proof2_m_2;
	size_t    proof2_m_2_len;
	uint8_t  *proof2_m_3;
	size_t    proof2_m_3_len;
	uint8_t  *proof2_m_4;
	size_t    proof2_m_4_len;
	uint8_t  *proof2_m_5;
	size_t    proof2_m_5_len;
	uint8_t  *proof2_m_6;
	size_t    proof2_m_6_len;
	uint8_t  *proof2_m_7;
	size_t    proof2_m_7_len;
	uint8_t  *proof2_m_8;
	size_t    proof2_m_8_len;
	uint8_t  *proof2_m_9;
	size_t    proof2_m_9_len;
	uint8_t  *proof2_m_10;
	size_t    proof2_m_10_len;
	uint8_t  *proof2_proof;
	size_t    proof2_proof_len;

	uint8_t  *proof3_public_key;
	uint8_t  *proof3_signature;
	size_t    proof3_signature_len;
	uint8_t  *proof3_header;
	size_t    proof3_header_len;
	uint8_t  *proof3_presentation_header;
	size_t    proof3_presentation_header_len;
	uint64_t *proof3_revealed_indexes;
	size_t    proof3_revealed_indexes_len;
	uint8_t  *proof3_proof;
	size_t    proof3_proof_len;
	uint8_t  *proof3_m_1;
	size_t    proof3_m_1_len;
	uint8_t  *proof3_m_3;
	size_t    proof3_m_3_len;
	uint8_t  *proof3_m_5;
	size_t    proof3_m_5_len;
	uint8_t  *proof3_m_7;
	size_t    proof3_m_7_len;
} proof_fixture_t;

static const char *suite_names[] = {
	"BLS12_381_SHA256",
	"BLS12_381_SHAKE256"
};

int
bbs_fix_proof_verify ()
{
	// *INDENT-OFF* - Preserve formatting
	proof_fixture_t test_cases[] = {
		{
			.cipher_suite = bbs_sha256_cipher_suite,
			.proof_SEED = fixture_bls12_381_sha_256_proof_SEED,
			.proof_SEED_len = sizeof(fixture_bls12_381_sha_256_proof_SEED),
			.proof_DST = fixture_bls12_381_sha_256_proof_DST,
			.proof_DST_len = sizeof(fixture_bls12_381_sha_256_proof_DST),
			.proof_random_scalar_1 = fixture_bls12_381_sha_256_proof_random_scalar_1,
			.proof_random_scalar_1_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_1),
			.proof_random_scalar_2 = fixture_bls12_381_sha_256_proof_random_scalar_2,
			.proof_random_scalar_2_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_2),
			.proof_random_scalar_3 = fixture_bls12_381_sha_256_proof_random_scalar_3,
			.proof_random_scalar_3_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_3),
			.proof_random_scalar_4 = fixture_bls12_381_sha_256_proof_random_scalar_4,
			.proof_random_scalar_4_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_4),
			.proof_random_scalar_5 = fixture_bls12_381_sha_256_proof_random_scalar_5,
			.proof_random_scalar_5_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_5),
			.proof_random_scalar_6 = fixture_bls12_381_sha_256_proof_random_scalar_6,
			.proof_random_scalar_6_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_6),
			.proof_random_scalar_7 = fixture_bls12_381_sha_256_proof_random_scalar_7,
			.proof_random_scalar_7_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_7),
			.proof_random_scalar_8 = fixture_bls12_381_sha_256_proof_random_scalar_8,
			.proof_random_scalar_8_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_8),
			.proof_random_scalar_9 = fixture_bls12_381_sha_256_proof_random_scalar_9,
			.proof_random_scalar_9_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_9),
			.proof_random_scalar_10 = fixture_bls12_381_sha_256_proof_random_scalar_10,
			.proof_random_scalar_10_len = sizeof(fixture_bls12_381_sha_256_proof_random_scalar_10),

			.proof1_public_key = fixture_bls12_381_sha_256_proof1_public_key,
			.proof1_signature = fixture_bls12_381_sha_256_proof1_signature,
			.proof1_signature_len = sizeof(fixture_bls12_381_sha_256_proof1_signature),
			.proof1_header = fixture_bls12_381_sha_256_proof1_header,
			.proof1_header_len = sizeof(fixture_bls12_381_sha_256_proof1_header),
			.proof1_presentation_header = fixture_bls12_381_sha_256_proof1_presentation_header,
			.proof1_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof1_presentation_header),
			.proof1_revealed_indexes = fixture_bls12_381_sha_256_proof1_revealed_indexes,
			.proof1_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof1_revealed_indexes),
			.proof1_m_1 = fixture_bls12_381_sha_256_proof1_m_1,
			.proof1_m_1_len = sizeof(fixture_bls12_381_sha_256_proof1_m_1),
			.proof1_proof = fixture_bls12_381_sha_256_proof1_proof,
			.proof1_proof_len = sizeof(fixture_bls12_381_sha_256_proof1_proof),

			.proof2_public_key = fixture_bls12_381_sha_256_proof2_public_key,
			.proof2_signature = fixture_bls12_381_sha_256_proof2_signature,
			.proof2_signature_len = sizeof(fixture_bls12_381_sha_256_proof2_signature),
			.proof2_header = fixture_bls12_381_sha_256_proof2_header,
			.proof2_header_len = sizeof(fixture_bls12_381_sha_256_proof2_header),
			.proof2_presentation_header = fixture_bls12_381_sha_256_proof2_presentation_header,
			.proof2_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof2_presentation_header),
			.proof2_revealed_indexes = fixture_bls12_381_sha_256_proof2_revealed_indexes,
			.proof2_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof2_revealed_indexes),
			.proof2_m_1 = fixture_bls12_381_sha_256_proof2_m_1,
			.proof2_m_1_len = sizeof(fixture_bls12_381_sha_256_proof2_m_1),
			.proof2_m_2 = fixture_bls12_381_sha_256_proof2_m_2,
			.proof2_m_2_len = sizeof(fixture_bls12_381_sha_256_proof2_m_2),
			.proof2_m_3 = fixture_bls12_381_sha_256_proof2_m_3,
			.proof2_m_3_len = sizeof(fixture_bls12_381_sha_256_proof2_m_3),
			.proof2_m_4 = fixture_bls12_381_sha_256_proof2_m_4,
			.proof2_m_4_len = sizeof(fixture_bls12_381_sha_256_proof2_m_4),
			.proof2_m_5 = fixture_bls12_381_sha_256_proof2_m_5,
			.proof2_m_5_len = sizeof(fixture_bls12_381_sha_256_proof2_m_5),
			.proof2_m_6 = fixture_bls12_381_sha_256_proof2_m_6,
			.proof2_m_6_len = sizeof(fixture_bls12_381_sha_256_proof2_m_6),
			.proof2_m_7 = fixture_bls12_381_sha_256_proof2_m_7,
			.proof2_m_7_len = sizeof(fixture_bls12_381_sha_256_proof2_m_7),
			.proof2_m_8 = fixture_bls12_381_sha_256_proof2_m_8,
			.proof2_m_8_len = sizeof(fixture_bls12_381_sha_256_proof2_m_8),
			.proof2_m_9 = fixture_bls12_381_sha_256_proof2_m_9,
			.proof2_m_9_len = sizeof(fixture_bls12_381_sha_256_proof2_m_9),
			.proof2_m_10 = fixture_bls12_381_sha_256_proof2_m_10,
			.proof2_m_10_len = sizeof(fixture_bls12_381_sha_256_proof2_m_10),
			.proof2_proof = fixture_bls12_381_sha_256_proof2_proof,
			.proof2_proof_len = sizeof(fixture_bls12_381_sha_256_proof2_proof),

			.proof3_public_key = fixture_bls12_381_sha_256_proof3_public_key,
			.proof3_signature = fixture_bls12_381_sha_256_proof3_signature,
			.proof3_signature_len = sizeof(fixture_bls12_381_sha_256_proof3_signature),
			.proof3_header = fixture_bls12_381_sha_256_proof3_header,
			.proof3_header_len = sizeof(fixture_bls12_381_sha_256_proof3_header),
			.proof3_presentation_header = fixture_bls12_381_sha_256_proof3_presentation_header,
			.proof3_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
			.proof3_revealed_indexes = fixture_bls12_381_sha_256_proof3_revealed_indexes,
			.proof3_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof3_revealed_indexes),
			.proof3_proof = fixture_bls12_381_sha_256_proof3_proof,
			.proof3_proof_len = sizeof(fixture_bls12_381_sha_256_proof3_proof),
			.proof3_m_1 = fixture_bls12_381_sha_256_proof3_m_1,
			.proof3_m_1_len = sizeof(fixture_bls12_381_sha_256_proof3_m_1),
			.proof3_m_3 = fixture_bls12_381_sha_256_proof3_m_3,
			.proof3_m_3_len = sizeof(fixture_bls12_381_sha_256_proof3_m_3),
			.proof3_m_5 = fixture_bls12_381_sha_256_proof3_m_5,
			.proof3_m_5_len = sizeof(fixture_bls12_381_sha_256_proof3_m_5),
			.proof3_m_7 = fixture_bls12_381_sha_256_proof3_m_7,
			.proof3_m_7_len = sizeof(fixture_bls12_381_sha_256_proof3_m_7),
		},
		{
			.cipher_suite = bbs_shake256_cipher_suite,
			.proof_SEED = fixture_bls12_381_shake_256_proof_SEED,
			.proof_SEED_len = sizeof(fixture_bls12_381_shake_256_proof_SEED),
			.proof_DST = fixture_bls12_381_shake_256_proof_DST,
			.proof_DST_len = sizeof(fixture_bls12_381_shake_256_proof_DST),
			.proof_random_scalar_1 = fixture_bls12_381_shake_256_proof_random_scalar_1,
			.proof_random_scalar_1_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_1),
			.proof_random_scalar_2 = fixture_bls12_381_shake_256_proof_random_scalar_2,
			.proof_random_scalar_2_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_2),
			.proof_random_scalar_3 = fixture_bls12_381_shake_256_proof_random_scalar_3,
			.proof_random_scalar_3_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_3),
			.proof_random_scalar_4 = fixture_bls12_381_shake_256_proof_random_scalar_4,
			.proof_random_scalar_4_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_4),
			.proof_random_scalar_5 = fixture_bls12_381_shake_256_proof_random_scalar_5,
			.proof_random_scalar_5_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_5),
			.proof_random_scalar_6 = fixture_bls12_381_shake_256_proof_random_scalar_6,
			.proof_random_scalar_6_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_6),
			.proof_random_scalar_7 = fixture_bls12_381_shake_256_proof_random_scalar_7,
			.proof_random_scalar_7_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_7),
			.proof_random_scalar_8 = fixture_bls12_381_shake_256_proof_random_scalar_8,
			.proof_random_scalar_8_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_8),
			.proof_random_scalar_9 = fixture_bls12_381_shake_256_proof_random_scalar_9,
			.proof_random_scalar_9_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_9),
			.proof_random_scalar_10 = fixture_bls12_381_shake_256_proof_random_scalar_10,
			.proof_random_scalar_10_len = sizeof(fixture_bls12_381_shake_256_proof_random_scalar_10),

			.proof1_public_key = fixture_bls12_381_shake_256_proof1_public_key,
			.proof1_signature = fixture_bls12_381_shake_256_proof1_signature,
			.proof1_signature_len = sizeof(fixture_bls12_381_shake_256_proof1_signature),
			.proof1_header = fixture_bls12_381_shake_256_proof1_header,
			.proof1_header_len = sizeof(fixture_bls12_381_shake_256_proof1_header),
			.proof1_presentation_header = fixture_bls12_381_shake_256_proof1_presentation_header,
			.proof1_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof1_presentation_header),
			.proof1_revealed_indexes = fixture_bls12_381_shake_256_proof1_revealed_indexes,
			.proof1_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof1_revealed_indexes),
			.proof1_m_1 = fixture_bls12_381_shake_256_proof1_m_1,
			.proof1_m_1_len = sizeof(fixture_bls12_381_shake_256_proof1_m_1),
			.proof1_proof = fixture_bls12_381_shake_256_proof1_proof,
			.proof1_proof_len = sizeof(fixture_bls12_381_shake_256_proof1_proof),

			.proof2_public_key = fixture_bls12_381_shake_256_proof2_public_key,
			.proof2_signature = fixture_bls12_381_shake_256_proof2_signature,
			.proof2_signature_len = sizeof(fixture_bls12_381_shake_256_proof2_signature),
			.proof2_header = fixture_bls12_381_shake_256_proof2_header,
			.proof2_header_len = sizeof(fixture_bls12_381_shake_256_proof2_header),
			.proof2_presentation_header = fixture_bls12_381_shake_256_proof2_presentation_header,
			.proof2_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof2_presentation_header),
			.proof2_revealed_indexes = fixture_bls12_381_shake_256_proof2_revealed_indexes,
			.proof2_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof2_revealed_indexes),
			.proof2_m_1 = fixture_bls12_381_shake_256_proof2_m_1,
			.proof2_m_1_len = sizeof(fixture_bls12_381_shake_256_proof2_m_1),
			.proof2_m_2 = fixture_bls12_381_shake_256_proof2_m_2,
			.proof2_m_2_len = sizeof(fixture_bls12_381_shake_256_proof2_m_2),
			.proof2_m_3 = fixture_bls12_381_shake_256_proof2_m_3,
			.proof2_m_3_len = sizeof(fixture_bls12_381_shake_256_proof2_m_3),
			.proof2_m_4 = fixture_bls12_381_shake_256_proof2_m_4,
			.proof2_m_4_len = sizeof(fixture_bls12_381_shake_256_proof2_m_4),
			.proof2_m_5 = fixture_bls12_381_shake_256_proof2_m_5,
			.proof2_m_5_len = sizeof(fixture_bls12_381_shake_256_proof2_m_5),
			.proof2_m_6 = fixture_bls12_381_shake_256_proof2_m_6,
			.proof2_m_6_len = sizeof(fixture_bls12_381_shake_256_proof2_m_6),
			.proof2_m_7 = fixture_bls12_381_shake_256_proof2_m_7,
			.proof2_m_7_len = sizeof(fixture_bls12_381_shake_256_proof2_m_7),
			.proof2_m_8 = fixture_bls12_381_shake_256_proof2_m_8,
			.proof2_m_8_len = sizeof(fixture_bls12_381_shake_256_proof2_m_8),
			.proof2_m_9 = fixture_bls12_381_shake_256_proof2_m_9,
			.proof2_m_9_len = sizeof(fixture_bls12_381_shake_256_proof2_m_9),
			.proof2_m_10 = fixture_bls12_381_shake_256_proof2_m_10,
			.proof2_m_10_len = sizeof(fixture_bls12_381_shake_256_proof2_m_10),
			.proof2_proof = fixture_bls12_381_shake_256_proof2_proof,
			.proof2_proof_len = sizeof(fixture_bls12_381_shake_256_proof2_proof),

			.proof3_public_key = fixture_bls12_381_shake_256_proof3_public_key,
			.proof3_signature = fixture_bls12_381_shake_256_proof3_signature,
			.proof3_signature_len = sizeof(fixture_bls12_381_shake_256_proof3_signature),
			.proof3_header = fixture_bls12_381_shake_256_proof3_header,
			.proof3_header_len = sizeof(fixture_bls12_381_shake_256_proof3_header),
			.proof3_presentation_header = fixture_bls12_381_shake_256_proof3_presentation_header,
			.proof3_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof3_presentation_header),
			.proof3_revealed_indexes = fixture_bls12_381_shake_256_proof3_revealed_indexes,
			.proof3_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof3_revealed_indexes),
			.proof3_proof = fixture_bls12_381_shake_256_proof3_proof,
			.proof3_proof_len = sizeof(fixture_bls12_381_shake_256_proof3_proof),
			.proof3_m_1 = fixture_bls12_381_shake_256_proof3_m_1,
			.proof3_m_1_len = sizeof(fixture_bls12_381_shake_256_proof3_m_1),
			.proof3_m_3 = fixture_bls12_381_shake_256_proof3_m_3,
			.proof3_m_3_len = sizeof(fixture_bls12_381_shake_256_proof3_m_3),
			.proof3_m_5 = fixture_bls12_381_shake_256_proof3_m_5,
			.proof3_m_5_len = sizeof(fixture_bls12_381_shake_256_proof3_m_5),
			.proof3_m_7 = fixture_bls12_381_shake_256_proof3_m_7,
			.proof3_m_7_len = sizeof(fixture_bls12_381_shake_256_proof3_m_7),
		},
	};
	// *INDENT-ON* - Preserve formatting

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
	for (int cipher_suite_index = 0; cipher_suite_index < 2; cipher_suite_index++)
	{
		proof_fixture_t test_case = test_cases[cipher_suite_index];
		if (BBS_OK != bbs_proof_verify(test_case.cipher_suite, test_case.proof1_public_key,
						      test_case.proof1_proof,
						      test_case.proof1_proof_len,
						      test_case.proof1_header,
						      test_case.proof1_header_len,
						      test_case.proof1_presentation_header,
						      test_case.proof1_presentation_header_len,
						      test_case.proof1_revealed_indexes,
						      test_case.proof1_revealed_indexes_len, 1,
						      test_case.proof1_m_1,
						      test_case.proof1_m_1_len))
		{
			printf ("Error during proof 1 verification for suite `%s'\n",
					suite_names[cipher_suite_index]);
			return 1;
		}

		if (BBS_OK != bbs_proof_verify(test_case.cipher_suite, test_case.proof2_public_key,
						      test_case.proof2_proof,
						      test_case.proof2_proof_len,
						      test_case.proof2_header,
						      test_case.proof2_header_len,
						      test_case.proof2_presentation_header,
						      test_case.proof2_presentation_header_len,
						      test_case.proof2_revealed_indexes,
						      test_case.proof2_revealed_indexes_len, 10,
						      test_case.proof2_m_1,
						      test_case.proof2_m_1_len,
						      test_case.proof2_m_2,
						      test_case.proof2_m_2_len,
						      test_case.proof2_m_3,
						      test_case.proof2_m_3_len,
						      test_case.proof2_m_4,
						      test_case.proof2_m_4_len,
						      test_case.proof2_m_5,
						      test_case.proof2_m_5_len,
						      test_case.proof2_m_6,
						      test_case.proof2_m_6_len,
						      test_case.proof2_m_7,
						      test_case.proof2_m_7_len,
						      test_case.proof2_m_8,
						      test_case.proof2_m_8_len,
						      test_case.proof2_m_9,
						      test_case.proof2_m_9_len,
						      test_case.proof2_m_10,
						      test_case.proof2_m_10_len))
		{
			printf ("Error during proof 2 verification for suite `%s'\n",
					suite_names[cipher_suite_index]);
			return 1;
		}

		// Only some messages are being revealed here
		if (BBS_OK != bbs_proof_verify(test_case.cipher_suite, test_case.proof3_public_key,
						      test_case.proof3_proof,
						      test_case.proof3_proof_len,
						      test_case.proof3_header,
						      test_case.proof3_header_len,
						      test_case.proof3_presentation_header,
						      test_case.proof3_presentation_header_len,
						      test_case.proof3_revealed_indexes,
						      test_case.proof3_revealed_indexes_len, 10,
						      test_case.proof3_m_1,
						      test_case.proof3_m_1_len,
						      test_case.proof3_m_3,
						      test_case.proof3_m_3_len,
						      test_case.proof3_m_5,
						      test_case.proof3_m_5_len,
						      test_case.proof3_m_7,
						      test_case.proof3_m_7_len))
		{
			printf ("Error during proof 3 verification for suite `%s'\n",
					suite_names[cipher_suite_index]);
			return 1;
		}

	}

	return 0;
}
