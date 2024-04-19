#include "fixtures.h"
#include "test_util.h"


typedef struct
{
	bbs_cipher_suite_t cipher_suite;
	int (*verify)(const uint8_t *pk,
		      const uint8_t *signature,
		      const uint8_t *header,
		      uint64_t       header_len,
		      uint64_t       num_messages,
		      ...
		      );
	uint8_t  *signature1_SK;
	uint8_t  *signature1_PK;
	uint8_t  *signature1_header;
	uint32_t  signature1_header_len;
	uint8_t  *signature1_m_1;
	uint32_t  signature1_m_1_len;
	uint8_t  *signature1_signature;
	uint32_t  signature1_signature_len;

	uint8_t  *signature2_SK;
	uint8_t  *signature2_PK;
	uint8_t  *signature2_header;
	uint32_t  signature2_header_len;
	uint8_t  *signature2_m_1;
	uint32_t  signature2_m_1_len;
	uint8_t  *signature2_m_2;
	uint32_t  signature2_m_2_len;
	uint8_t  *signature2_m_3;
	uint32_t  signature2_m_3_len;
	uint8_t  *signature2_m_4;
	uint32_t  signature2_m_4_len;
	uint8_t  *signature2_m_5;
	uint32_t  signature2_m_5_len;
	uint8_t  *signature2_m_6;
	uint32_t  signature2_m_6_len;
	uint8_t  *signature2_m_7;
	uint32_t  signature2_m_7_len;
	uint8_t  *signature2_m_8;
	uint32_t  signature2_m_8_len;
	uint8_t  *signature2_m_9;
	uint32_t  signature2_m_9_len;
	uint8_t  *signature2_m_10;
	uint32_t  signature2_m_10_len;
	uint8_t  *signature2_signature;
	uint32_t  signature2_signature_len;
} bbs_fix_verify_fixture_t;


int
bbs_fix_verify ()
{
	// *INDENT-OFF* - Preserve formatting
	bbs_fix_verify_fixture_t test_cases[] = {
		{
			.cipher_suite = bbs_sha256_cipher_suite,
			.verify = bbs_sha256_verify,
			.signature1_SK = fixture_bls12_381_sha_256_signature1_SK,
			.signature1_PK = fixture_bls12_381_sha_256_signature1_PK,
			.signature1_header = fixture_bls12_381_sha_256_signature1_header,
			.signature1_header_len = sizeof(fixture_bls12_381_sha_256_signature1_header),
			.signature1_m_1 = fixture_bls12_381_sha_256_signature1_m_1,
			.signature1_m_1_len = sizeof(fixture_bls12_381_sha_256_signature1_m_1),
			.signature1_signature = fixture_bls12_381_sha_256_signature1_signature,
			.signature1_signature_len = sizeof(fixture_bls12_381_sha_256_signature1_signature),

			.signature2_SK = fixture_bls12_381_sha_256_signature2_SK,
			.signature2_PK = fixture_bls12_381_sha_256_signature2_PK,
			.signature2_header = fixture_bls12_381_sha_256_signature2_header,
			.signature2_header_len = sizeof(fixture_bls12_381_sha_256_signature2_header),
			.signature2_m_1 = fixture_bls12_381_sha_256_signature2_m_1,
			.signature2_m_1_len = sizeof(fixture_bls12_381_sha_256_signature2_m_1),
			.signature2_m_2 = fixture_bls12_381_sha_256_signature2_m_2,
			.signature2_m_2_len = sizeof(fixture_bls12_381_sha_256_signature2_m_2),
			.signature2_m_3 = fixture_bls12_381_sha_256_signature2_m_3,
			.signature2_m_3_len = sizeof(fixture_bls12_381_sha_256_signature2_m_3),
			.signature2_m_4 = fixture_bls12_381_sha_256_signature2_m_4,
			.signature2_m_4_len = sizeof(fixture_bls12_381_sha_256_signature2_m_4),
			.signature2_m_5 = fixture_bls12_381_sha_256_signature2_m_5,
			.signature2_m_5_len = sizeof(fixture_bls12_381_sha_256_signature2_m_5),
			.signature2_m_6 = fixture_bls12_381_sha_256_signature2_m_6,
			.signature2_m_6_len = sizeof(fixture_bls12_381_sha_256_signature2_m_6),
			.signature2_m_7 = fixture_bls12_381_sha_256_signature2_m_7,
			.signature2_m_7_len = sizeof(fixture_bls12_381_sha_256_signature2_m_7),
			.signature2_m_8 = fixture_bls12_381_sha_256_signature2_m_8,
			.signature2_m_8_len = sizeof(fixture_bls12_381_sha_256_signature2_m_8),
			.signature2_m_9 = fixture_bls12_381_sha_256_signature2_m_9,
			.signature2_m_9_len = sizeof(fixture_bls12_381_sha_256_signature2_m_9),
			.signature2_m_10 = fixture_bls12_381_sha_256_signature2_m_10,
			.signature2_m_10_len = sizeof(fixture_bls12_381_sha_256_signature2_m_10),
			.signature2_signature = fixture_bls12_381_sha_256_signature2_signature,
			.signature2_signature_len = sizeof(fixture_bls12_381_sha_256_signature2_signature),
		},
		{
			.cipher_suite = bbs_shake256_cipher_suite,
			.verify = bbs_shake256_verify,
			.signature1_SK = fixture_bls12_381_shake_256_signature1_SK,
			.signature1_PK = fixture_bls12_381_shake_256_signature1_PK,
			.signature1_header = fixture_bls12_381_shake_256_signature1_header,
			.signature1_header_len = sizeof(fixture_bls12_381_shake_256_signature1_header),
			.signature1_m_1 = fixture_bls12_381_shake_256_signature1_m_1,
			.signature1_m_1_len = sizeof(fixture_bls12_381_shake_256_signature1_m_1),
			.signature1_signature = fixture_bls12_381_shake_256_signature1_signature,
			.signature1_signature_len = sizeof(fixture_bls12_381_shake_256_signature1_signature),

			.signature2_SK = fixture_bls12_381_shake_256_signature2_SK,
			.signature2_PK = fixture_bls12_381_shake_256_signature2_PK,
			.signature2_header = fixture_bls12_381_shake_256_signature2_header,
			.signature2_header_len = sizeof(fixture_bls12_381_shake_256_signature2_header),
			.signature2_m_1 = fixture_bls12_381_shake_256_signature2_m_1,
			.signature2_m_1_len = sizeof(fixture_bls12_381_shake_256_signature2_m_1),
			.signature2_m_2 = fixture_bls12_381_shake_256_signature2_m_2,
			.signature2_m_2_len = sizeof(fixture_bls12_381_shake_256_signature2_m_2),
			.signature2_m_3 = fixture_bls12_381_shake_256_signature2_m_3,
			.signature2_m_3_len = sizeof(fixture_bls12_381_shake_256_signature2_m_3),
			.signature2_m_4 = fixture_bls12_381_shake_256_signature2_m_4,
			.signature2_m_4_len = sizeof(fixture_bls12_381_shake_256_signature2_m_4),
			.signature2_m_5 = fixture_bls12_381_shake_256_signature2_m_5,
			.signature2_m_5_len = sizeof(fixture_bls12_381_shake_256_signature2_m_5),
			.signature2_m_6 = fixture_bls12_381_shake_256_signature2_m_6,
			.signature2_m_6_len = sizeof(fixture_bls12_381_shake_256_signature2_m_6),
			.signature2_m_7 = fixture_bls12_381_shake_256_signature2_m_7,
			.signature2_m_7_len = sizeof(fixture_bls12_381_shake_256_signature2_m_7),
			.signature2_m_8 = fixture_bls12_381_shake_256_signature2_m_8,
			.signature2_m_8_len = sizeof(fixture_bls12_381_shake_256_signature2_m_8),
			.signature2_m_9 = fixture_bls12_381_shake_256_signature2_m_9,
			.signature2_m_9_len = sizeof(fixture_bls12_381_shake_256_signature2_m_9),
			.signature2_m_10 = fixture_bls12_381_shake_256_signature2_m_10,
			.signature2_m_10_len = sizeof(fixture_bls12_381_shake_256_signature2_m_10),
			.signature2_signature = fixture_bls12_381_shake_256_signature2_signature,
			.signature2_signature_len = sizeof(fixture_bls12_381_shake_256_signature2_signature),
		}
	};
	// *INDENT-ON* - Continue formatting

	for (int cipher_suite_index = 0; cipher_suite_index < 2; cipher_suite_index++)
	{
		bbs_fix_verify_fixture_t test_case = test_cases[cipher_suite_index];
		printf("Testing cipher suite %s\n", test_case.cipher_suite.cipher_suite_id);
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

		if (BBS_OK != test_case.verify (test_case.signature1_PK,
						test_case.signature1_signature,
						test_case.signature1_header,
						test_case.signature1_header_len, 1,
						test_case.signature1_m_1,
						test_case.signature1_m_1_len))
		{
			puts ("Error during signature 1 verification");
			return 1;
		}

		if (BBS_OK != test_case.verify (test_case.signature2_PK,
						test_case.signature2_signature,
						test_case.signature2_header,
						test_case.signature2_header_len, 10,
						test_case.signature2_m_1,
						test_case.signature2_m_1_len,
						test_case.signature2_m_2,
						test_case.signature2_m_2_len,
						test_case.signature2_m_3,
						test_case.signature2_m_3_len,
						test_case.signature2_m_4,
						test_case.signature2_m_4_len,
						test_case.signature2_m_5,
						test_case.signature2_m_5_len,
						test_case.signature2_m_6,
						test_case.signature2_m_6_len,
						test_case.signature2_m_7,
						test_case.signature2_m_7_len,
						test_case.signature2_m_8,
						test_case.signature2_m_8_len,
						test_case.signature2_m_9,
						test_case.signature2_m_9_len,
						test_case.signature2_m_10,
						test_case.signature2_m_10_len))
		{
			puts ("Error during signature 2 verification");
			return 1;
		}
	}
	return 0;
}
