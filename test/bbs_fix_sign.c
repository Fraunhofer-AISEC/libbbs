#include "fixtures.h"
#include "test_util.h"

typedef struct
{
	bbs_cipher_suite_t  *cipher_suite;
	uint8_t  *signature1_SK;
	uint8_t  *signature1_PK;
	uint8_t  *signature1_header;
	uint32_t signature1_header_len;
	uint8_t  *signature1_m_1;
	uint32_t signature1_m_1_len;
	uint8_t  *signature1_signature;
	uint32_t signature1_signature_len;

	uint8_t  *signature2_SK;
	uint8_t  *signature2_PK;
	uint8_t  *signature2_header;
	uint32_t signature2_header_len;
	uint8_t  *signature2_m_1;
	uint32_t signature2_m_1_len;
	uint8_t  *signature2_m_2;
	uint32_t signature2_m_2_len;
	uint8_t  *signature2_m_3;
	uint32_t signature2_m_3_len;
	uint8_t  *signature2_m_4;
	uint32_t signature2_m_4_len;
	uint8_t  *signature2_m_5;
	uint32_t signature2_m_5_len;
	uint8_t  *signature2_m_6;
	uint32_t signature2_m_6_len;
	uint8_t  *signature2_m_7;
	uint32_t signature2_m_7_len;
	uint8_t  *signature2_m_8;
	uint32_t signature2_m_8_len;
	uint8_t  *signature2_m_9;
	uint32_t signature2_m_9_len;
	uint8_t  *signature2_m_10;
	uint32_t signature2_m_10_len;
	uint8_t  *signature2_signature;
	uint32_t signature2_signature_len;
} bbs_fix_sign_fixture_t;

int
bbs_fix_sign ()
{
	// *INDENT-OFF* - Preserve formatting
#ifdef LIBBBS_TEST_SUITE_SHAKE256
  bbs_fix_sign_fixture_t fixture = {
			.cipher_suite = bbs_shake256_cipher_suite,
			.signature1_SK =         fixture_bls12_381_shake_256_signature1_SK,
			.signature1_PK =         fixture_bls12_381_shake_256_signature1_PK,
			.signature1_header =     fixture_bls12_381_shake_256_signature1_header,
			.signature1_header_len = sizeof(fixture_bls12_381_shake_256_signature1_header),
			.signature1_m_1 =        fixture_bls12_381_shake_256_signature1_m_1,
			.signature1_m_1_len =    sizeof(fixture_bls12_381_shake_256_signature1_m_1),
			.signature1_signature =  fixture_bls12_381_shake_256_signature1_signature,
			.signature1_signature_len = sizeof(fixture_bls12_381_shake_256_signature1_signature),

			.signature2_SK =         fixture_bls12_381_shake_256_signature2_SK,
			.signature2_PK =         fixture_bls12_381_shake_256_signature2_PK,
			.signature2_header =     fixture_bls12_381_shake_256_signature2_header,
			.signature2_header_len = sizeof(fixture_bls12_381_shake_256_signature2_header),
			.signature2_m_1 =        fixture_bls12_381_shake_256_signature2_m_1,
			.signature2_m_1_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_1),
			.signature2_m_2 =        fixture_bls12_381_shake_256_signature2_m_2,
			.signature2_m_2_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_2),
			.signature2_m_3 =        fixture_bls12_381_shake_256_signature2_m_3,
			.signature2_m_3_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_3),
			.signature2_m_4 =        fixture_bls12_381_shake_256_signature2_m_4,
			.signature2_m_4_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_4),
			.signature2_m_5 =        fixture_bls12_381_shake_256_signature2_m_5,
			.signature2_m_5_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_5),
			.signature2_m_6 =        fixture_bls12_381_shake_256_signature2_m_6,
			.signature2_m_6_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_6),
			.signature2_m_7 =        fixture_bls12_381_shake_256_signature2_m_7,
			.signature2_m_7_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_7),
			.signature2_m_8 =        fixture_bls12_381_shake_256_signature2_m_8,
			.signature2_m_8_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_8),
			.signature2_m_9 =        fixture_bls12_381_shake_256_signature2_m_9,
			.signature2_m_9_len =    sizeof(fixture_bls12_381_shake_256_signature2_m_9),
			.signature2_m_10 =       fixture_bls12_381_shake_256_signature2_m_10,
			.signature2_m_10_len =   sizeof(fixture_bls12_381_shake_256_signature2_m_10),
			.signature2_signature =  fixture_bls12_381_shake_256_signature2_signature,
			.signature2_signature_len =  sizeof(fixture_bls12_381_shake_256_signature2_signature),
	};
#elif LIBBBS_TEST_SUITE_SHA256
  bbs_fix_sign_fixture_t fixture = {
			.cipher_suite = bbs_sha256_cipher_suite,
			.signature1_SK =         fixture_bls12_381_sha_256_signature1_SK,
			.signature1_PK =         fixture_bls12_381_sha_256_signature1_PK,
			.signature1_header =     fixture_bls12_381_sha_256_signature1_header,
			.signature1_header_len = sizeof(fixture_bls12_381_sha_256_signature1_header),
			.signature1_m_1 =        fixture_bls12_381_sha_256_signature1_m_1,
			.signature1_m_1_len =    sizeof(fixture_bls12_381_sha_256_signature1_m_1),
			.signature1_signature =  fixture_bls12_381_sha_256_signature1_signature,
			.signature1_signature_len = sizeof(fixture_bls12_381_sha_256_signature1_signature),

			.signature2_SK =         fixture_bls12_381_sha_256_signature2_SK,
			.signature2_PK =         fixture_bls12_381_sha_256_signature2_PK,
			.signature2_header =     fixture_bls12_381_sha_256_signature2_header,
			.signature2_header_len = sizeof(fixture_bls12_381_sha_256_signature2_header),
			.signature2_m_1 =        fixture_bls12_381_sha_256_signature2_m_1,
			.signature2_m_1_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_1),
			.signature2_m_2 =        fixture_bls12_381_sha_256_signature2_m_2,
			.signature2_m_2_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_2),
			.signature2_m_3 =        fixture_bls12_381_sha_256_signature2_m_3,
			.signature2_m_3_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_3),
			.signature2_m_4 =        fixture_bls12_381_sha_256_signature2_m_4,
			.signature2_m_4_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_4),
			.signature2_m_5 =        fixture_bls12_381_sha_256_signature2_m_5,
			.signature2_m_5_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_5),
			.signature2_m_6 =        fixture_bls12_381_sha_256_signature2_m_6,
			.signature2_m_6_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_6),
			.signature2_m_7 =        fixture_bls12_381_sha_256_signature2_m_7,
			.signature2_m_7_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_7),
			.signature2_m_8 =        fixture_bls12_381_sha_256_signature2_m_8,
			.signature2_m_8_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_8),
			.signature2_m_9 =        fixture_bls12_381_sha_256_signature2_m_9,
			.signature2_m_9_len =    sizeof(fixture_bls12_381_sha_256_signature2_m_9),
			.signature2_m_10 =       fixture_bls12_381_sha_256_signature2_m_10,
			.signature2_m_10_len =   sizeof(fixture_bls12_381_sha_256_signature2_m_10),
			.signature2_signature =  fixture_bls12_381_sha_256_signature2_signature,
			.signature2_signature_len =  sizeof(fixture_bls12_381_sha_256_signature2_signature),
	};
#endif
	// *INDENT-ON* - Preserve formatting

	printf("Testing cipher suite %s\n", fixture.cipher_suite->cipher_suite_id);
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

	bbs_signature sig;
	if (BBS_OK != bbs_sign(fixture.cipher_suite, fixture.signature1_SK, fixture.signature1_PK, sig,
	                       fixture.signature1_header,
	                       fixture.signature1_header_len, 1,                // num_messages
	                       fixture.signature1_m_1,
	                       fixture.signature1_m_1_len))
	{
		puts ("Error during signature 1 generation");
		return 1;
	}
	ASSERT_EQ_PTR ("signature 1 generation",
	               sig,
	               fixture.signature1_signature,
	               fixture.signature1_signature_len);

	if (BBS_OK != bbs_sign(fixture.cipher_suite, fixture.signature2_SK, fixture.signature2_PK, sig,
	                       fixture.signature2_header,
	                       fixture.signature2_header_len, 10,
	                       // num_messages
	                       fixture.signature2_m_1,
	                       fixture.signature2_m_1_len,
	                       fixture.signature2_m_2,
	                       fixture.signature2_m_2_len,
	                       fixture.signature2_m_3,
	                       fixture.signature2_m_3_len,
	                       fixture.signature2_m_4,
	                       fixture.signature2_m_4_len,
	                       fixture.signature2_m_5,
	                       fixture.signature2_m_5_len,
	                       fixture.signature2_m_6,
	                       fixture.signature2_m_6_len,
	                       fixture.signature2_m_7,
	                       fixture.signature2_m_7_len,
	                       fixture.signature2_m_8,
	                       fixture.signature2_m_8_len,
	                       fixture.signature2_m_9,
	                       fixture.signature2_m_9_len,
	                       fixture.signature2_m_10,
	                       fixture.signature2_m_10_len))
	{
		puts ("Error during signature 2 generation");
		return 1;
	}
	ASSERT_EQ_PTR ("signature 2 generation",
	               sig,
	               fixture.signature2_signature,
	               fixture.signature2_signature_len);
	return 0;
}
