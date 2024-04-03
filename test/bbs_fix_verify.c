#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

#define signature1_SK        fixture_bls12_381_sha_256_signature1_SK
#define signature1_PK        fixture_bls12_381_sha_256_signature1_PK
#define signature1_header    fixture_bls12_381_sha_256_signature1_header
#define signature1_m_1       fixture_bls12_381_sha_256_signature1_m_1
#define signature1_signature fixture_bls12_381_sha_256_signature1_signature

#define signature2_SK        fixture_bls12_381_sha_256_signature2_SK
#define signature2_PK        fixture_bls12_381_sha_256_signature2_PK
#define signature2_header    fixture_bls12_381_sha_256_signature2_header
#define signature2_m_1       fixture_bls12_381_sha_256_signature2_m_1
#define signature2_m_2       fixture_bls12_381_sha_256_signature2_m_2
#define signature2_m_3       fixture_bls12_381_sha_256_signature2_m_3
#define signature2_m_4       fixture_bls12_381_sha_256_signature2_m_4
#define signature2_m_5       fixture_bls12_381_sha_256_signature2_m_5
#define signature2_m_6       fixture_bls12_381_sha_256_signature2_m_6
#define signature2_m_7       fixture_bls12_381_sha_256_signature2_m_7
#define signature2_m_8       fixture_bls12_381_sha_256_signature2_m_8
#define signature2_m_9       fixture_bls12_381_sha_256_signature2_m_9
#define signature2_m_10      fixture_bls12_381_sha_256_signature2_m_10
#define signature2_signature fixture_bls12_381_sha_256_signature2_signature

#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

#define signature1_SK        fixture_bls12_381_shake_256_signature1_SK
#define signature1_PK        fixture_bls12_381_shake_256_signature1_PK
#define signature1_header    fixture_bls12_381_shake_256_signature1_header
#define signature1_m_1       fixture_bls12_381_shake_256_signature1_m_1
#define signature1_signature fixture_bls12_381_shake_256_signature1_signature

#define signature2_SK        fixture_bls12_381_shake_256_signature2_SK
#define signature2_PK        fixture_bls12_381_shake_256_signature2_PK
#define signature2_header    fixture_bls12_381_shake_256_signature2_header
#define signature2_m_1       fixture_bls12_381_shake_256_signature2_m_1
#define signature2_m_2       fixture_bls12_381_shake_256_signature2_m_2
#define signature2_m_3       fixture_bls12_381_shake_256_signature2_m_3
#define signature2_m_4       fixture_bls12_381_shake_256_signature2_m_4
#define signature2_m_5       fixture_bls12_381_shake_256_signature2_m_5
#define signature2_m_6       fixture_bls12_381_shake_256_signature2_m_6
#define signature2_m_7       fixture_bls12_381_shake_256_signature2_m_7
#define signature2_m_8       fixture_bls12_381_shake_256_signature2_m_8
#define signature2_m_9       fixture_bls12_381_shake_256_signature2_m_9
#define signature2_m_10      fixture_bls12_381_shake_256_signature2_m_10
#define signature2_signature fixture_bls12_381_shake_256_signature2_signature

#endif

int
bbs_fix_verify ()
{
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

	if (BBS_OK != bbs_sha256_verify (signature1_PK, signature1_signature, signature1_header, sizeof(
					  signature1_header), 1, signature1_m_1, sizeof(
					  signature1_m_1)))
	{
		puts ("Error during signature 1 verification");
		return 1;
	}

	if (BBS_OK != bbs_sha256_verify (signature2_PK, signature2_signature, signature2_header, sizeof(
					  signature2_header), 10, signature2_m_1, sizeof(
					  signature2_m_1), signature2_m_2, sizeof(signature2_m_2),
				  signature2_m_3, sizeof(signature2_m_3), signature2_m_4, sizeof(
					  signature2_m_4), signature2_m_5, sizeof(signature2_m_5),
				  signature2_m_6, sizeof(signature2_m_6), signature2_m_7, sizeof(
					  signature2_m_7), signature2_m_8, sizeof(signature2_m_8),
				  signature2_m_9, sizeof(signature2_m_9), signature2_m_10, sizeof(
					  signature2_m_10)))
	{
		puts ("Error during signature 2 verification");
		return 1;
	}

	return 0;
}
