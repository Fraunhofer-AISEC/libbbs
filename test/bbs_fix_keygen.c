#include "fixtures.h"
#include "test_util.h"

typedef struct
{
	bbs_cipher_suite_t *cipher_suite;
	uint8_t        *key_material;
	uint16_t key_material_len;
	uint8_t        *key_info;
	uint16_t key_info_len;
	uint8_t        *key_dst;
	uint16_t key_dst_len;
	uint8_t  *expected_SK;
	uint8_t  *expected_PK;
} bbs_fix_keygen_fixture_t;

int
bbs_fix_keygen ()
{
#ifdef LIBBBS_TEST_SUITE_SHAKE256
	bbs_fix_keygen_fixture_t fixture = {
		.cipher_suite     = bbs_shake256_cipher_suite,
		.key_material     = fixture_bls12_381_shake_256_key_material,
		.key_material_len = sizeof(fixture_bls12_381_shake_256_key_material),
		.key_info         = fixture_bls12_381_shake_256_key_info,
		.key_info_len     = sizeof(fixture_bls12_381_shake_256_key_info),
		.key_dst          = fixture_bls12_381_shake_256_key_dst,
		.key_dst_len      = sizeof(fixture_bls12_381_shake_256_key_dst),
		.expected_SK      = fixture_bls12_381_shake_256_SK,
		.expected_PK      = fixture_bls12_381_shake_256_PK,
	};
#elif LIBBBS_TEST_SUITE_SHA256
	bbs_fix_keygen_fixture_t fixture = {
		.cipher_suite     = bbs_sha256_cipher_suite,
		.key_material     = fixture_bls12_381_sha_256_key_material,
		.key_material_len = sizeof(fixture_bls12_381_sha_256_key_material),
		.key_info         = fixture_bls12_381_sha_256_key_info,
		.key_info_len     = sizeof(fixture_bls12_381_sha_256_key_info),
		.key_dst          = fixture_bls12_381_sha_256_key_dst,
		.key_dst_len      = sizeof(fixture_bls12_381_sha_256_key_dst),
		.expected_SK      = fixture_bls12_381_sha_256_SK,
		.expected_PK      = fixture_bls12_381_sha_256_PK,
	};
#endif
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
	if (BBS_OK != bbs_keygen(fixture.cipher_suite, sk, fixture.key_material, fixture.key_material_len
	                         , fixture.key_info,
	                         fixture.key_info_len, fixture.key_dst,
	                         fixture.key_dst_len))
	{
		puts ("Error during secret key generation");
		return 1;
	}
	ASSERT_EQ_PTR ("secret key generation", sk, fixture.expected_SK, BBS_SK_LEN);

	bbs_public_key pk;
	if (BBS_OK != bbs_sk_to_pk (fixture.cipher_suite, fixture.expected_SK, pk))
	{
		puts ("Error during public key generation");
		return 1;
	}
	ASSERT_EQ_PTR ("public key generation", pk, fixture.expected_PK, BBS_PK_LEN);
	return 0;
}
