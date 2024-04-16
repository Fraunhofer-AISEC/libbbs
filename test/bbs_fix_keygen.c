#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define key_gen              bbs_sha256_keygen
#define cipher_suite         bbs_sha256_cipher_suite
#define fixture_key_material fixture_bls12_381_sha_256_key_material
#define fixture_key_info     fixture_bls12_381_sha_256_key_info
#define fixture_key_dst      fixture_bls12_381_sha_256_key_dst
#define fixture_SK           fixture_bls12_381_sha_256_SK
#define fixture_PK           fixture_bls12_381_sha_256_PK
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define key_gen              bbs_shake256_keygen
#define fixture_key_material fixture_bls12_381_shake_256_key_material
#define fixture_key_info     fixture_bls12_381_shake_256_key_info
#define fixture_key_dst      fixture_bls12_381_shake_256_key_dst
#define fixture_SK           fixture_bls12_381_shake_256_SK
#define fixture_PK           fixture_bls12_381_shake_256_PK
#endif

typedef struct
{
	int (*key_gen) (
		bbs_secret_key  sk,
		const uint8_t  *key_material,
		uint16_t        key_material_len,
		const uint8_t  *key_info,
		uint16_t        key_info_len,
		const uint8_t  *key_dst,
		uint8_t         key_dst_len
		);
	uint8_t        *key_material;
	uint16_t        key_material_len;
	uint8_t        *key_info;
	uint16_t        key_info_len;
	uint8_t        *key_dst;
	uint16_t        key_dst_len;
	uint8_t  *expected_SK;
	uint8_t  *expected_PK;
} bbs_fix_keygen_fixture_t;

int
bbs_fix_keygen ()
{
	bbs_fix_keygen_fixture_t test_cases[] = {
		{
			.key_gen          = bbs_sha256_keygen,
			.key_material     = fixture_bls12_381_sha_256_key_material,
			.key_material_len = sizeof(fixture_bls12_381_sha_256_key_material),
			.key_info         = fixture_bls12_381_sha_256_key_info,
			.key_info_len     = sizeof(fixture_bls12_381_sha_256_key_info),
			.key_dst          = fixture_bls12_381_sha_256_key_dst,
			.key_dst_len      = sizeof(fixture_bls12_381_sha_256_key_dst),
			.expected_SK      = fixture_bls12_381_sha_256_SK,
			.expected_PK      = fixture_bls12_381_sha_256_PK,
		},{
			.key_gen          = bbs_shake256_keygen,
			.key_material     = fixture_bls12_381_shake_256_key_material,
			.key_material_len = sizeof(fixture_bls12_381_shake_256_key_material),
			.key_info         = fixture_bls12_381_shake_256_key_info,
			.key_info_len     = sizeof(fixture_bls12_381_shake_256_key_info),
			.key_dst          = fixture_bls12_381_shake_256_key_dst,
			.key_dst_len      = sizeof(fixture_bls12_381_shake_256_key_dst),
			.expected_SK      = fixture_bls12_381_shake_256_SK,
			.expected_PK      = fixture_bls12_381_shake_256_PK,
		}
	};

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

	for (int i = 0; i < 2; i++)
	{
		bbs_fix_keygen_fixture_t fixture = test_cases[i];

		bbs_secret_key sk;
		if (BBS_OK != fixture.key_gen (sk, fixture.key_material, fixture.key_material_len
					       , fixture.key_info,
					       fixture.key_info_len, fixture.key_dst,
					       fixture.key_dst_len))
		{
			puts ("Error during secret key generation");
			return 1;
		}
		ASSERT_EQ_PTR ("secret key generation", sk, fixture.expected_SK, BBS_SK_LEN);

		bbs_public_key pk;
		if (BBS_OK != bbs_sk_to_pk (fixture.expected_SK, pk))
		{
			puts ("Error during public key generation");
			return 1;
		}
		ASSERT_EQ_PTR ("public key generation", pk, fixture.expected_PK, BBS_PK_LEN);
	}
	return 0;
}
