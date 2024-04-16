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

int
bbs_fix_keygen ()
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

	bbs_secret_key sk;
	if (BBS_OK != key_gen (sk,
			       fixture_key_material,
			       sizeof(fixture_key_material),
			       fixture_key_info,
			       sizeof(fixture_key_info),
			       fixture_key_dst,
			       sizeof(fixture_key_dst)))
	{
		puts ("Error during secret key generation");
		return 1;
	}
	ASSERT_EQ ("secret key generation", sk, fixture_SK);

	bbs_public_key pk;
	if (BBS_OK != bbs_sk_to_pk (fixture_SK, pk))
	{
		puts ("Error during public key generation");
		return 1;
	}
	ASSERT_EQ ("public key generation", pk, fixture_PK);

	return 0;
}
