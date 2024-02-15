#include "fixtures.h"
#include "test_util.h"

int bbs_fix_keygen() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	bbs_secret_key sk;
	if(BBS_OK != bbs_keygen(
				sk,
				fixture_bls12_381_sha_256_key_material,
				sizeof(fixture_bls12_381_sha_256_key_material),
				fixture_bls12_381_sha_256_key_info,
				sizeof(fixture_bls12_381_sha_256_key_info),
				fixture_bls12_381_sha_256_key_dst,
				sizeof(fixture_bls12_381_sha_256_key_dst))) {
		puts("Error during secret key generation");
		return 1;
	}
	ASSERT_EQ("secret key generation", sk, fixture_bls12_381_sha_256_SK);

	bbs_public_key pk;
	if(BBS_OK != bbs_sk_to_pk(fixture_bls12_381_sha_256_SK, pk)) {
		puts("Error during public key generation");
		return 1;
	}
	ASSERT_EQ("public key generation", pk, fixture_bls12_381_sha_256_PK);

	return 0;
}

