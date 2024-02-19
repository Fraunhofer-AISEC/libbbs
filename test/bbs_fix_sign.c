#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

int bbs_fix_sign() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	bbs_signature sig;
	if(BBS_OK != bbs_sign(
				fixture_bls12_381_sha_256_signature1_SK,
				fixture_bls12_381_sha_256_signature1_PK,
				sig,
				fixture_bls12_381_sha_256_signature1_header,
				sizeof(fixture_bls12_381_sha_256_signature1_header),
				1,
				fixture_bls12_381_sha_256_signature1_m_1,
				sizeof(fixture_bls12_381_sha_256_signature1_m_1))) {
		puts("Error during signature 1 generation");
		return 1;
	}
	ASSERT_EQ("signature 1 generation", sig, fixture_bls12_381_sha_256_signature1_signature);

	if(BBS_OK != bbs_sign(
				fixture_bls12_381_sha_256_signature2_SK,
				fixture_bls12_381_sha_256_signature2_PK,
				sig,
				fixture_bls12_381_sha_256_signature2_header,
				sizeof(fixture_bls12_381_sha_256_signature2_header),
				10,
				fixture_bls12_381_sha_256_signature2_m_1,
				sizeof(fixture_bls12_381_sha_256_signature2_m_1),
				fixture_bls12_381_sha_256_signature2_m_2,
				sizeof(fixture_bls12_381_sha_256_signature2_m_2),
				fixture_bls12_381_sha_256_signature2_m_3,
				sizeof(fixture_bls12_381_sha_256_signature2_m_3),
				fixture_bls12_381_sha_256_signature2_m_4,
				sizeof(fixture_bls12_381_sha_256_signature2_m_4),
				fixture_bls12_381_sha_256_signature2_m_5,
				sizeof(fixture_bls12_381_sha_256_signature2_m_5),
				fixture_bls12_381_sha_256_signature2_m_6,
				sizeof(fixture_bls12_381_sha_256_signature2_m_6),
				fixture_bls12_381_sha_256_signature2_m_7,
				sizeof(fixture_bls12_381_sha_256_signature2_m_7),
				fixture_bls12_381_sha_256_signature2_m_8,
				sizeof(fixture_bls12_381_sha_256_signature2_m_8),
				fixture_bls12_381_sha_256_signature2_m_9,
				sizeof(fixture_bls12_381_sha_256_signature2_m_9),
				fixture_bls12_381_sha_256_signature2_m_10,
				sizeof(fixture_bls12_381_sha_256_signature2_m_10))) {
		puts("Error during signature 2 generation");
		return 1;
	}
	ASSERT_EQ("signature 2 generation", sig, fixture_bls12_381_sha_256_signature2_signature);

	return 0;
}

#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

int bbs_fix_sign() {
	// TODO
	return 0;
}

#endif