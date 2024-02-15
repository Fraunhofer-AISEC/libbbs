#include "fixtures.h"
#include "test_util.h"

int bbs_fix_verify() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	if(BBS_OK != bbs_verify(
				fixture_bls12_381_sha_256_signature1_PK,
				fixture_bls12_381_sha_256_signature1_signature,
				fixture_bls12_381_sha_256_signature1_header,
				sizeof(fixture_bls12_381_sha_256_signature1_header),
				1,
				fixture_bls12_381_sha_256_signature1_m_1,
				sizeof(fixture_bls12_381_sha_256_signature1_m_1))) {
		puts("Error during signature 1 verification");
		return 1;
	}

	if(BBS_OK != bbs_verify(
				fixture_bls12_381_sha_256_signature2_PK,
				fixture_bls12_381_sha_256_signature2_signature,
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
		puts("Error during signature 2 verification");
		return 1;
	}

	return 0;
}

