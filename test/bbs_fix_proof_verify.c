#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

int bbs_fix_proof_verify() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	if(BBS_OK != bbs_proof_verify(
				fixture_bls12_381_sha_256_proof1_public_key,
				fixture_bls12_381_sha_256_proof1_proof,
				sizeof(fixture_bls12_381_sha_256_proof1_proof),
				fixture_bls12_381_sha_256_proof1_header,
				sizeof(fixture_bls12_381_sha_256_proof1_header),
				fixture_bls12_381_sha_256_proof1_presentation_header,
				sizeof(fixture_bls12_381_sha_256_proof1_presentation_header),
				fixture_bls12_381_sha_256_proof1_revealed_indexes,
				LEN(fixture_bls12_381_sha_256_proof1_revealed_indexes),
				1,
				fixture_bls12_381_sha_256_proof1_m_1,
				sizeof(fixture_bls12_381_sha_256_proof1_m_1))) {
		puts("Error during proof 1 verification");
		return 1;
	}

	if(BBS_OK != bbs_proof_verify(
				fixture_bls12_381_sha_256_proof2_public_key,
				fixture_bls12_381_sha_256_proof2_proof,
				sizeof(fixture_bls12_381_sha_256_proof2_proof),
				fixture_bls12_381_sha_256_proof2_header,
				sizeof(fixture_bls12_381_sha_256_proof2_header),
				fixture_bls12_381_sha_256_proof2_presentation_header,
				sizeof(fixture_bls12_381_sha_256_proof2_presentation_header),
				fixture_bls12_381_sha_256_proof2_revealed_indexes,
				LEN(fixture_bls12_381_sha_256_proof2_revealed_indexes),
				10,
				fixture_bls12_381_sha_256_proof2_m_1,
				sizeof(fixture_bls12_381_sha_256_proof2_m_1),
				fixture_bls12_381_sha_256_proof2_m_2,
				sizeof(fixture_bls12_381_sha_256_proof2_m_2),
				fixture_bls12_381_sha_256_proof2_m_3,
				sizeof(fixture_bls12_381_sha_256_proof2_m_3),
				fixture_bls12_381_sha_256_proof2_m_4,
				sizeof(fixture_bls12_381_sha_256_proof2_m_4),
				fixture_bls12_381_sha_256_proof2_m_5,
				sizeof(fixture_bls12_381_sha_256_proof2_m_5),
				fixture_bls12_381_sha_256_proof2_m_6,
				sizeof(fixture_bls12_381_sha_256_proof2_m_6),
				fixture_bls12_381_sha_256_proof2_m_7,
				sizeof(fixture_bls12_381_sha_256_proof2_m_7),
				fixture_bls12_381_sha_256_proof2_m_8,
				sizeof(fixture_bls12_381_sha_256_proof2_m_8),
				fixture_bls12_381_sha_256_proof2_m_9,
				sizeof(fixture_bls12_381_sha_256_proof2_m_9),
				fixture_bls12_381_sha_256_proof2_m_10,
				sizeof(fixture_bls12_381_sha_256_proof2_m_10))) {
		puts("Error during proof 2 verification");
		return 1;
	}

	// Only some messages are being revealed here
	if(BBS_OK != bbs_proof_verify(
				fixture_bls12_381_sha_256_proof3_public_key,
				fixture_bls12_381_sha_256_proof3_proof,
				sizeof(fixture_bls12_381_sha_256_proof3_proof),
				fixture_bls12_381_sha_256_proof3_header,
				sizeof(fixture_bls12_381_sha_256_proof3_header),
				fixture_bls12_381_sha_256_proof3_presentation_header,
				sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
				fixture_bls12_381_sha_256_proof3_revealed_indexes,
				LEN(fixture_bls12_381_sha_256_proof3_revealed_indexes),
				10,
				fixture_bls12_381_sha_256_proof3_m_1,
				sizeof(fixture_bls12_381_sha_256_proof3_m_1),
				fixture_bls12_381_sha_256_proof3_m_3,
				sizeof(fixture_bls12_381_sha_256_proof3_m_3),
				fixture_bls12_381_sha_256_proof3_m_5,
				sizeof(fixture_bls12_381_sha_256_proof3_m_5),
				fixture_bls12_381_sha_256_proof3_m_7,
				sizeof(fixture_bls12_381_sha_256_proof3_m_7))) {
		puts("Error during proof 3 verification");
		return 1;
	}

	return 0;
}

#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
int bbs_fix_proof_verify() {
	// TODO
	return 0;
}
#endif