#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define proof_verify bbs_sha256_proof_verify
#define proof_SEED                 fixture_bls12_381_sha_256_proof_SEED
#define proof_DST                  fixture_bls12_381_sha_256_proof_DST
#define proof_random_scalar_1      fixture_bls12_381_sha_256_proof_random_scalar_1
#define proof_random_scalar_2      fixture_bls12_381_sha_256_proof_random_scalar_2
#define proof_random_scalar_3      fixture_bls12_381_sha_256_proof_random_scalar_3
#define proof_random_scalar_4      fixture_bls12_381_sha_256_proof_random_scalar_4
#define proof_random_scalar_5      fixture_bls12_381_sha_256_proof_random_scalar_5
#define proof_random_scalar_6      fixture_bls12_381_sha_256_proof_random_scalar_6
#define proof_random_scalar_7      fixture_bls12_381_sha_256_proof_random_scalar_7
#define proof_random_scalar_8      fixture_bls12_381_sha_256_proof_random_scalar_8
#define proof_random_scalar_9      fixture_bls12_381_sha_256_proof_random_scalar_9
#define proof_random_scalar_10     fixture_bls12_381_sha_256_proof_random_scalar_10

#define proof1_public_key          fixture_bls12_381_sha_256_proof1_public_key
#define proof1_signature           fixture_bls12_381_sha_256_proof1_signature
#define proof1_header              fixture_bls12_381_sha_256_proof1_header
#define proof1_presentation_header fixture_bls12_381_sha_256_proof1_presentation_header
#define proof1_revealed_indexes    fixture_bls12_381_sha_256_proof1_revealed_indexes
#define proof1_m_1                 fixture_bls12_381_sha_256_proof1_m_1
#define proof1_proof               fixture_bls12_381_sha_256_proof1_proof

#define proof2_public_key          fixture_bls12_381_sha_256_proof2_public_key
#define proof2_signature           fixture_bls12_381_sha_256_proof2_signature
#define proof2_header              fixture_bls12_381_sha_256_proof2_header
#define proof2_presentation_header fixture_bls12_381_sha_256_proof2_presentation_header
#define proof2_revealed_indexes    fixture_bls12_381_sha_256_proof2_revealed_indexes
#define proof2_m_1                 fixture_bls12_381_sha_256_proof2_m_1
#define proof2_m_2                 fixture_bls12_381_sha_256_proof2_m_2
#define proof2_m_3                 fixture_bls12_381_sha_256_proof2_m_3
#define proof2_m_4                 fixture_bls12_381_sha_256_proof2_m_4
#define proof2_m_5                 fixture_bls12_381_sha_256_proof2_m_5
#define proof2_m_6                 fixture_bls12_381_sha_256_proof2_m_6
#define proof2_m_7                 fixture_bls12_381_sha_256_proof2_m_7
#define proof2_m_8                 fixture_bls12_381_sha_256_proof2_m_8
#define proof2_m_9                 fixture_bls12_381_sha_256_proof2_m_9
#define proof2_m_10                fixture_bls12_381_sha_256_proof2_m_10
#define proof2_proof               fixture_bls12_381_sha_256_proof2_proof

#define proof3_public_key          fixture_bls12_381_sha_256_proof3_public_key
#define proof3_signature           fixture_bls12_381_sha_256_proof3_signature
#define proof3_header              fixture_bls12_381_sha_256_proof3_header
#define proof3_presentation_header fixture_bls12_381_sha_256_proof3_presentation_header
#define proof3_revealed_indexes    fixture_bls12_381_sha_256_proof3_revealed_indexes
#define proof3_proof               fixture_bls12_381_sha_256_proof3_proof
#define proof3_m_1 fixture_bls12_381_sha_256_proof3_m_1
#define proof3_m_3 fixture_bls12_381_sha_256_proof3_m_3
#define proof3_m_5 fixture_bls12_381_sha_256_proof3_m_5
#define proof3_m_7 fixture_bls12_381_sha_256_proof3_m_7


#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define proof_verify bbs_shake256_proof_verify
#define proof_SEED                 fixture_bls12_381_shake_256_proof_SEED
#define proof_DST                  fixture_bls12_381_shake_256_proof_DST
#define proof_random_scalar_1      fixture_bls12_381_shake_256_proof_random_scalar_1
#define proof_random_scalar_2      fixture_bls12_381_shake_256_proof_random_scalar_2
#define proof_random_scalar_3      fixture_bls12_381_shake_256_proof_random_scalar_3
#define proof_random_scalar_4      fixture_bls12_381_shake_256_proof_random_scalar_4
#define proof_random_scalar_5      fixture_bls12_381_shake_256_proof_random_scalar_5
#define proof_random_scalar_6      fixture_bls12_381_shake_256_proof_random_scalar_6
#define proof_random_scalar_7      fixture_bls12_381_shake_256_proof_random_scalar_7
#define proof_random_scalar_8      fixture_bls12_381_shake_256_proof_random_scalar_8
#define proof_random_scalar_9      fixture_bls12_381_shake_256_proof_random_scalar_9
#define proof_random_scalar_10     fixture_bls12_381_shake_256_proof_random_scalar_10

#define proof1_public_key          fixture_bls12_381_shake_256_proof1_public_key
#define proof1_signature           fixture_bls12_381_shake_256_proof1_signature
#define proof1_header              fixture_bls12_381_shake_256_proof1_header
#define proof1_presentation_header fixture_bls12_381_shake_256_proof1_presentation_header
#define proof1_revealed_indexes    fixture_bls12_381_shake_256_proof1_revealed_indexes
#define proof1_m_1                 fixture_bls12_381_shake_256_proof1_m_1
#define proof1_proof               fixture_bls12_381_shake_256_proof1_proof

#define proof2_public_key          fixture_bls12_381_shake_256_proof2_public_key
#define proof2_signature           fixture_bls12_381_shake_256_proof2_signature
#define proof2_header              fixture_bls12_381_shake_256_proof2_header
#define proof2_presentation_header fixture_bls12_381_shake_256_proof2_presentation_header
#define proof2_revealed_indexes    fixture_bls12_381_shake_256_proof2_revealed_indexes
#define proof2_m_1                 fixture_bls12_381_shake_256_proof2_m_1
#define proof2_m_2                 fixture_bls12_381_shake_256_proof2_m_2
#define proof2_m_3                 fixture_bls12_381_shake_256_proof2_m_3
#define proof2_m_4                 fixture_bls12_381_shake_256_proof2_m_4
#define proof2_m_5                 fixture_bls12_381_shake_256_proof2_m_5
#define proof2_m_6                 fixture_bls12_381_shake_256_proof2_m_6
#define proof2_m_7                 fixture_bls12_381_shake_256_proof2_m_7
#define proof2_m_8                 fixture_bls12_381_shake_256_proof2_m_8
#define proof2_m_9                 fixture_bls12_381_shake_256_proof2_m_9
#define proof2_m_10                fixture_bls12_381_shake_256_proof2_m_10
#define proof2_proof               fixture_bls12_381_shake_256_proof2_proof

#define proof3_public_key          fixture_bls12_381_shake_256_proof3_public_key
#define proof3_signature           fixture_bls12_381_shake_256_proof3_signature
#define proof3_header              fixture_bls12_381_shake_256_proof3_header
#define proof3_presentation_header fixture_bls12_381_shake_256_proof3_presentation_header
#define proof3_revealed_indexes    fixture_bls12_381_shake_256_proof3_revealed_indexes
#define proof3_proof               fixture_bls12_381_shake_256_proof3_proof
#define proof3_m_1 fixture_bls12_381_shake_256_proof3_m_1
#define proof3_m_3 fixture_bls12_381_shake_256_proof3_m_3
#define proof3_m_5 fixture_bls12_381_shake_256_proof3_m_5
#define proof3_m_7 fixture_bls12_381_shake_256_proof3_m_7

#endif

int bbs_fix_proof_verify() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	if(BBS_OK != proof_verify(
				proof1_public_key,
				proof1_proof,
				sizeof(proof1_proof),
				proof1_header,
				sizeof(proof1_header),
				proof1_presentation_header,
				sizeof(proof1_presentation_header),
				proof1_revealed_indexes,
				LEN(proof1_revealed_indexes),
				1,
				proof1_m_1,
				sizeof(proof1_m_1))) {
		puts("Error during proof 1 verification");
		return 1;
	}

	if(BBS_OK != proof_verify(
				proof2_public_key,
				proof2_proof,
				sizeof(proof2_proof),
				proof2_header,
				sizeof(proof2_header),
				proof2_presentation_header,
				sizeof(proof2_presentation_header),
				proof2_revealed_indexes,
				LEN(proof2_revealed_indexes),
				10,
				proof2_m_1,
				sizeof(proof2_m_1),
				proof2_m_2,
				sizeof(proof2_m_2),
				proof2_m_3,
				sizeof(proof2_m_3),
				proof2_m_4,
				sizeof(proof2_m_4),
				proof2_m_5,
				sizeof(proof2_m_5),
				proof2_m_6,
				sizeof(proof2_m_6),
				proof2_m_7,
				sizeof(proof2_m_7),
				proof2_m_8,
				sizeof(proof2_m_8),
				proof2_m_9,
				sizeof(proof2_m_9),
				proof2_m_10,
				sizeof(proof2_m_10))) {
		puts("Error during proof 2 verification");
		return 1;
	}

	// Only some messages are being revealed here
	if(BBS_OK != proof_verify(
				proof3_public_key,
				proof3_proof,
				sizeof(proof3_proof),
				proof3_header,
				sizeof(proof3_header),
				proof3_presentation_header,
				sizeof(proof3_presentation_header),
				proof3_revealed_indexes,
				LEN(proof3_revealed_indexes),
				10,
				proof3_m_1,
				sizeof(proof3_m_1),
				proof3_m_3,
				sizeof(proof3_m_3),
				proof3_m_5,
				sizeof(proof3_m_5),
				proof3_m_7,
				sizeof(proof3_m_7))) {
		puts("Error during proof 3 verification");
		return 1;
	}

	return 0;
}

