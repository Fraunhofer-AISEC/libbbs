#include "fixtures.h"
#include "test_util.h"

// Mocked random scalars for bbs_proof_gen_det
int mocked_prf(
		bn_t out,
		uint8_t input_type,
		uint64_t input,
		void* cookie) {
	uint8_t *rand = (uint8_t*)cookie;
	int res = BBS_ERROR;

	if(0 == input_type && 10 > input) {
		// msg_tilde
		rand += (5 + input) * 48;
	}
	else if (0 == input && 5 >= input_type) {
		// other stuff
		rand += (input_type - 1) * 48;
	}
	else goto cleanup;

	RLC_TRY {
		bn_read_bin(out, rand, 48);
		bn_mod(out, out, &(core_get()->ep_r));
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}

int fill_randomness(
		uint8_t *rand,
		int count,
		const uint8_t *seed,
		uint64_t seed_len,
		const uint8_t *dst,
		uint64_t dst_len
	) {
	int ret = BBS_ERROR;
	RLC_TRY {
		md_xmd(rand, count * 48, seed, seed_len, dst, dst_len);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}
	ret = BBS_OK;
cleanup:
	return ret;
}

int mocked_proof_gen(
		const bbs_public_key  pk,
		const bbs_signature   signature,
		uint8_t              *proof,
		const uint8_t        *header,
		uint64_t              header_len,
		const uint8_t        *presentation_header,
		uint64_t              presentation_header_len,
		const uint64_t       *disclosed_indexes,
		uint64_t              disclosed_indexes_len,
		uint64_t              num_messages,
		...
	) {
	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];
	va_list ap;
	int ret = BBS_ERROR;
	va_start(ap, num_messages);

	if(BBS_OK != fill_randomness(
				randomness,
				5 + num_messages - disclosed_indexes_len,
				fixture_bls12_381_sha_256_proof_SEED,
				sizeof(fixture_bls12_381_sha_256_proof_SEED),
				fixture_bls12_381_sha_256_proof_DST,
				sizeof(fixture_bls12_381_sha_256_proof_DST)
				)) {
		goto cleanup;
	}
	if (BBS_OK != bbs_proof_gen_det (pk, signature, proof, header, header_len,
					 presentation_header, presentation_header_len,
					 disclosed_indexes, disclosed_indexes_len,
					 num_messages, mocked_prf, randomness, ap))
	{
		goto cleanup;
	}

	ret = BBS_OK;
cleanup:
	va_end(ap);
	return ret;
}

int bbs_fix_proof_gen() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];

	// Randomness generation self check, to catch any errors related to this
	// step
	uint8_t scalar_buffer[BBS_SCALAR_LEN];
	bn_t scalar;

	bn_null(scalar);
	RLC_TRY { bn_new(scalar) }
	RLC_CATCH_ANY {
		puts("Internal error");
		return 1;
	}
	if(BBS_OK != fill_randomness(
				randomness,
				10,
				fixture_bls12_381_sha_256_proof_SEED,
				LEN(fixture_bls12_381_sha_256_proof_SEED),
				fixture_bls12_381_sha_256_proof_DST,
				LEN(fixture_bls12_381_sha_256_proof_DST))) {
		puts("Error during randomness generation self test");
		return 1;
	}
#define WRITE_SCALAR RLC_TRY { bn_write_bbs(scalar_buffer, scalar); } \
	             RLC_CATCH_ANY { puts("Write error"); return 1;}
	if(BBS_OK != mocked_prf(scalar, 1, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_1 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_1);

	if(BBS_OK != mocked_prf(scalar, 2, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_2 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_2);

	if(BBS_OK != mocked_prf(scalar, 3, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_3 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_3);

	if(BBS_OK != mocked_prf(scalar, 4, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_4 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_4);

	if(BBS_OK != mocked_prf(scalar, 5, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_5 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_5);

	if(BBS_OK != mocked_prf(scalar, 0, 0, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_6 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_6);

	if(BBS_OK != mocked_prf(scalar, 0, 1, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_7 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_7);

	if(BBS_OK != mocked_prf(scalar, 0, 2, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_8 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_8);

	if(BBS_OK != mocked_prf(scalar, 0, 3, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_9 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_9);

	if(BBS_OK != mocked_prf(scalar, 0, 4, randomness)) {
		puts("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ("scalar_10 test", scalar_buffer, fixture_bls12_381_sha_256_proof_random_scalar_10);

	uint8_t proof1[BBS_PROOF_LEN(0)];
        BBS_BENCH_START()
	if(BBS_OK != mocked_proof_gen(
				fixture_bls12_381_sha_256_proof1_public_key,
				fixture_bls12_381_sha_256_proof1_signature,
				proof1,
				fixture_bls12_381_sha_256_proof1_header,
				sizeof(fixture_bls12_381_sha_256_proof1_header),
				fixture_bls12_381_sha_256_proof1_presentation_header,
				sizeof(fixture_bls12_381_sha_256_proof1_presentation_header),
				fixture_bls12_381_sha_256_proof1_revealed_indexes,
				LEN(fixture_bls12_381_sha_256_proof1_revealed_indexes),
				1,
				fixture_bls12_381_sha_256_proof1_m_1,
				sizeof(fixture_bls12_381_sha_256_proof1_m_1))) {
		puts("Error during proof 1 generation");
		return 1;
	}
        BBS_BENCH_END("Valid Single Message Proof")
	ASSERT_EQ("proof 1 generation", proof1, fixture_bls12_381_sha_256_proof1_proof);

	uint8_t proof2[BBS_PROOF_LEN(0)];
	if(BBS_OK != mocked_proof_gen(
				fixture_bls12_381_sha_256_proof2_public_key,
				fixture_bls12_381_sha_256_proof2_signature,
				proof2,
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
		puts("Error during proof 2 generation");
		return 1;
	}
        BBS_BENCH_END("Valid Multi-Message, All Messages Disclosed Proof")
	ASSERT_EQ("proof 2 generation", proof2, fixture_bls12_381_sha_256_proof2_proof);

	// Only some messages are being revealed here
	uint8_t proof3[BBS_PROOF_LEN(6)];
	if(BBS_OK != mocked_proof_gen(
				fixture_bls12_381_sha_256_proof3_public_key,
				fixture_bls12_381_sha_256_proof3_signature,
				proof3,
				fixture_bls12_381_sha_256_proof3_header,
				sizeof(fixture_bls12_381_sha_256_proof3_header),
				fixture_bls12_381_sha_256_proof3_presentation_header,
				sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
				fixture_bls12_381_sha_256_proof3_revealed_indexes,
				LEN(fixture_bls12_381_sha_256_proof3_revealed_indexes),
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
		puts("Error during proof 3 generation");
		return 1;
	}
        BBS_BENCH_END("Valid Multi-Message, Some Messages Disclosed Proof")
	ASSERT_EQ("proof 3 generation", proof3, fixture_bls12_381_sha_256_proof3_proof);

	bn_free(scalar);
	return 0;
}

