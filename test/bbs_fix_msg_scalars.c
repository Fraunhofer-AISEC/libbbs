#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define cipher_suite bbs_sha256_cipher_suite
#define fixture_msg_scalar_1 fixture_bls12_381_sha_256_msg_scalar_1
#define fixture_msg_scalar_2 fixture_bls12_381_sha_256_msg_scalar_2
#define fixture_msg_scalar_3 fixture_bls12_381_sha_256_msg_scalar_3
#define fixture_msg_scalar_4 fixture_bls12_381_sha_256_msg_scalar_4
#define fixture_msg_scalar_5 fixture_bls12_381_sha_256_msg_scalar_5
#define fixture_msg_scalar_6 fixture_bls12_381_sha_256_msg_scalar_6
#define fixture_msg_scalar_7 fixture_bls12_381_sha_256_msg_scalar_7
#define fixture_msg_scalar_8 fixture_bls12_381_sha_256_msg_scalar_8
#define fixture_msg_scalar_9 fixture_bls12_381_sha_256_msg_scalar_9
#define fixture_msg_scalar_10 fixture_bls12_381_sha_256_msg_scalar_10
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define cipher_suite bbs_shake256_cipher_suite
#define fixture_msg_scalar_1 fixture_bls12_381_shake_256_msg_scalar_1
#define fixture_msg_scalar_2 fixture_bls12_381_shake_256_msg_scalar_2
#define fixture_msg_scalar_3 fixture_bls12_381_shake_256_msg_scalar_3
#define fixture_msg_scalar_4 fixture_bls12_381_shake_256_msg_scalar_4
#define fixture_msg_scalar_5 fixture_bls12_381_shake_256_msg_scalar_5
#define fixture_msg_scalar_6 fixture_bls12_381_shake_256_msg_scalar_6
#define fixture_msg_scalar_7 fixture_bls12_381_shake_256_msg_scalar_7
#define fixture_msg_scalar_8 fixture_bls12_381_shake_256_msg_scalar_8
#define fixture_msg_scalar_9 fixture_bls12_381_shake_256_msg_scalar_9
#define fixture_msg_scalar_10 fixture_bls12_381_shake_256_msg_scalar_10

#endif
int bbs_fix_msg_scalars() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	uint8_t bin[BBS_SCALAR_LEN];
	bn_t scalar;
	bn_null(scalar);
	RLC_TRY {
		bn_new(scalar); // Yes, this might leak. This is a test and thus
				// short lived
	}
	RLC_CATCH_ANY { puts("Internal Error"); return 1; }

	const uint8_t *map_dst = (uint8_t *) cipher_suite.map_dst;
	const uint8_t map_dst_len = cipher_suite.map_dst_len;

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_1, sizeof(fixture_m_1), 0)) {
		puts("Error during hash to scalar for message 1");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 1 generation", bin, fixture_msg_scalar_1);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_2, sizeof(fixture_m_2), 0)) {
		puts("Error during hash to scalar for message 2");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 2 generation", bin, fixture_msg_scalar_2);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_3, sizeof(fixture_m_3), 0)) {
		puts("Error during hash to scalar for message 3");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 3 generation", bin, fixture_msg_scalar_3);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_4, sizeof(fixture_m_4), 0)) {
		puts("Error during hash to scalar for message 4");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 4 generation", bin, fixture_msg_scalar_4);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_5, sizeof(fixture_m_5), 0)) {
		puts("Error during hash to scalar for message 5");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 5 generation", bin, fixture_msg_scalar_5);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_6, sizeof(fixture_m_6), 0)) {
		puts("Error during hash to scalar for message 6");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 6 generation", bin, fixture_msg_scalar_6);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_7, sizeof(fixture_m_7), 0)) {
		puts("Error during hash to scalar for message 7");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 7 generation", bin, fixture_msg_scalar_7);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_8, sizeof(fixture_m_8), 0)) {
		puts("Error during hash to scalar for message 8");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 8 generation", bin, fixture_msg_scalar_8);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_9, sizeof(fixture_m_9), 0)) {
		puts("Error during hash to scalar for message 9");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 9 generation", bin, fixture_msg_scalar_9);

	if(BBS_OK != hash_to_scalar(&cipher_suite, scalar, map_dst, map_dst_len, fixture_m_10, sizeof(fixture_m_10), 0)) {
		puts("Error during hash to scalar for message 10");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs(bin, scalar);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("scalar 10 generation", bin, fixture_msg_scalar_10);

	bn_free(scalar);
	return 0;
}

