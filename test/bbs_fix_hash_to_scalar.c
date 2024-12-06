#include "fixtures.h"
#include "test_util.h"


typedef struct
{
	bbs_cipher_suite_t *cipher_suite;
	uint8_t            *msg;
	uint16_t msg_len;
	uint8_t            *dst;
	uint16_t dst_len;
	uint8_t            *scalar;
	uint16_t scalar_len;
} bbs_fix_hash_to_scalar_fixture_t;

int
bbs_fix_hash_to_scalar ()
{
#ifdef LIBBBS_TEST_SUITE_SHAKE256
	bbs_fix_hash_to_scalar_fixture_t fixture = {
		.cipher_suite = bbs_sha256_cipher_suite,
		.msg          = fixture_bls12_381_sha_256_h2s_msg, .msg_len     = 32,
		.dst          = fixture_bls12_381_sha_256_h2s_dst, .dst_len     = 48,
		.scalar       = fixture_bls12_381_sha_256_h2s_scalar, .scalar_len  = 32,
	};
#elif LIBBBS_TEST_SUITE_SHA256
	bbs_fix_hash_to_scalar_fixture_t fixture = {
		.cipher_suite = bbs_shake256_cipher_suite,
		.msg          = fixture_bls12_381_shake_256_h2s_msg, .msg_len     = 32,
		.dst          = fixture_bls12_381_shake_256_h2s_dst, .dst_len     = 50,
		.scalar       = fixture_bls12_381_shake_256_h2s_scalar, .scalar_len  = 32,
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

	uint8_t bin[BBS_SCALAR_LEN];
	bn_t scalar;
	bn_null (scalar);
	RLC_TRY {
		bn_new (scalar);
	}
	RLC_CATCH_ANY {
		puts ("Internal Error");
		return 1;
	}

	if (BBS_OK != hash_to_scalar (fixture.cipher_suite, scalar, fixture.dst, fixture.dst_len,
	                              1, fixture.msg, fixture.msg_len))
	{
		puts ("Error during hash to scalar");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs (bin, scalar);
	} RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

	ASSERT_EQ_PTR ("hash to scalar", bin, fixture.scalar, fixture.scalar_len);

	return 0;
}
