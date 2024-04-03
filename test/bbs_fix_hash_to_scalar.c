#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define fixture_msg             fixture_bls12_381_sha_256_h2s_msg
#define fixture_msg_len         32
#define fixture_dst             fixture_bls12_381_sha_256_h2s_dst
#define fixture_dst_len         48
#define fixture_expected_scalar fixture_bls12_381_sha_256_h2s_scalar
#define fixture_scalar_len      32
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define fixture_msg             fixture_bls12_381_shake_256_h2s_msg
#define fixture_msg_len         32
#define fixture_dst             fixture_bls12_381_shake_256_h2s_dst
#define fixture_dst_len         50
#define fixture_expected_scalar fixture_bls12_381_shake_256_h2s_scalar
#define fixture_scalar_len      32
#endif

int
bbs_fix_hash_to_scalar ()
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

	uint8_t bin[BBS_SCALAR_LEN];
	bn_t    scalar;
	bn_null (scalar);
	RLC_TRY {
		bn_new (scalar);
	}
	RLC_CATCH_ANY {
		puts ("Internal Error");
		return 1;
	}

	if (BBS_OK != hash_to_scalar (&bbs_sha256_cipher_suite, scalar, fixture_dst, fixture_dst_len, fixture_msg,
				      fixture_msg_len, 0))
	{
		puts ("Error during hash to scalar");
		return 1;
	}
	RLC_TRY {
		bn_write_bbs (bin, scalar);
	} RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

	ASSERT_EQ ("hash to scalar", bin, fixture_expected_scalar);

	return 0;
}
