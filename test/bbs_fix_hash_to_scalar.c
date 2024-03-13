#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define msg             fixture_bls12_381_sha_256_h2s_msg;
#define dst             fixture_bls12_381_sha_256_h2s_dst;
#define dst_len         48;
#define expected_scalar fixture_bls12_381_sha_256_h2s_scalar;
#define scalar_len      32;
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define msg             fixture_bls12_381_shake_256_h2s_msg fixture_m_1
#define dst             fixture_bls12_381_shake_256_h2s_dst;
#define dst_len         48;
#define expected_scalar fixture_bls12_381_shake_256_h2s_scalar;
#define scalar_len      32;
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

	bn_t out;
	bn_null (out);
	RLC_TRY {
		bn_new (out);
	}
	RLC_CATCH_ANY {
		puts ("Internal Error");
		return 1;
	}

	if (BBS_OK != hash_to_scalar (out, fixture_bls12_381_sha_256_h2s_dst, 48,
				      fixture_bls12_381_sha_256_h2s_msg, 32, 0))
	{
		puts ("Error during hash to scalar");
		return 1;
	}

	// Determine the length of the bn in bytes
	int bn_len = bn_size_bin (out);

	// Dynamically allocate a temporary buffer for the byte array
	uint8_t*buffer = (uint8_t*) malloc (bn_len * sizeof(uint8_t));
	if (buffer == NULL)
	{
		// Handle memory allocation failure
		printf ("Memory allocation failed.\n");
		return 1;
	}

	// Convert bn_t to byte array (big-endian)
	bn_write_bin (buffer, bn_len, out);

	ASSERT_EQ ("hash to scalar", buffer, fixture_bls12_381_sha_256_h2s_scalar);

	return 0;
}
