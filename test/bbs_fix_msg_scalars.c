#include "fixtures.h"
#include "test_util.h"

typedef struct
{
	bbs_cipher_suite_t  *cipher_suite;
	const uint8_t      *msg[10];
	size_t              msg_len;
} fixture_msg_scalar;

int
bbs_fix_msg_scalars ()
{
	fixture_msg_scalar fixture = {
#ifdef LIBBBS_TEST_SUITE_SHA256
			.cipher_suite = bbs_sha256_cipher_suite,
			.msg          = {
				fixture_bls12_381_sha_256_msg_scalar_1,
				fixture_bls12_381_sha_256_msg_scalar_2,
				fixture_bls12_381_sha_256_msg_scalar_3,
				fixture_bls12_381_sha_256_msg_scalar_4,
				fixture_bls12_381_sha_256_msg_scalar_5,
				fixture_bls12_381_sha_256_msg_scalar_6,
				fixture_bls12_381_sha_256_msg_scalar_7,
				fixture_bls12_381_sha_256_msg_scalar_8,
				fixture_bls12_381_sha_256_msg_scalar_9,
				fixture_bls12_381_sha_256_msg_scalar_10,
			},
			.msg_len = sizeof(fixture_bls12_381_sha_256_msg_scalar_1)
#elif LIBBBS_TEST_SUITE_SHAKE256
			.cipher_suite = bbs_shake256_cipher_suite,
			.msg          = {
				fixture_bls12_381_shake_256_msg_scalar_1,
				fixture_bls12_381_shake_256_msg_scalar_2,
				fixture_bls12_381_shake_256_msg_scalar_3,
				fixture_bls12_381_shake_256_msg_scalar_4,
				fixture_bls12_381_shake_256_msg_scalar_5,
				fixture_bls12_381_shake_256_msg_scalar_6,
				fixture_bls12_381_shake_256_msg_scalar_7,
				fixture_bls12_381_shake_256_msg_scalar_8,
				fixture_bls12_381_shake_256_msg_scalar_9,
				fixture_bls12_381_shake_256_msg_scalar_10,
			},
			.msg_len = sizeof(fixture_bls12_381_shake_256_msg_scalar_1)
#endif
	};

	uint8_t           *fixture_ms[10] = {
		fixture_m_1, fixture_m_2, fixture_m_3, fixture_m_4, fixture_m_5, fixture_m_6,
		fixture_m_7, fixture_m_8, fixture_m_9, fixture_m_10
	};
	uint32_t           fixture_ms_len[10] = {
		sizeof(fixture_m_1), sizeof(fixture_m_2), sizeof(fixture_m_3), sizeof(fixture_m_4),
		sizeof(fixture_m_5), sizeof(fixture_m_6), sizeof(fixture_m_7), sizeof(fixture_m_8),
		sizeof(fixture_m_9), sizeof(fixture_m_10)
	};

		if (bbs_init ())
		{
			bbs_deinit ();
			return 1;
		}

		uint8_t bin[BBS_SCALAR_LEN];
		blst_scalar    scalar;

		const uint8_t *map_dst     = (uint8_t *) fixture.cipher_suite->map_dst;
		const uint8_t  map_dst_len = fixture.cipher_suite->map_dst_len;

		for (int i = 0; i < 10; i++)
		{

			hash_to_scalar (fixture.cipher_suite, &scalar, map_dst,
					map_dst_len, 1, fixture_ms[i], fixture_ms_len[i]);

			bn_write_bbs (bin, &scalar);
			ASSERT_EQ_PTR ("scalar 1 generation", bin, fixture.msg[i], fixture.msg_len);
		}
	return 0;
}
