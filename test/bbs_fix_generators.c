#include "fixtures.h"
#include "test_util.h"

typedef struct
{
	uint8_t  *q_1;
	uint8_t  *hs[10];
} bbs_fix_generators_fixture_t;

int
bbs_fix_generators ()
{
#ifdef LIBBBS_TEST_SUITE_SHAKE256
	bbs_cipher_suite_t *cipher_suite = bbs_shake256_cipher_suite;
	bbs_fix_generators_fixture_t fixture = {
		.q_1 = fixture_bls12_381_shake_256_Q_1,
		.hs = {
			fixture_bls12_381_shake_256_H_1, fixture_bls12_381_shake_256_H_2,
			fixture_bls12_381_shake_256_H_3, fixture_bls12_381_shake_256_H_4,
			fixture_bls12_381_shake_256_H_5, fixture_bls12_381_shake_256_H_6,
			fixture_bls12_381_shake_256_H_7, fixture_bls12_381_shake_256_H_8,
			fixture_bls12_381_shake_256_H_9, fixture_bls12_381_shake_256_H_10
		},
	};
#elif LIBBBS_TEST_SUITE_SHA256
	bbs_cipher_suite_t *cipher_suite = bbs_sha256_cipher_suite;
	bbs_fix_generators_fixture_t fixture = {
		.q_1 = fixture_bls12_381_sha_256_Q_1,
		.hs = {
			fixture_bls12_381_sha_256_H_1, fixture_bls12_381_sha_256_H_2,
			fixture_bls12_381_sha_256_H_3, fixture_bls12_381_sha_256_H_4,
			fixture_bls12_381_sha_256_H_5, fixture_bls12_381_sha_256_H_6,
			fixture_bls12_381_sha_256_H_7, fixture_bls12_381_sha_256_H_8,
			fixture_bls12_381_sha_256_H_9, fixture_bls12_381_sha_256_H_10
		},
	};
#endif


	printf("Testing %s\n", cipher_suite->cipher_suite_id);

	if (bbs_init ())
	{
		bbs_deinit ();
		return 1;
	}

	uint8_t state[48 + 8];
	uint8_t bin[BBS_G1_ELEM_LEN];
	ep_t generator;
	ep_null (generator);
	RLC_TRY {
		ep_new (generator);         // Yes, this might leak. This is a test and thus
		                            // short lived
	}
	RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

	const uint8_t *api_id     = (uint8_t *) cipher_suite->api_id;
	const uint8_t api_id_len = cipher_suite->api_id_len;

	if (BBS_OK != create_generator_init (cipher_suite, state, api_id, api_id_len))
	{
		puts ("Error during generator initialization");
		return 1;
	}

	DEBUG("TEST", state, 56);

	if (BBS_OK != create_generator_next (cipher_suite, state, generator, api_id,
	                                     api_id_len))
	{
		puts ("Error during generator Q_1 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs (bin, generator);
	} RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

	ASSERT_EQ_PTR ("generator Q_1 creation", bin, fixture.q_1, BBS_G1_ELEM_LEN);

	for (int j = 0; j < 10; j++) {
		if (BBS_OK != create_generator_next (cipher_suite, state, generator, api_id,
		                                     api_id_len))
		{
			printf ("Error during generator %d creation", j + 1);
			return 1;
		}
		RLC_TRY {
			ep_write_bbs (bin, generator);
		} RLC_CATCH_ANY { puts ("Internal Error"); return 1; }
		ASSERT_EQ_PTR ("generator creation", bin, fixture.hs[j], BBS_G1_ELEM_LEN);
	}
	return 0;
}
