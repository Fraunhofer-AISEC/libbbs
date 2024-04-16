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
	bbs_cipher_suite_t           cipher_suites[] = {
		bbs_sha256_cipher_suite, bbs_shake256_cipher_suite
	};

	bbs_fix_generators_fixture_t test_cases[] = {
		{
			.q_1 = fixture_bls12_381_sha_256_Q_1, 
			.hs = {
				fixture_bls12_381_sha_256_H_1, fixture_bls12_381_sha_256_H_2,
				fixture_bls12_381_sha_256_H_3, fixture_bls12_381_sha_256_H_4,
				fixture_bls12_381_sha_256_H_5, fixture_bls12_381_sha_256_H_6,
				fixture_bls12_381_sha_256_H_7, fixture_bls12_381_sha_256_H_8,
				fixture_bls12_381_sha_256_H_9, fixture_bls12_381_sha_256_H_10
			},
		},
		{
			.q_1 = fixture_bls12_381_shake_256_Q_1, 
			.hs = {
				fixture_bls12_381_shake_256_H_1, fixture_bls12_381_shake_256_H_2,
				fixture_bls12_381_shake_256_H_3, fixture_bls12_381_shake_256_H_4,
				fixture_bls12_381_shake_256_H_5, fixture_bls12_381_shake_256_H_6,
				fixture_bls12_381_shake_256_H_7, fixture_bls12_381_shake_256_H_8,
				fixture_bls12_381_shake_256_H_9, fixture_bls12_381_shake_256_H_10
			},
		},
	};


	for (int i = 0; i < 2; i++)
	{
		bbs_cipher_suite_t cipher_suite = cipher_suites[i];
		bbs_fix_generators_fixture_t fixture = test_cases[i];

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

		uint8_t state[48 + 8];
		uint8_t bin[BBS_G1_ELEM_LEN];
		ep_t    generator;
		ep_null (generator);
		RLC_TRY {
			ep_new (generator); // Yes, this might leak. This is a test and thus
			                    // short lived
		}
		RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

		const uint8_t *api_id     = (uint8_t *) cipher_suite.api_id;
		const uint8_t  api_id_len = cipher_suite.api_id_len;

		if (BBS_OK != create_generator_init (&cipher_suite, state, api_id, api_id_len))
		{
			puts ("Error during generator initialization");
			return 1;
		}

		if (BBS_OK != create_generator_next (&cipher_suite, state, generator, api_id,
						     api_id_len))
		{
			puts ("Error during generator Q_1 creation");
			return 1;
		}
		RLC_TRY {
			ep_write_bbs (bin, generator);
		} RLC_CATCH_ANY { puts ("Internal Error"); return 1; }

		ASSERT_EQ ("generator Q_1 creation", bin, fixture.q_1);

		for (int j = 0; j < 10; j++) {
			if (BBS_OK != create_generator_next (&cipher_suite, state, generator, api_id,
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
	}
}
