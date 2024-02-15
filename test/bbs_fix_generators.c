#include "fixtures.h"
#include "test_util.h"

int bbs_fix_generators() {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}
	if (pc_param_set_any() != RLC_OK) {
		core_clean();
		return 1;
	}

	uint8_t state[48 + 8];
	uint8_t bin[BBS_G1_ELEM_LEN];
	ep_t generator;
	ep_null(generator);
	RLC_TRY {
		ep_new(generator); // Yes, this might leak. This is a test and thus
				   // short lived
	}
	RLC_CATCH_ANY { puts("Internal Error"); return 1; }

	static uint8_t api_id[] = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
	static uint8_t api_id_len = 44;

	if(BBS_OK != create_generator_init(state, api_id, api_id_len)) {
		puts("Error during generator initialization");
		return 1;
	}

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator Q_1 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator Q_1 creation", bin, fixture_bls12_381_sha_256_Q_1);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_1 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_1 creation", bin, fixture_bls12_381_sha_256_H_1);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_2 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_2 creation", bin, fixture_bls12_381_sha_256_H_2);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_3 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_3 creation", bin, fixture_bls12_381_sha_256_H_3);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_4 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_4 creation", bin, fixture_bls12_381_sha_256_H_4);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_5 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_5 creation", bin, fixture_bls12_381_sha_256_H_5);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_6 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_6 creation", bin, fixture_bls12_381_sha_256_H_6);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_7 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_7 creation", bin, fixture_bls12_381_sha_256_H_7);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_8 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_8 creation", bin, fixture_bls12_381_sha_256_H_8);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_9 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_9 creation", bin, fixture_bls12_381_sha_256_H_9);

	if(BBS_OK != create_generator_next(state, generator, api_id, api_id_len)) {
		puts("Error during generator H_10 creation");
		return 1;
	}
	RLC_TRY {
		ep_write_bbs(bin, generator);
	} RLC_CATCH_ANY { puts("Internal Error"); return 1; }
	ASSERT_EQ("generator H_10 creation", bin, fixture_bls12_381_sha_256_H_10);

	ep_free(generator);
	return 0;
}

