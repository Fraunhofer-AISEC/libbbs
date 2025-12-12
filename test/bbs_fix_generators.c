#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_generators ()
{
	uint8_t state[48 + 8];
	blst_p1 g;
	uint8_t g_buffer[BBS_G1_ELEM_LEN];

	for(size_t i=0; i < vectors_generators_len; i++) {
		create_generator_init (*fixture_cipher_suite, state);

		for (size_t j = 0; j < vectors_generators[i].result_len; j++) {
			create_generator_next (*fixture_cipher_suite, state, &g);
			ep_write_bbs (g_buffer, &g);

			ASSERT_EQ_PTR ("generator",
					g_buffer,
					vectors_generators[i].result[j],
					sizeof(vectors_generators[i].result[j]));
		}
	}

	return 0;
}
