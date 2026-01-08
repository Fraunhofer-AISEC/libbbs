// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_hash_to_scalar ()
{
	blst_scalar s;
	uint8_t s_buffer[BBS_SCALAR_LEN];

	for(size_t i=0; i < vectors_hash_to_scalar_len; i++) {
		hash_to_scalar (*fixture_ciphersuite,
				&s,
				vectors_hash_to_scalar[i].dst,
				vectors_hash_to_scalar[i].dst_len,
	                        1,
				vectors_hash_to_scalar[i].msg,
				vectors_hash_to_scalar[i].msg_len);
		bn_write_bbs (s_buffer, &s);
		ASSERT_EQ_PTR ("hash to scalar",
				s_buffer,
				vectors_hash_to_scalar[i].result,
				sizeof(vectors_hash_to_scalar[i].result));
	}

	return 0;
}
