#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_keygen ()
{
	bbs_secret_key sk;
	bbs_public_key pk;

	for(size_t i=0; i < vectors_keygen_len; i++) {
		if (BBS_OK != bbs_keygen(*fixture_cipher_suite,
					sk,
					vectors_keygen[i].key_material,
					vectors_keygen[i].key_material_len,
					vectors_keygen[i].key_info,
					vectors_keygen[i].key_info_len,
					vectors_keygen[i].key_dst,
					vectors_keygen[i].key_dst_len))
		{
			puts ("Error during secret key generation");
			return 1;
		}
		ASSERT_EQ_PTR ("secret key generation",
				sk,
				vectors_keygen[i].result_sk,
				sizeof(vectors_keygen[i].result_sk));

		if (BBS_OK != bbs_sk_to_pk (*fixture_cipher_suite,
					vectors_keygen[i].result_sk,
					pk))
		{
			puts ("Error during public key generation");
			return 1;
		}
		ASSERT_EQ_PTR ("public key generation",
				pk,
				vectors_keygen[i].result_pk,
				sizeof(vectors_keygen[i].result_pk));
	}

	return 0;
}
