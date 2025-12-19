#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_sign ()
{
	bbs_signature sig;

	for(size_t i=0; i < vectors_signature_len; i++) {
		// Do not try to recreate invalid signatures
		if(!vectors_signature[i].result_valid) continue;

		if (BBS_OK != bbs_sign(*fixture_ciphersuite,
					vectors_signature[i].sk,
					vectors_signature[i].pk,
					sig,
					vectors_signature[i].header,
					vectors_signature[i].header_len,
					vectors_signature[i].num_messages,
					vectors_signature[i].msgs,
					vectors_signature[i].msg_lens))
		{
			puts ("Error during signature generation");
			return 1;
		}
		ASSERT_EQ_PTR ("signature generation",
			       sig,
			       vectors_signature[i].result,
			       sizeof(vectors_signature[i].result));
	}

	return 0;
}
