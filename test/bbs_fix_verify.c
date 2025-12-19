#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_verify ()
{
	int expected_return;

	for(size_t i=0; i < vectors_signature_len; i++) {
		expected_return = vectors_signature[i].result_valid ? BBS_OK : BBS_ERROR;
		if (expected_return != bbs_verify(*fixture_ciphersuite,
					vectors_signature[i].pk,
					vectors_signature[i].result,
					vectors_signature[i].header,
					vectors_signature[i].header_len,
					vectors_signature[i].num_messages,
					vectors_signature[i].msgs,
					vectors_signature[i].msg_lens))
		{
			puts ("Invalid return value during signature verification");
			return 1;
		}
	}

	return 0;
}
