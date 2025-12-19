#include "fixtures.h"
#include "test_util.h"

int
bbs_fix_proof_verify ()
{
	int expected_return;

	for(size_t i=0; i < vectors_proof_len; i++) {
		const void *disclosed_msgs[vectors_proof[i].disclosed_indexes_len];
		size_t disclosed_msg_lens[vectors_proof[i].disclosed_indexes_len];
		for(size_t j=0; j<vectors_proof[i].disclosed_indexes_len; j++) {
			disclosed_msgs    [j] = vectors_proof[i].msgs    [vectors_proof[i].disclosed_indexes[j]];
			disclosed_msg_lens[j] = vectors_proof[i].msg_lens[vectors_proof[i].disclosed_indexes[j]];
		}
		expected_return = vectors_proof[i].result_valid ? BBS_OK : BBS_ERROR;
		if (expected_return != bbs_proof_verify(*fixture_ciphersuite,
					vectors_proof[i].pk,
					vectors_proof[i].result,
					vectors_proof[i].result_len,
					vectors_proof[i].header,
					vectors_proof[i].header_len,
					vectors_proof[i].presentation_header,
					vectors_proof[i].presentation_header_len,
					vectors_proof[i].disclosed_indexes,
					vectors_proof[i].disclosed_indexes_len,
					vectors_proof[i].num_messages,
					disclosed_msgs,
					disclosed_msg_lens))
		{
			printf ("Invalid return value during proof verification\n");
			return 1;
		}
	}

	return 0;
}
