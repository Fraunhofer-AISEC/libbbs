// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"

int
bbs_fix_proof_verify ()
{
	int expected_return;

	for(size_t i=0; i < vectors_proof_len; i++) {
		bbs_message disclosed_msgs[vectors_proof[i].num_messages];
		for(size_t j=0; j<vectors_proof[i].num_messages; j++) {
			bool disclosed = false;
			for(size_t k=0; k<vectors_proof[i].disclosed_indexes_len; k++)
				if(vectors_proof[i].disclosed_indexes[k] == j) disclosed = true;
			disclosed_msgs[j] = disclosed ? vectors_proof[i].msgs[j] : BBS_UNDISCLOSED_MSG;
		}
		expected_return = vectors_proof[i].result_valid ? BBS_OK : BBS_ERROR;
		if (expected_return != bbs_proof_verify(*fixture_ciphersuite,
					vectors_proof[i].pk,
					vectors_proof[i].result,
					vectors_proof[i].header,
					vectors_proof[i].presentation_header,
					vectors_proof[i].disclosed_indexes,
					vectors_proof[i].disclosed_indexes_len,
					disclosed_msgs,
					vectors_proof[i].num_messages))
		{
			printf ("Invalid return value during proof verification\n");
			return 1;
		}
	}

	return 0;
}
