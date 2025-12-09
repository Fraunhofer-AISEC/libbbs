#include "fixtures.h"
#include "test_util.h"
#include <stdlib.h>

// Not yet in any header file

int
bbs_compressed_proof_gen_nva (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	const uint64_t       *disclosed_indexes,
	uint64_t              disclosed_indexes_len,
	uint64_t              num_messages,
	uint8_t**             messages,
	uint32_t*             messages_lens
	);
int
bbs_compressed_proof_verify_nva (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const uint8_t        *proof,
	uint64_t              proof_len,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	const uint64_t       *disclosed_indexes,
	uint64_t              disclosed_indexes_len,
	uint64_t              num_messages,
	uint8_t**             messages,
	uint32_t*             messages_lens
	);
uint64_t bbs_compressed_proof_len(uint64_t num_undisclosed);

// -----------------------------------------------------------------------------

typedef struct
{
	bbs_cipher_suite_t *cipher_suite;
	uint8_t *pk;
	uint8_t *signature;
	const uint8_t *header;
	uint64_t header_len;
	const uint8_t *presentation_header;
	uint64_t presentation_header_len;
	const uint64_t *disclosed_indexes;
	uint64_t disclosed_indexes_len;
	uint64_t num_messages;
	uint8_t** messages;
	uint32_t *message_lens;
} proof_fixture_t;

int
bbs_experimental_compressed_proofs ()
{
	//const uint64_t disclosed[] = { 0,1,2,3,4,5,6,7 };
	// *INDENT-OFF* - Preserve formatting
#ifdef LIBBBS_TEST_SUITE_SHA256
	uint8_t *msgs[] = {
				fixture_bls12_381_sha_256_proof3_m_1,
				fixture_bls12_381_sha_256_proof3_m_2,
				fixture_bls12_381_sha_256_proof3_m_3,
				fixture_bls12_381_sha_256_proof3_m_4,
				fixture_bls12_381_sha_256_proof3_m_5,
				fixture_bls12_381_sha_256_proof3_m_6,
				fixture_bls12_381_sha_256_proof3_m_7,
				fixture_bls12_381_sha_256_proof3_m_8,
				fixture_bls12_381_sha_256_proof3_m_9,
				fixture_bls12_381_sha_256_proof3_m_10
	};
	uint32_t msg_lens[] = {
				sizeof(fixture_bls12_381_sha_256_proof3_m_1),
				sizeof(fixture_bls12_381_sha_256_proof3_m_2),
				sizeof(fixture_bls12_381_sha_256_proof3_m_3),
				sizeof(fixture_bls12_381_sha_256_proof3_m_4),
				sizeof(fixture_bls12_381_sha_256_proof3_m_5),
				sizeof(fixture_bls12_381_sha_256_proof3_m_6),
				sizeof(fixture_bls12_381_sha_256_proof3_m_7),
				sizeof(fixture_bls12_381_sha_256_proof3_m_8),
				sizeof(fixture_bls12_381_sha_256_proof3_m_9),
				0 /* m_10 */
	};
	proof_fixture_t tc = {
			.cipher_suite = bbs_sha256_cipher_suite,
			.pk = fixture_bls12_381_sha_256_proof3_public_key,
			.signature = fixture_bls12_381_sha_256_proof3_signature,
			.header = fixture_bls12_381_sha_256_proof3_header,
			.header_len = sizeof(fixture_bls12_381_sha_256_proof3_header),
			.presentation_header = fixture_bls12_381_sha_256_proof3_presentation_header,
			.presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
			.disclosed_indexes = fixture_bls12_381_sha_256_proof3_revealed_indexes,
			.disclosed_indexes_len = LEN (fixture_bls12_381_sha_256_proof3_revealed_indexes),
			//.disclosed_indexes = disclosed,
			//.disclosed_indexes_len = LEN(disclosed),
			.num_messages = 10,
			.messages = msgs,
			.message_lens = msg_lens
		};
#elif LIBBBS_TEST_SUITE_SHAKE256
	uint8_t *msgs[] = {
				fixture_bls12_381_shake_256_proof3_m_1,
				fixture_bls12_381_shake_256_proof3_m_2,
				fixture_bls12_381_shake_256_proof3_m_3,
				fixture_bls12_381_shake_256_proof3_m_4,
				fixture_bls12_381_shake_256_proof3_m_5,
				fixture_bls12_381_shake_256_proof3_m_6,
				fixture_bls12_381_shake_256_proof3_m_7,
				fixture_bls12_381_shake_256_proof3_m_8,
				fixture_bls12_381_shake_256_proof3_m_9,
				fixture_bls12_381_shake_256_proof3_m_10
	};
	uint32_t msg_lens[] = {
				sizeof(fixture_bls12_381_shake_256_proof3_m_1),
				sizeof(fixture_bls12_381_shake_256_proof3_m_2),
				sizeof(fixture_bls12_381_shake_256_proof3_m_3),
				sizeof(fixture_bls12_381_shake_256_proof3_m_4),
				sizeof(fixture_bls12_381_shake_256_proof3_m_5),
				sizeof(fixture_bls12_381_shake_256_proof3_m_6),
				sizeof(fixture_bls12_381_shake_256_proof3_m_7),
				sizeof(fixture_bls12_381_shake_256_proof3_m_8),
				sizeof(fixture_bls12_381_shake_256_proof3_m_9),
				0 /* m_10 */
	};
	proof_fixture_t tc = {
			.cipher_suite = bbs_shake256_cipher_suite,
			.pk = fixture_bls12_381_shake_256_proof3_public_key,
			.signature = fixture_bls12_381_shake_256_proof3_signature,
			.header = fixture_bls12_381_shake_256_proof3_header,
			.header_len = sizeof(fixture_bls12_381_shake_256_proof3_header),
			.presentation_header = fixture_bls12_381_shake_256_proof3_presentation_header,
			.presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof3_presentation_header),
			.disclosed_indexes = fixture_bls12_381_shake_256_proof3_revealed_indexes,
			.disclosed_indexes_len = LEN (fixture_bls12_381_shake_256_proof3_revealed_indexes),
			//.disclosed_indexes = disclosed,
			//.disclosed_indexes_len = LEN(disclosed),
			.num_messages = 10,
			.messages = msgs,
			.message_lens = msg_lens
	};
#endif
	// *INDENT-ON* - Preserve formatting

	uint64_t proof_len = bbs_compressed_proof_len(tc.num_messages - tc.disclosed_indexes_len);
	uint8_t *proof = malloc(proof_len);

	if(!proof) {
		printf("malloc error\n");
		return 1;
	}
	if(BBS_OK != bbs_compressed_proof_gen_nva(tc.cipher_suite,
				tc.pk,
				tc.signature,
				proof,
				tc.header,
				tc.header_len,
				tc.presentation_header,
				tc.presentation_header_len,
				tc.disclosed_indexes,
				tc.disclosed_indexes_len,
				tc.num_messages,
				tc.messages,
				tc.message_lens))
	{
		printf ("Error during compressed proof generation\n");
		return 1;
	}

	uint8_t *disclosed_msgs[tc.disclosed_indexes_len];
	uint32_t disclosed_msg_lens[tc.disclosed_indexes_len];
	for(uint64_t i=0; i<tc.disclosed_indexes_len; i++) {
		disclosed_msgs[i]     = tc.messages    [tc.disclosed_indexes[i]];
		disclosed_msg_lens[i] = tc.message_lens[tc.disclosed_indexes[i]];
	}

	if(BBS_OK != bbs_compressed_proof_verify_nva(tc.cipher_suite,
				tc.pk,
				proof,
				proof_len,
				tc.header,
				tc.header_len,
				tc.presentation_header,
				tc.presentation_header_len,
				tc.disclosed_indexes,
				tc.disclosed_indexes_len,
				tc.num_messages,
				disclosed_msgs,
				disclosed_msg_lens))
	{
		printf ("Error during compressed proof verification\n");
		return 1;
	}

	free(proof);

	return 0;
}
