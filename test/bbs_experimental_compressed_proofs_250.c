#define ENABLE_BENCHMARK
#include "fixtures.h"
#include "test_util.h"
#include <stdlib.h>
#include <string.h>
#define ITERATIONS 100

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
bbs_experimental_compressed_proofs_250 ()
{
	// *INDENT-OFF* - Preserve formatting
	uint8_t *msgs[256];
	uint32_t msg_lens[256];
	uint64_t disclosed_idxs[6] = { 0, 50, 100, 150, 200, 250 };
	bbs_secret_key sk;
	bbs_public_key pk;
	bbs_signature signature;

#ifdef LIBBBS_TEST_SUITE_SHA256
	proof_fixture_t tc = {
			.cipher_suite = bbs_sha256_cipher_suite,
			.pk = pk,
			.signature = signature,
			.header = fixture_bls12_381_sha_256_proof3_header,
			.header_len = sizeof(fixture_bls12_381_sha_256_proof3_header),
			.presentation_header = fixture_bls12_381_sha_256_proof3_presentation_header,
			.presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
			.disclosed_indexes = disclosed_idxs,
			.disclosed_indexes_len = 6,
			.num_messages = 256,
			.messages = msgs,
			.message_lens = msg_lens
		};
#elif LIBBBS_TEST_SUITE_SHAKE256
	proof_fixture_t tc = {
			.cipher_suite = bbs_shake256_cipher_suite,
			.pk = pk,
			.signature = signature,
			.header = fixture_bls12_381_shake_256_proof3_header,
			.header_len = sizeof(fixture_bls12_381_shake_256_proof3_header),
			.presentation_header = fixture_bls12_381_shake_256_proof3_presentation_header,
			.presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof3_presentation_header),
			.disclosed_indexes = disclosed_idxs,
			.disclosed_indexes_len = 6,
			.num_messages = 256,
			.messages = msgs,
			.message_lens = msg_lens
	};
#endif
	// *INDENT-ON* - Preserve formatting

	// Generate messages. Longer messages would basically bench the hash
	// function only.
	for(uint64_t i = 0; i < tc.num_messages; i++) {
		char msg_buf[7];
		sprintf(msg_buf, "msg%03"PRIu64, i);
		msg_lens[i] = sizeof(msg_buf);
		if(!(msgs[i] = (uint8_t*)strdup(msg_buf))) {
			printf("strdup error\n");
			return 1;
		}
	}

	// We generate our own keys and signature
	if(BBS_OK != bbs_keygen_full(tc.cipher_suite, sk, pk)) {
		printf("keygen error\n");
		return 1;
	}
	if(BBS_OK != bbs_sign_nva(tc.cipher_suite, sk, pk, signature, tc.header, tc.header_len, tc.num_messages, tc.messages, tc.message_lens)) {
		printf("signature error\n");
		return 1;
	}

	uint64_t proof_len = bbs_compressed_proof_len(tc.num_messages - tc.disclosed_indexes_len);
	//uint64_t proof_len = BBS_PROOF_LEN(tc.num_messages - tc.disclosed_indexes_len);
	uint8_t *proof = malloc(proof_len);

	printf("Projected proof length: %"PRIu64"\n", proof_len);
	printf("Required uncompressed length: %"PRIu64"\n", BBS_PROOF_LEN(tc.num_messages - tc.disclosed_indexes_len));

	if(!proof) {
		printf("malloc error\n");
		return 1;
	}

	BBS_BENCH_START (prove)
	for (int i = 0; i < ITERATIONS; i++)
	{
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
	}
	BBS_BENCH_END (prove, "Proving")

	uint8_t *disclosed_msgs[tc.disclosed_indexes_len];
	uint32_t disclosed_msg_lens[tc.disclosed_indexes_len];
	for(uint64_t i=0; i<tc.disclosed_indexes_len; i++) {
		disclosed_msgs[i]     = tc.messages    [tc.disclosed_indexes[i]];
		disclosed_msg_lens[i] = tc.message_lens[tc.disclosed_indexes[i]];
	}

	BBS_BENCH_START (vfy)
	for (int i = 0; i < ITERATIONS; i++)
	{
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
	}
	BBS_BENCH_END (vfy, "Verifying")

	free(proof);

	return 0;
}
