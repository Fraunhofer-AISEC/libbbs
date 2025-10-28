#include "fixtures.h"
#include "test_util.h"
#include <stdbool.h>

// BEGIN declarations of bbs.c
// These are usually static, but made global in a modified library
typedef struct {
	bbs_cipher_suite_t   *cipher_suite;
	uint8_t                generator_ctx[48 + 8];
	union bbs_hash_context dom_ctx;
	blst_p1 Q_1;
	// Final output
	blst_p1 B;
	// Temporary outputs
	blst_p1 H_i;
	blst_scalar msg_scalar; // Also used for domain
} bbs_acc_ctx;
typedef struct {
	bbs_acc_ctx acc;
	blst_p1 T2;
	union bbs_hash_context ch_ctx;
	uint64_t disclosed_ctr;
	uint64_t undisclosed_ctr;
	bbs_bn_prf           *prf;
	void                 *prf_cookie;
} bbs_proof_gen_ctx;

void
bbs_proof_gen_init (
	bbs_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	);

void
bbs_proof_gen_update (
	bbs_proof_gen_ctx *ctx,
	uint8_t *proof,
	uint8_t *msg,
	uint64_t msg_len,
	bool disclosed
	);

int
bbs_proof_gen_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_signature   signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	uint64_t              num_messages,
	uint64_t              num_disclosed
	);
// END declarations of bbs.c

typedef struct
{
	bbs_cipher_suite_t  *cipher_suite;

	uint8_t            *proof_SEED;
	size_t proof_SEED_len;

	uint8_t            *proof_DST;
	size_t proof_DST_len;

	uint8_t            *proof_random_scalar[10];
	size_t proof_random_scalar_len[10];

	uint8_t            *proof1_public_key;
	uint8_t            *proof1_signature;
	size_t proof1_signature_len;
	uint8_t            *proof1_header;
	size_t proof1_header_len;
	uint8_t            *proof1_presentation_header;
	size_t proof1_presentation_header_len;
	uint64_t           *proof1_revealed_indexes;
	size_t proof1_revealed_indexes_len;
	uint8_t            *proof1_m_1;
	size_t proof1_m_1_len;
	uint8_t            *proof1_proof;
	size_t proof1_proof_len;

	uint8_t            *proof2_public_key;
	uint8_t            *proof2_signature;
	size_t proof2_signature_len;
	uint8_t            *proof2_header;
	size_t proof2_header_len;
	uint8_t            *proof2_presentation_header;
	size_t proof2_presentation_header_len;
	uint64_t           *proof2_revealed_indexes;
	size_t proof2_revealed_indexes_len;
	uint8_t            *proof2_m[10];
	size_t proof2_m_len[10];
	uint8_t            *proof2_proof;
	size_t proof2_proof_len;

	uint8_t            *proof3_public_key;
	uint8_t            *proof3_signature;
	size_t proof3_signature_len;
	uint8_t            *proof3_header;
	size_t proof3_header_len;
	uint8_t            *proof3_presentation_header;
	size_t proof3_presentation_header_len;
	uint64_t           *proof3_revealed_indexes;
	size_t proof3_revealed_indexes_len;
	uint8_t            *proof3_proof;
	size_t proof3_proof_len;
} fixture_proof_gen_t;

// Mocked random scalars for bbs_proof_gen_det
// The randomness-array contains r1, r3^-1, e~, r1~, r3~, and the m~
// We return on (input_type, input):
// (0,x) -> rand[x+2], (1,0) -> rand[0], (2,0) -> rand[1]
void
mocked_prf (
	bbs_cipher_suite_t *cipher_suite,
	blst_scalar *out,
	uint8_t input_type,
	uint64_t input,
	void     *cookie
	)
{
	(void)cipher_suite;
	uint8_t *rand = (uint8_t*) cookie;

	// TODO: Fix mapping
	if (0 == input_type && 10 > input)
	{
		// commitment randomness
		rand += (2 + input) * 48;
	}
	else if (0 == input && 2 >= input_type)
	{
		// blinding randomness
		rand += (input_type - 1) * 48;
	}
	else return; // Will most likely violate the fixtures

	blst_scalar_from_be_bytes(out, rand, 48);
}


void
fill_randomness (
	bbs_cipher_suite_t  *cipher_suite,
	uint8_t            *rand,
	int count,
	const uint8_t      *seed,
	uint64_t seed_len,
	const uint8_t      *dst,
	uint64_t dst_len
	)
{
	union bbs_hash_context ctx;

	cipher_suite->expand_message_init(&ctx);
	cipher_suite->expand_message_update(&ctx, seed, seed_len);
	cipher_suite->expand_message_finalize(&ctx, rand, count*48, dst, dst_len);
}


int
mocked_proof_gen (
	fixture_proof_gen_t test_case,
	const bbs_public_key pk,
	const bbs_signature signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t header_len,
	const uint8_t        *presentation_header,
	uint64_t presentation_header_len,
	const uint64_t       *disclosed_indexes,
	uint64_t disclosed_indexes_len,
	uint64_t num_messages,
	...
	)
{
	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];
	va_list ap;
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	uint8_t *msg;
	uint32_t msg_len;
	bool disclosed;

	fill_randomness (test_case.cipher_suite,
	                 randomness,
	                 5 + num_messages - disclosed_indexes_len,
	                 test_case.proof_SEED,
	                 test_case.proof_SEED_len,
	                 test_case.proof_DST,
	                 test_case.proof_DST_len);

	va_start (ap, num_messages);
	bbs_proof_gen_init(&ctx, test_case.cipher_suite, pk, num_messages, disclosed_indexes_len, mocked_prf, randomness);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		bbs_proof_gen_update(&ctx, proof, msg, msg_len, disclosed);
		if(disclosed) di_idx++;
	}
	va_end(ap);

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}


int
bbs_fix_proof_gen ()
{
	// *INDENT-OFF* - Preserve formatting
#ifdef LIBBBS_TEST_SUITE_SHA256
	fixture_proof_gen_t test_case = {
			.cipher_suite = bbs_sha256_cipher_suite,

			.proof_SEED = fixture_bls12_381_sha_256_proof_SEED,
			.proof_SEED_len = sizeof(fixture_bls12_381_sha_256_proof_SEED),

			.proof_DST = fixture_bls12_381_sha_256_proof_DST,
			.proof_DST_len = sizeof(fixture_bls12_381_sha_256_proof_DST),

			.proof_random_scalar = {
				fixture_bls12_381_sha_256_proof_random_scalar_1, fixture_bls12_381_sha_256_proof_random_scalar_2, fixture_bls12_381_sha_256_proof_random_scalar_3,
				fixture_bls12_381_sha_256_proof_random_scalar_4, fixture_bls12_381_sha_256_proof_random_scalar_5, fixture_bls12_381_sha_256_proof_random_scalar_6,
				fixture_bls12_381_sha_256_proof_random_scalar_7, fixture_bls12_381_sha_256_proof_random_scalar_8, fixture_bls12_381_sha_256_proof_random_scalar_9,
				fixture_bls12_381_sha_256_proof_random_scalar_10
			},
			.proof_random_scalar_len = {
				sizeof(fixture_bls12_381_sha_256_proof_random_scalar_1), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_2), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_3),
				sizeof(fixture_bls12_381_sha_256_proof_random_scalar_4), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_5), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_6),
				sizeof(fixture_bls12_381_sha_256_proof_random_scalar_7), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_8), sizeof(fixture_bls12_381_sha_256_proof_random_scalar_9),
				sizeof(fixture_bls12_381_sha_256_proof_random_scalar_10)
			},

			.proof1_public_key = fixture_bls12_381_sha_256_proof1_public_key,
			.proof1_signature = fixture_bls12_381_sha_256_proof1_signature,
			.proof1_signature_len = sizeof(fixture_bls12_381_sha_256_proof1_signature),
			.proof1_header = fixture_bls12_381_sha_256_proof1_header,
			.proof1_header_len = sizeof(fixture_bls12_381_sha_256_proof1_header),
			.proof1_presentation_header = fixture_bls12_381_sha_256_proof1_presentation_header,
			.proof1_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof1_presentation_header),
			.proof1_revealed_indexes = fixture_bls12_381_sha_256_proof1_revealed_indexes,
			.proof1_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof1_revealed_indexes),
			.proof1_m_1 = fixture_bls12_381_sha_256_proof1_m_1,
			.proof1_m_1_len = sizeof(fixture_bls12_381_sha_256_proof1_m_1),
			.proof1_proof = fixture_bls12_381_sha_256_proof1_proof,
			.proof1_proof_len = sizeof(fixture_bls12_381_sha_256_proof1_proof),
			.proof2_public_key = fixture_bls12_381_sha_256_proof2_public_key,
			.proof2_signature = fixture_bls12_381_sha_256_proof2_signature,
			.proof2_signature_len = sizeof(fixture_bls12_381_sha_256_proof2_signature),
			.proof2_header = fixture_bls12_381_sha_256_proof2_header,
			.proof2_header_len = sizeof(fixture_bls12_381_sha_256_proof2_header),
			.proof2_presentation_header = fixture_bls12_381_sha_256_proof2_presentation_header,
			.proof2_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof2_presentation_header),
			.proof2_revealed_indexes = fixture_bls12_381_sha_256_proof2_revealed_indexes,
			.proof2_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof2_revealed_indexes),
			.proof2_m = {
				fixture_bls12_381_sha_256_proof2_m_1, fixture_bls12_381_sha_256_proof2_m_2, fixture_bls12_381_sha_256_proof2_m_3,
				fixture_bls12_381_sha_256_proof2_m_4, fixture_bls12_381_sha_256_proof2_m_5, fixture_bls12_381_sha_256_proof2_m_6,
				fixture_bls12_381_sha_256_proof2_m_7, fixture_bls12_381_sha_256_proof2_m_8, fixture_bls12_381_sha_256_proof2_m_9,
				fixture_bls12_381_sha_256_proof2_m_10
			},
			.proof2_m_len = {
				sizeof(fixture_bls12_381_sha_256_proof2_m_1), sizeof(fixture_bls12_381_sha_256_proof2_m_2), sizeof(fixture_bls12_381_sha_256_proof2_m_3),
				sizeof(fixture_bls12_381_sha_256_proof2_m_4), sizeof(fixture_bls12_381_sha_256_proof2_m_5), sizeof(fixture_bls12_381_sha_256_proof2_m_6),
				sizeof(fixture_bls12_381_sha_256_proof2_m_7), sizeof(fixture_bls12_381_sha_256_proof2_m_8), sizeof(fixture_bls12_381_sha_256_proof2_m_9),
				0 /*m_10*/
			},
			.proof2_proof = fixture_bls12_381_sha_256_proof2_proof,
			.proof2_proof_len = sizeof(fixture_bls12_381_sha_256_proof2_proof),

			.proof3_public_key = fixture_bls12_381_sha_256_proof3_public_key,
			.proof3_signature = fixture_bls12_381_sha_256_proof3_signature,
			.proof3_signature_len = sizeof(fixture_bls12_381_sha_256_proof3_signature),
			.proof3_header = fixture_bls12_381_sha_256_proof3_header,
			.proof3_header_len = sizeof(fixture_bls12_381_sha_256_proof3_header),
			.proof3_presentation_header = fixture_bls12_381_sha_256_proof3_presentation_header,
			.proof3_presentation_header_len = sizeof(fixture_bls12_381_sha_256_proof3_presentation_header),
			.proof3_revealed_indexes = fixture_bls12_381_sha_256_proof3_revealed_indexes,
			.proof3_revealed_indexes_len = LEN (fixture_bls12_381_sha_256_proof3_revealed_indexes),
			.proof3_proof = fixture_bls12_381_sha_256_proof3_proof,
			.proof3_proof_len = sizeof(fixture_bls12_381_sha_256_proof3_proof),
  };
#elif LIBBBS_TEST_SUITE_SHAKE256
	fixture_proof_gen_t test_case = {
			.cipher_suite = bbs_shake256_cipher_suite,

			.proof_SEED = fixture_bls12_381_shake_256_proof_SEED,
			.proof_SEED_len = sizeof(fixture_bls12_381_shake_256_proof_SEED),

			.proof_DST = fixture_bls12_381_shake_256_proof_DST,
			.proof_DST_len = sizeof(fixture_bls12_381_shake_256_proof_DST),

			.proof_random_scalar = {
				fixture_bls12_381_shake_256_proof_random_scalar_1, fixture_bls12_381_shake_256_proof_random_scalar_2, fixture_bls12_381_shake_256_proof_random_scalar_3,
				fixture_bls12_381_shake_256_proof_random_scalar_4, fixture_bls12_381_shake_256_proof_random_scalar_5, fixture_bls12_381_shake_256_proof_random_scalar_6,
				fixture_bls12_381_shake_256_proof_random_scalar_7, fixture_bls12_381_shake_256_proof_random_scalar_8, fixture_bls12_381_shake_256_proof_random_scalar_9,
				fixture_bls12_381_shake_256_proof_random_scalar_10
			},
			.proof_random_scalar_len = {
				sizeof(fixture_bls12_381_shake_256_proof_random_scalar_1), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_2), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_3),
				sizeof(fixture_bls12_381_shake_256_proof_random_scalar_4), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_5), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_6),
				sizeof(fixture_bls12_381_shake_256_proof_random_scalar_7), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_8), sizeof(fixture_bls12_381_shake_256_proof_random_scalar_9),
				sizeof(fixture_bls12_381_shake_256_proof_random_scalar_10)
			},

			.proof1_public_key = fixture_bls12_381_shake_256_proof1_public_key,
			.proof1_signature = fixture_bls12_381_shake_256_proof1_signature,
			.proof1_signature_len = sizeof(fixture_bls12_381_shake_256_proof1_signature),
			.proof1_header = fixture_bls12_381_shake_256_proof1_header,
			.proof1_header_len = sizeof(fixture_bls12_381_shake_256_proof1_header),
			.proof1_presentation_header = fixture_bls12_381_shake_256_proof1_presentation_header,
			.proof1_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof1_presentation_header),
			.proof1_revealed_indexes = fixture_bls12_381_shake_256_proof1_revealed_indexes,
			.proof1_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof1_revealed_indexes),
			.proof1_m_1 = fixture_bls12_381_shake_256_proof1_m_1,
			.proof1_m_1_len = sizeof(fixture_bls12_381_shake_256_proof1_m_1),
			.proof1_proof = fixture_bls12_381_shake_256_proof1_proof,
			.proof1_proof_len = sizeof(fixture_bls12_381_shake_256_proof1_proof),
			.proof2_public_key = fixture_bls12_381_shake_256_proof2_public_key,
			.proof2_signature = fixture_bls12_381_shake_256_proof2_signature,
			.proof2_signature_len = sizeof(fixture_bls12_381_shake_256_proof2_signature),
			.proof2_header = fixture_bls12_381_shake_256_proof2_header,
			.proof2_header_len = sizeof(fixture_bls12_381_shake_256_proof2_header),
			.proof2_presentation_header = fixture_bls12_381_shake_256_proof2_presentation_header,
			.proof2_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof2_presentation_header),
			.proof2_revealed_indexes = fixture_bls12_381_shake_256_proof2_revealed_indexes,
			.proof2_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof2_revealed_indexes),
			.proof2_m = {
				fixture_bls12_381_shake_256_proof2_m_1, fixture_bls12_381_shake_256_proof2_m_2, fixture_bls12_381_shake_256_proof2_m_3,
				fixture_bls12_381_shake_256_proof2_m_4, fixture_bls12_381_shake_256_proof2_m_5, fixture_bls12_381_shake_256_proof2_m_6,
				fixture_bls12_381_shake_256_proof2_m_7, fixture_bls12_381_shake_256_proof2_m_8, fixture_bls12_381_shake_256_proof2_m_9,
				fixture_bls12_381_shake_256_proof2_m_10
			},
			.proof2_m_len = {
				sizeof(fixture_bls12_381_shake_256_proof2_m_1), sizeof(fixture_bls12_381_shake_256_proof2_m_2), sizeof(fixture_bls12_381_shake_256_proof2_m_3),
				sizeof(fixture_bls12_381_shake_256_proof2_m_4), sizeof(fixture_bls12_381_shake_256_proof2_m_5), sizeof(fixture_bls12_381_shake_256_proof2_m_6),
				sizeof(fixture_bls12_381_shake_256_proof2_m_7), sizeof(fixture_bls12_381_shake_256_proof2_m_8), sizeof(fixture_bls12_381_shake_256_proof2_m_9),
				0 /*m_10*/
			},
			.proof2_proof = fixture_bls12_381_shake_256_proof2_proof,
			.proof2_proof_len = sizeof(fixture_bls12_381_shake_256_proof2_proof),

			.proof3_public_key = fixture_bls12_381_shake_256_proof3_public_key,
			.proof3_signature = fixture_bls12_381_shake_256_proof3_signature,
			.proof3_signature_len = sizeof(fixture_bls12_381_shake_256_proof3_signature),
			.proof3_header = fixture_bls12_381_shake_256_proof3_header,
			.proof3_header_len = sizeof(fixture_bls12_381_shake_256_proof3_header),
			.proof3_presentation_header = fixture_bls12_381_shake_256_proof3_presentation_header,
			.proof3_presentation_header_len = sizeof(fixture_bls12_381_shake_256_proof3_presentation_header),
			.proof3_revealed_indexes = fixture_bls12_381_shake_256_proof3_revealed_indexes,
			.proof3_revealed_indexes_len = LEN (fixture_bls12_381_shake_256_proof3_revealed_indexes),
			.proof3_proof = fixture_bls12_381_shake_256_proof3_proof,
			.proof3_proof_len = sizeof(fixture_bls12_381_shake_256_proof3_proof),
	};
#endif
	// *INDENT-ON* - Preserve formatting

	printf ("Testing BBS Proof Generation with cipher suite %s\n",
	        test_case.cipher_suite->cipher_suite_id);
	if (bbs_init ())
	{
		bbs_deinit ();
		return 1;
	}

	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];

	// Randomness generation self check, to catch any errors related to this
	// step
	uint8_t scalar_buffer[BBS_SCALAR_LEN];
	blst_scalar scalar;

	fill_randomness (test_case.cipher_suite, randomness, 10,
	                               test_case.proof_SEED, test_case.proof_SEED_len,
	                               test_case.proof_DST, test_case.proof_DST_len);

	// Test rerandomization scalars
	for (int i = 0; i < 2; i++)
	{
		mocked_prf (test_case.cipher_suite, &scalar, i + 1, 0, randomness);
		bn_write_bbs (scalar_buffer, &scalar);
		ASSERT_EQ_PTR ("scalar test",
		               scalar_buffer,
		               test_case.proof_random_scalar[i],
		               test_case.proof_random_scalar_len[i]);
	}

	// Test commitment scalars
	for (int i = 0; i < 8; i++)
	{
		mocked_prf (test_case.cipher_suite, &scalar, 0, i, randomness);
		bn_write_bbs (scalar_buffer, &scalar);
		ASSERT_EQ_PTR ("scalar test",
		               scalar_buffer,
		               test_case.proof_random_scalar[i + 2],
		               test_case.proof_random_scalar_len[i + 2]);
	}

	uint8_t proof1[BBS_PROOF_LEN (0)];
	BBS_BENCH_START (mocked_proof_gen)
	if (BBS_OK != mocked_proof_gen (test_case, test_case.proof1_public_key,
	                                test_case.proof1_signature, proof1,
	                                test_case.proof1_header,
	                                test_case.proof1_header_len,
	                                test_case.proof1_presentation_header,
	                                test_case.proof1_presentation_header_len,
	                                test_case.proof1_revealed_indexes,
	                                test_case.proof1_revealed_indexes_len, 1,         // num_messages
	                                test_case.proof1_m_1, test_case.proof1_m_1_len))
	{
		puts ("Error during proof 1 generation");
		return 1;
	}
	BBS_BENCH_END (mocked_proof_gen, "Valid Single Message Proof");
	ASSERT_EQ_PTR ("proof 1 generation",
	               proof1,
	               test_case.proof1_proof,
	               test_case.proof1_proof_len);

	uint8_t proof2[BBS_PROOF_LEN (0)];
if (BBS_OK != mocked_proof_gen (test_case, test_case.proof2_public_key,
	                                test_case.proof2_signature, proof2,
	                                test_case.proof2_header,
	                                test_case.proof2_header_len,
	                                test_case.proof2_presentation_header,
	                                test_case.proof2_presentation_header_len,
test_case.proof2_revealed_indexes,
	                                test_case.proof2_revealed_indexes_len, 10,
	                                test_case.proof2_m[0], test_case.proof2_m_len[0],
	                                test_case.proof2_m[1], test_case.proof2_m_len[1],
	                                test_case.proof2_m[2], test_case.proof2_m_len[2],
	                                test_case.proof2_m[3], test_case.proof2_m_len[3],
	                                test_case.proof2_m[4], test_case.proof2_m_len[4],
	                                test_case.proof2_m[5], test_case.proof2_m_len[5],
	                                test_case.proof2_m[6], test_case.proof2_m_len[6],
	                                test_case.proof2_m[7], test_case.proof2_m_len[7],
	                                test_case.proof2_m[8], test_case.proof2_m_len[8],
	                                test_case.proof2_m[9], test_case.proof2_m_len[9]))
	{
		puts ("Error during proof 2 generation");
		return 1;
	}
	ASSERT_EQ_PTR ("proof 2 generation",
	               proof2,
	               test_case.proof2_proof,
	               test_case.proof2_proof_len);

	// Only some messages are being revealed here
	uint8_t proof3[BBS_PROOF_LEN (6)];
	if (BBS_OK != mocked_proof_gen (test_case, test_case.proof3_public_key,
	                                test_case.proof3_signature, proof3,
	                                test_case.proof3_header,
	                                test_case.proof3_header_len,
	                                test_case.proof3_presentation_header,
	                                test_case.proof3_presentation_header_len,
	                                test_case.proof3_revealed_indexes,
	                                test_case.proof3_revealed_indexes_len, 10,
	                                test_case.proof2_m[0], test_case.proof2_m_len[0],
	                                test_case.proof2_m[1], test_case.proof2_m_len[1],
	                                test_case.proof2_m[2], test_case.proof2_m_len[2],
	                                test_case.proof2_m[3], test_case.proof2_m_len[3],
	                                test_case.proof2_m[4], test_case.proof2_m_len[4],
	                                test_case.proof2_m[5], test_case.proof2_m_len[5],
	                                test_case.proof2_m[6], test_case.proof2_m_len[6],
	                                test_case.proof2_m[7], test_case.proof2_m_len[7],
	                                test_case.proof2_m[8], test_case.proof2_m_len[8],
	                                test_case.proof2_m[9], test_case.proof2_m_len[9]))
	{
		puts ("Error during proof 3 generation");
		return 1;
	}
	ASSERT_EQ_PTR ("proof 3 generation",
	               proof3,
	               test_case.proof3_proof,
	               test_case.proof3_proof_len);

	return 0;
}
