#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

#define proof_SEED                 fixture_bls12_381_sha_256_proof_SEED
#define proof_DST                  fixture_bls12_381_sha_256_proof_DST
#define proof_random_scalar_1      fixture_bls12_381_sha_256_proof_random_scalar_1
#define proof_random_scalar_2      fixture_bls12_381_sha_256_proof_random_scalar_2
#define proof_random_scalar_3      fixture_bls12_381_sha_256_proof_random_scalar_3
#define proof_random_scalar_4      fixture_bls12_381_sha_256_proof_random_scalar_4
#define proof_random_scalar_5      fixture_bls12_381_sha_256_proof_random_scalar_5
#define proof_random_scalar_6      fixture_bls12_381_sha_256_proof_random_scalar_6
#define proof_random_scalar_7      fixture_bls12_381_sha_256_proof_random_scalar_7
#define proof_random_scalar_8      fixture_bls12_381_sha_256_proof_random_scalar_8
#define proof_random_scalar_9      fixture_bls12_381_sha_256_proof_random_scalar_9
#define proof_random_scalar_10     fixture_bls12_381_sha_256_proof_random_scalar_10

#define proof1_public_key          fixture_bls12_381_sha_256_proof1_public_key
#define proof1_signature           fixture_bls12_381_sha_256_proof1_signature
#define proof1_header              fixture_bls12_381_sha_256_proof1_header
#define proof1_presentation_header fixture_bls12_381_sha_256_proof1_presentation_header
#define proof1_revealed_indexes    fixture_bls12_381_sha_256_proof1_revealed_indexes
#define proof1_m_1                 fixture_bls12_381_sha_256_proof1_m_1
#define proof1_proof               fixture_bls12_381_sha_256_proof1_proof

#define proof2_public_key          fixture_bls12_381_sha_256_proof2_public_key
#define proof2_signature           fixture_bls12_381_sha_256_proof2_signature
#define proof2_header              fixture_bls12_381_sha_256_proof2_header
#define proof2_presentation_header fixture_bls12_381_sha_256_proof2_presentation_header
#define proof2_revealed_indexes    fixture_bls12_381_sha_256_proof2_revealed_indexes
#define proof2_m_1                 fixture_bls12_381_sha_256_proof2_m_1
#define proof2_m_2                 fixture_bls12_381_sha_256_proof2_m_2
#define proof2_m_3                 fixture_bls12_381_sha_256_proof2_m_3
#define proof2_m_4                 fixture_bls12_381_sha_256_proof2_m_4
#define proof2_m_5                 fixture_bls12_381_sha_256_proof2_m_5
#define proof2_m_6                 fixture_bls12_381_sha_256_proof2_m_6
#define proof2_m_7                 fixture_bls12_381_sha_256_proof2_m_7
#define proof2_m_8                 fixture_bls12_381_sha_256_proof2_m_8
#define proof2_m_9                 fixture_bls12_381_sha_256_proof2_m_9
#define proof2_m_10                fixture_bls12_381_sha_256_proof2_m_10
#define proof2_proof               fixture_bls12_381_sha_256_proof2_proof

#define proof3_public_key          fixture_bls12_381_sha_256_proof3_public_key
#define proof3_signature           fixture_bls12_381_sha_256_proof3_signature
#define proof3_header              fixture_bls12_381_sha_256_proof3_header
#define proof3_presentation_header fixture_bls12_381_sha_256_proof3_presentation_header
#define proof3_revealed_indexes    fixture_bls12_381_sha_256_proof3_revealed_indexes
#define proof3_proof               fixture_bls12_381_sha_256_proof3_proof

#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

#define proof_SEED                 fixture_bls12_381_shake_256_proof_SEED
#define proof_DST                  fixture_bls12_381_shake_256_proof_DST
#define proof_random_scalar_1      fixture_bls12_381_shake_256_proof_random_scalar_1
#define proof_random_scalar_2      fixture_bls12_381_shake_256_proof_random_scalar_2
#define proof_random_scalar_3      fixture_bls12_381_shake_256_proof_random_scalar_3
#define proof_random_scalar_4      fixture_bls12_381_shake_256_proof_random_scalar_4
#define proof_random_scalar_5      fixture_bls12_381_shake_256_proof_random_scalar_5
#define proof_random_scalar_6      fixture_bls12_381_shake_256_proof_random_scalar_6
#define proof_random_scalar_7      fixture_bls12_381_shake_256_proof_random_scalar_7
#define proof_random_scalar_8      fixture_bls12_381_shake_256_proof_random_scalar_8
#define proof_random_scalar_9      fixture_bls12_381_shake_256_proof_random_scalar_9
#define proof_random_scalar_10     fixture_bls12_381_shake_256_proof_random_scalar_10

#define proof1_public_key          fixture_bls12_381_shake_256_proof1_public_key
#define proof1_signature           fixture_bls12_381_shake_256_proof1_signature
#define proof1_header              fixture_bls12_381_shake_256_proof1_header
#define proof1_presentation_header fixture_bls12_381_shake_256_proof1_presentation_header
#define proof1_revealed_indexes    fixture_bls12_381_shake_256_proof1_revealed_indexes
#define proof1_m_1                 fixture_bls12_381_shake_256_proof1_m_1
#define proof1_proof               fixture_bls12_381_shake_256_proof1_proof

#define proof2_public_key          fixture_bls12_381_shake_256_proof2_public_key
#define proof2_signature           fixture_bls12_381_shake_256_proof2_signature
#define proof2_header              fixture_bls12_381_shake_256_proof2_header
#define proof2_presentation_header fixture_bls12_381_shake_256_proof2_presentation_header
#define proof2_revealed_indexes    fixture_bls12_381_shake_256_proof2_revealed_indexes
#define proof2_m_1                 fixture_bls12_381_shake_256_proof2_m_1
#define proof2_m_2                 fixture_bls12_381_shake_256_proof2_m_2
#define proof2_m_3                 fixture_bls12_381_shake_256_proof2_m_3
#define proof2_m_4                 fixture_bls12_381_shake_256_proof2_m_4
#define proof2_m_5                 fixture_bls12_381_shake_256_proof2_m_5
#define proof2_m_6                 fixture_bls12_381_shake_256_proof2_m_6
#define proof2_m_7                 fixture_bls12_381_shake_256_proof2_m_7
#define proof2_m_8                 fixture_bls12_381_shake_256_proof2_m_8
#define proof2_m_9                 fixture_bls12_381_shake_256_proof2_m_9
#define proof2_m_10                fixture_bls12_381_shake_256_proof2_m_10
#define proof2_proof               fixture_bls12_381_shake_256_proof2_proof

#define proof3_public_key          fixture_bls12_381_shake_256_proof3_public_key
#define proof3_signature           fixture_bls12_381_shake_256_proof3_signature
#define proof3_header              fixture_bls12_381_shake_256_proof3_header
#define proof3_presentation_header fixture_bls12_381_shake_256_proof3_presentation_header
#define proof3_revealed_indexes    fixture_bls12_381_shake_256_proof3_revealed_indexes
#define proof3_proof               fixture_bls12_381_shake_256_proof3_proof

#endif


// Mocked random scalars for bbs_proof_gen_det
int
mocked_prf (
	bn_t      out,
	uint8_t   input_type,
	uint64_t  input,
	void     *cookie
	)
{
	uint8_t *rand = (uint8_t*) cookie;
	int      res  = BBS_ERROR;

	if (0 == input_type && 10 > input)
	{
		// msg_tilde
		rand += (5 + input) * 48;
	}
	else if (0 == input && 5 >= input_type)
	{
		// other stuff
		rand += (input_type - 1) * 48;
	}
	else
		goto cleanup;

	RLC_TRY {
		bn_read_bin (out, rand, 48);
		bn_mod (out, out, &(core_get ()->ep_r));
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


int
fill_randomness (
	uint8_t       *rand,
	int            count,
	const uint8_t *seed,
	uint64_t       seed_len,
	const uint8_t *dst,
	uint64_t       dst_len
	)
{
	int ret     = BBS_ERROR;
	int out_len = count * 48;

	#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

	RLC_TRY {
		md_xmd (rand, out_len, seed, seed_len, dst, dst_len);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}
	ret = BBS_OK;

	#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

	bbs_hash_ctx hctx;
	if (BBS_OK != expand_message_init (&hctx))
	{
		goto cleanup;
	}
	if (BBS_OK != expand_message_update (&hctx, seed, seed_len))
	{
		goto cleanup;
	}
	if (BBS_OK != _expand_message_finalize (&hctx, rand, out_len, dst, dst_len))
	{
		goto cleanup;
	}
	ret = BBS_OK;

	#endif

cleanup:
	return ret;
}


int
mocked_proof_gen (
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
	...
	)
{
	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];
	va_list ap;
	int     ret = BBS_ERROR;
	va_start (ap, num_messages);

	if (BBS_OK != fill_randomness (randomness, 5 + num_messages - disclosed_indexes_len,
				       proof_SEED, sizeof(proof_SEED), proof_DST, sizeof(proof_DST))
	    )
	{
		goto cleanup;
	}
	if (BBS_OK != bbs_proof_gen_det (&bbs_sha256_cipher_suite, pk, signature, proof, header, header_len,
					 presentation_header, presentation_header_len,
					 disclosed_indexes, disclosed_indexes_len, num_messages,
					 mocked_prf, randomness, ap))
	{
		goto cleanup;
	}

	ret = BBS_OK;
cleanup:
	va_end (ap);
	return ret;
}


int
bbs_fix_proof_gen ()
{
	if (core_init () != RLC_OK)
	{
		core_clean ();
		return 1;
	}
	if (pc_param_set_any () != RLC_OK)
	{
		core_clean ();
		return 1;
	}

	// Stores randomness for 15 random scalars, which is as much as we need
	uint8_t randomness[48 * 15];

	// Randomness generation self check, to catch any errors related to this
	// step
	uint8_t scalar_buffer[BBS_SCALAR_LEN];
	bn_t    scalar;

	bn_null (scalar);
	RLC_TRY { bn_new (scalar) }
	RLC_CATCH_ANY {
		puts ("Internal error");
		return 1;
	}
	if (BBS_OK != fill_randomness (randomness, 10, proof_SEED, LEN (proof_SEED), proof_DST, LEN
					       (proof_DST)))
	{
		puts ("Error during randomness generation self test");
		return 1;
	}
#define WRITE_SCALAR RLC_TRY { bn_write_bbs (scalar_buffer, scalar); } \
	RLC_CATCH_ANY { puts ("Write error"); return 1;}
	if (BBS_OK != mocked_prf (scalar, 1, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_1 test", scalar_buffer, proof_random_scalar_1);

	if (BBS_OK != mocked_prf (scalar, 2, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_2 test", scalar_buffer, proof_random_scalar_2);

	if (BBS_OK != mocked_prf (scalar, 3, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_3 test", scalar_buffer, proof_random_scalar_3);

	if (BBS_OK != mocked_prf (scalar, 4, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_4 test", scalar_buffer, proof_random_scalar_4);

	if (BBS_OK != mocked_prf (scalar, 5, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_5 test", scalar_buffer, proof_random_scalar_5);

	if (BBS_OK != mocked_prf (scalar, 0, 0, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_6 test", scalar_buffer, proof_random_scalar_6);

	if (BBS_OK != mocked_prf (scalar, 0, 1, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_7 test", scalar_buffer, proof_random_scalar_7);

	if (BBS_OK != mocked_prf (scalar, 0, 2, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_8 test", scalar_buffer, proof_random_scalar_8);

	if (BBS_OK != mocked_prf (scalar, 0, 3, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_9 test", scalar_buffer, proof_random_scalar_9);

	if (BBS_OK != mocked_prf (scalar, 0, 4, randomness))
	{
		puts ("Read error");
		return 1;
	}
	WRITE_SCALAR;
	ASSERT_EQ ("scalar_10 test", scalar_buffer, proof_random_scalar_10);

	uint8_t proof1[BBS_PROOF_LEN (0)];
	BBS_BENCH_START ()
	if (BBS_OK != mocked_proof_gen (proof1_public_key, proof1_signature, proof1, proof1_header,
					sizeof(proof1_header), proof1_presentation_header, sizeof(
						proof1_presentation_header), proof1_revealed_indexes
					, LEN (proof1_revealed_indexes), 1, // num_messages
					proof1_m_1, sizeof(proof1_m_1)))
	{
		puts ("Error during proof 1 generation");
		return 1;
	}
	BBS_BENCH_END ("Valid Single Message Proof");
	ASSERT_EQ ("proof 1 generation", proof1, proof1_proof);

	uint8_t proof2[BBS_PROOF_LEN (0)];
	if (BBS_OK != mocked_proof_gen (proof2_public_key, proof2_signature, proof2, proof2_header,
					sizeof(proof2_header), proof2_presentation_header, sizeof(
						proof2_presentation_header), proof2_revealed_indexes
					, LEN (proof2_revealed_indexes), 10, proof2_m_1, sizeof(
						proof2_m_1), proof2_m_2, sizeof(proof2_m_2),
					proof2_m_3, sizeof(proof2_m_3), proof2_m_4, sizeof(
						proof2_m_4), proof2_m_5, sizeof(proof2_m_5),
					proof2_m_6, sizeof(proof2_m_6), proof2_m_7, sizeof(
						proof2_m_7), proof2_m_8, sizeof(proof2_m_8),
					proof2_m_9, sizeof(proof2_m_9), proof2_m_10, sizeof(
						proof2_m_10)))
	{
		puts ("Error during proof 2 generation");
		return 1;
	}
	BBS_BENCH_END ("Valid Multi-Message, All Messages Disclosed Proof")
	ASSERT_EQ ("proof 2 generation", proof2, proof2_proof);

	// Only some messages are being revealed here
	uint8_t proof3[BBS_PROOF_LEN (6)];
	if (BBS_OK != mocked_proof_gen (proof3_public_key, proof3_signature, proof3, proof3_header,
					sizeof(proof3_header), proof3_presentation_header, sizeof(
						proof3_presentation_header), proof3_revealed_indexes
					, LEN (proof3_revealed_indexes), 10, proof2_m_1, sizeof(
						proof2_m_1), proof2_m_2, sizeof(proof2_m_2),
					proof2_m_3, sizeof(proof2_m_3), proof2_m_4, sizeof(
						proof2_m_4), proof2_m_5, sizeof(proof2_m_5),
					proof2_m_6, sizeof(proof2_m_6), proof2_m_7, sizeof(
						proof2_m_7), proof2_m_8, sizeof(proof2_m_8),
					proof2_m_9, sizeof(proof2_m_9), proof2_m_10, sizeof(
						proof2_m_10)))
	{
		puts ("Error during proof 3 generation");
		return 1;
	}
	BBS_BENCH_END ("Valid Multi-Message, Some Messages Disclosed Proof")
	ASSERT_EQ ("proof 3 generation", proof3, proof3_proof);

	bn_free (scalar);
	return 0;
}
