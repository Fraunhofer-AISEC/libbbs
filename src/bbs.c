#include "bbs.h"
#include "bbs_util.h"
#include <relic.h>

// Magic constants to be used as Domain Separation Tags

#define BBS_SHA256_CIPHER_SUITE_ID        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
#define BBS_SHA256_CIPHER_SUITE_LENGTH    35
#define BBS_SHA256_DEFAULT_KEY_DST        BBS_SHA256_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_SHA256_DEFAULT_KEY_DST_LENGTH BBS_SHA256_CIPHER_SUITE_LENGTH + 11
#define BBS_SHA256_API_ID                 BBS_SHA256_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_SHA256_API_ID_LENGTH          BBS_SHA256_CIPHER_SUITE_LENGTH + 9
#define BBS_SHA256_SIGNATURE_DST          BBS_SHA256_API_ID "H2S_"
#define BBS_SHA256_SIGNATURE_DST_LENGTH   BBS_SHA256_API_ID_LENGTH + 4
#define BBS_SHA256_CHALLENGE_DST          BBS_SHA256_API_ID "H2S_"
#define BBS_SHA256_CHALLENGE_DST_LENGTH   BBS_SHA256_API_ID_LENGTH + 4
#define BBS_SHA256_MAP_DST                BBS_SHA256_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_SHA256_MAP_DST_LENGTH         BBS_SHA256_API_ID_LENGTH + 26

// The above collision stems from the ID. Possible oversight? Should not compromise
// security too much...

SHA256Context bbs_sha256_hash_ctx_t;
SHA256Context bbs_sha256_dom_ctx_t;
SHA256Context bbs_sha256_ch_ctx_t;

#define BBS_SHAKE256_CIPHER_SUITE_ID        "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
#define BBS_SHAKE256_CIPHER_SUITE_LENGTH    37
#define BBS_SHAKE256_DEFAULT_KEY_DST        BBS_SHAKE256_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_SHAKE256_DEFAULT_KEY_DST_LENGTH BBS_SHAKE256_CIPHER_SUITE_LENGTH + 11
#define BBS_SHAKE256_API_ID                 BBS_SHAKE256_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_SHAKE256_API_ID_LENGTH          BBS_SHAKE256_CIPHER_SUITE_LENGTH + 9
#define BBS_SHAKE256_SIGNATURE_DST          BBS_SHAKE256_API_ID "H2S_"
#define BBS_SHAKE256_SIGNATURE_DST_LENGTH   BBS_SHAKE256_API_ID_LENGTH + 4
#define BBS_SHAKE256_CHALLENGE_DST          BBS_SHAKE256_API_ID "H2S_"
#define BBS_SHAKE256_CHALLENGE_DST_LENGTH   BBS_SHAKE256_API_ID_LENGTH + 4
#define BBS_SHAKE256_MAP_DST                BBS_SHAKE256_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_SHAKE256_MAP_DST_LENGTH         BBS_SHAKE256_API_ID_LENGTH + 26


Keccak_HashInstance bbs_shake256_hash_ctx_t;
Keccak_HashInstance bbs_shake256_dom_ctx_t;
Keccak_HashInstance bbs_shake256_ch_ctx_t;

static uint8_t      BBS_SHA256_P1[] = {
	0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
	0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
	0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
	0x4e, 0x28, 0xc9
};
static uint8_t      BBS_SHAKE256_P1[] = {
	0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
	0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
	0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
	0x15, 0x07, 0x55
};

// *INDENT-OFF* - Preserve formatting
bbs_cipher_suite_t bbs_sha256_cipher_suite = {
	.hash_ctx = &bbs_sha256_hash_ctx_t,
	.dom_ctx = &bbs_sha256_dom_ctx_t,
	.ch_ctx = &bbs_sha256_ch_ctx_t,
	.p1 = BBS_SHA256_P1,
	.expand_message_init = bbs_sha256_expand_message_init,
	.expand_message_update = bbs_sha256_expand_message_update,
	.expand_message_finalize_48B = bbs_sha256_expand_message_finalize_48B,
	.expand_message_dyn = bbs_sha256_expand_message_dyn,
	.cipher_suite_id = (char*) BBS_SHA256_CIPHER_SUITE_ID,
	.cipher_suite_id_len = BBS_SHA256_CIPHER_SUITE_LENGTH,
	.default_key_dst = BBS_SHA256_DEFAULT_KEY_DST,
	.default_key_dst_len = BBS_SHA256_DEFAULT_KEY_DST_LENGTH,
	.api_id = BBS_SHA256_API_ID,
	.api_id_len = BBS_SHA256_API_ID_LENGTH,
	.signature_dst = BBS_SHA256_SIGNATURE_DST,
	.signature_dst_len = BBS_SHA256_SIGNATURE_DST_LENGTH,
	.challenge_dst = BBS_SHA256_CHALLENGE_DST,
	.challenge_dst_len = BBS_SHA256_CHALLENGE_DST_LENGTH,
	.map_dst = BBS_SHA256_MAP_DST,
	.map_dst_len = BBS_SHA256_MAP_DST_LENGTH,
};

bbs_cipher_suite_t bbs_shake256_cipher_suite = {
	.hash_ctx = &bbs_shake256_hash_ctx_t,
	.dom_ctx = &bbs_shake256_dom_ctx_t,
	.ch_ctx = &bbs_shake256_ch_ctx_t,
	.p1 = BBS_SHAKE256_P1,
	.expand_message_init = bbs_shake256_expand_message_init,
	.expand_message_update = bbs_shake256_expand_message_update,
	.expand_message_finalize_48B = bbs_shake256_expand_message_finalize_48B,
	.expand_message_dyn = bbs_shake256_expand_message_dyn,
	.cipher_suite_id = (char*) BBS_SHAKE256_CIPHER_SUITE_ID,
	.cipher_suite_id_len = BBS_SHAKE256_CIPHER_SUITE_LENGTH,
	.default_key_dst = BBS_SHAKE256_DEFAULT_KEY_DST,
	.default_key_dst_len = BBS_SHAKE256_DEFAULT_KEY_DST_LENGTH,
	.api_id = BBS_SHAKE256_API_ID,
	.api_id_len = BBS_SHAKE256_API_ID_LENGTH,
	.signature_dst = BBS_SHAKE256_SIGNATURE_DST,
	.signature_dst_len = BBS_SHAKE256_SIGNATURE_DST_LENGTH,
	.challenge_dst = BBS_SHAKE256_CHALLENGE_DST,
	.challenge_dst_len = BBS_SHAKE256_CHALLENGE_DST_LENGTH,
	.map_dst = BBS_SHAKE256_MAP_DST,
	.map_dst_len = BBS_SHAKE256_MAP_DST_LENGTH,
};
// *INDENT-ON* - Restore formatting

int
bbs_sha256_keygen_full (
	bbs_secret_key  sk,
	bbs_public_key  pk
	)
{
	return bbs_keygen_full (&bbs_sha256_cipher_suite, sk, pk);
}


int
bbs_shake256_keygen_full (
	bbs_secret_key  sk,
	bbs_public_key  pk
	)
{
	return bbs_keygen_full (&bbs_shake256_cipher_suite, sk, pk);
}


int
bbs_keygen_full (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
	)
{
	int            res = BBS_ERROR;
	static uint8_t seed[32];

	// Gather randomness
	RLC_TRY {
		rand_bytes (seed, 32);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Generate the secret key
	if (BBS_OK != bbs_keygen (cipher_suite, sk, seed, 32, 0, 0, 0, 0))
	{
		goto cleanup;
	}

	// Generate the public key
	if (BBS_OK != bbs_sk_to_pk (sk, pk))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


int
bbs_sha256_keygen (
	bbs_secret_key  sk,
	const uint8_t  *key_material,
	uint16_t        key_material_len,
	const uint8_t  *key_info,
	uint16_t        key_info_len,
	const uint8_t  *key_dst,
	uint8_t         key_dst_len
	)
{
	return bbs_keygen (&bbs_sha256_cipher_suite,
			   sk,
			   key_material,
			   key_material_len,
			   key_info,
			   key_info_len,
			   key_dst,
			   key_dst_len);
}


int
bbs_shake256_keygen (
	bbs_secret_key  sk,
	const uint8_t  *key_material,
	uint16_t        key_material_len,
	const uint8_t  *key_info,
	uint16_t        key_info_len,
	const uint8_t  *key_dst,
	uint8_t         key_dst_len
	)
{
	return bbs_keygen (&bbs_shake256_cipher_suite,
			   sk,
			   key_material,
			   key_material_len,
			   key_info,
			   key_info_len,
			   key_dst,
			   key_dst_len);
}


int
bbs_keygen (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	const uint8_t      *key_material,
	uint16_t            key_material_len,
	const uint8_t      *key_info,
	uint16_t            key_info_len,
	const uint8_t      *key_dst,
	uint8_t             key_dst_len
	)
{
	bn_t     sk_n;
	uint16_t key_info_len_be = ((key_info_len & 0x00FFu) << 8) | (key_info_len >> 8);
	int      res             = BBS_ERROR;

	bn_null (sk_n);

	if (! key_info)
	{
		key_info     = (uint8_t*) "";
		key_info_len = 0;
	}

	if (! key_dst)
	{
		key_dst     = (uint8_t*) cipher_suite->default_key_dst;
		key_dst_len = cipher_suite->default_key_dst_len;
	}

	RLC_TRY {
		bn_new (sk_n);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar (cipher_suite,
				      sk_n,
				      key_dst,
				      key_dst_len,
				      key_material,
				      key_material_len,
				      &key_info_len_be,
				      2,
				      key_info,
				      key_info_len,
				      0))
	{
		goto cleanup;
	}

	// Serialize
	RLC_TRY {
		bn_write_bin (sk, BBS_SK_LEN, sk_n);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	bn_free (sk_n);
	return res;
}


int
bbs_sk_to_pk (
	const bbs_secret_key  sk,
	bbs_public_key        pk
	)
{
	int   res = BBS_ERROR;
	bn_t  sk_n;
	ep2_t pk_p;

	bn_null (sk_n);
	ep2_null (pk_p);

	RLC_TRY {
		bn_new (sk_n);
		ep2_new (pk_p);
		bn_read_bbs (sk_n, sk);
		ep2_mul_gen (pk_p, sk_n);
		ep2_write_bbs (pk, pk_p);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	bn_free (sk_n);
	ep2_free (pk_p);
	return res;
}


int
bbs_sha256_sign (
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_sign (&bbs_sha256_cipher_suite,
				   sk,
				   pk,
				   signature,
				   header,
				   header_len,
				   num_messages,
				   args);
	va_end (args);
	return result;
}


int
bbs_shake256_sign (
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_sign (&bbs_shake256_cipher_suite,
				   sk,
				   pk,
				   signature,
				   header,
				   header_len,
				   num_messages,
				   args);
	va_end (args);
	return result;
}


int
bbs_sign (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	va_list               ap
	)
{
	uint8_t  generator_ctx[48 + 8];
	uint8_t  buffer[BBS_SCALAR_LEN];
	bn_t     e, domain, msg_scalar, sk_n;
	ep_t     A, B, Q_1, H_i;
	uint8_t *msg;
	uint32_t msg_len;
	int      res = BBS_ERROR;

	bn_null (e);
	bn_null (sk_n);
	bn_null (domain);
	bn_null (msg_scalar);
	ep_null (A);
	ep_null (B);
	ep_null (Q_1);
	ep_null (H_i);

	if (! header)
	{
		header     = (uint8_t*) "";
		header_len = 0;
	}

	if (BBS_OK != create_generator_init (cipher_suite,
					     generator_ctx,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_init (cipher_suite, cipher_suite->dom_ctx, pk, num_messages))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_init (cipher_suite, cipher_suite->ch_ctx))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, cipher_suite->ch_ctx, sk, BBS_SK_LEN))
	{
		goto cleanup;
	}
	RLC_TRY {
		bn_new (e);
		bn_new (sk_n);
		bn_new (domain);
		bn_new (msg_scalar);
		ep_new (A);
		ep_new (B);
		ep_new (Q_1);
		ep_new (H_i);

		// Initialize B to P1
		ep_read_bbs (B, cipher_suite->p1);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Ideally, I would like to merge these two loops. I can't, because I
	// need domain very early when hashing to scalar. For now, we generate
	// the generators twice, even though this is slow. Note that one can
	// pregenerate the domain if speed is relevant, which solves this issue.
	// BEGIN UGLY CODE
	for (int i = 0; i<num_messages + 1; i++)
	{
		// Technically, this includes Q_1
		if (BBS_OK != create_generator_next (cipher_suite, generator_ctx, H_i,
						     (uint8_t*) cipher_suite->api_id,
						     cipher_suite->api_id_len)
		    )
		{
			goto cleanup;
		}
		if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, H_i))
		{
			goto cleanup;
		}
	}
	if (BBS_OK != calculate_domain_finalize (cipher_suite,
						 cipher_suite->dom_ctx,
						 domain,
						 header,
						 header_len,
						 (uint8_t*) cipher_suite->api_id,
						 cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != create_generator_init (cipher_suite,
					     generator_ctx,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	RLC_TRY {
		bn_write_bbs (buffer, domain);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     buffer,
					     BBS_SCALAR_LEN))
	{
		goto cleanup;
	}
	// END UGLY CODE

	// Calculate Q_1
	if (BBS_OK != create_generator_next (cipher_suite,
					     generator_ctx,
					     Q_1,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}

	for (int i = 0; i<num_messages; i++)
	{
		// Calculate H_i
		if (BBS_OK != create_generator_next (cipher_suite, generator_ctx, H_i,
						     (uint8_t*) cipher_suite->api_id,
						     cipher_suite->api_id_len)
		    )
		{
			goto cleanup;
		}
		// This is where I would like to merge in the generator into
		// domain. As mentioned before, by this point, the domain has to
		// be hashed into hash_to_scalar already.

		// Calculate msg_scalar (oneshot)
		msg     = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
					      (uint8_t*) cipher_suite->map_dst,
					      cipher_suite->map_dst_len, msg, msg_len, 0))
		{
			goto cleanup;
		}
		RLC_TRY {
			// Update B
			ep_mul (H_i, H_i, msg_scalar);
			ep_add (B, B, H_i);

			// Serialize msg_scalar for hashing into e
			bn_write_bbs (buffer, msg_scalar);
		}
		RLC_CATCH_ANY {
			goto cleanup;
		}
		if (BBS_OK != hash_to_scalar_update (cipher_suite, cipher_suite->ch_ctx, buffer,
						     BBS_SCALAR_LEN))
		{
			goto cleanup;
		}
	}

	// Derive e
	if (BBS_OK != hash_to_scalar_finalize (cipher_suite,
					       cipher_suite->ch_ctx,
					       e,
					       (uint8_t*) cipher_suite->signature_dst,
					       cipher_suite->signature_dst_len))
	{
		goto cleanup;
	}

	RLC_TRY {
		// Update B
		ep_mul (Q_1, Q_1, domain);
		ep_add (B, B, Q_1);

		// Calculate A
		bn_new (sk_n);
		bn_read_bbs (sk_n, sk);
		bn_add (sk_n, sk_n, e);
		bn_mod_inv (sk_n, sk_n, &(core_get ()->ep_r));
		ep_mul (A, B, sk_n);

		// Serialize (A,e)
		ep_write_bbs (signature, A);
		bn_write_bbs (signature + BBS_G1_ELEM_LEN, e);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	bn_free (e);
	bn_free (sk_n);
	bn_free (domain);
	bn_free (msg_scalar);
	ep_free (A);
	ep_free (B);
	ep_free (Q_1);
	ep_free (H_i);
	return res;
}


int
bbs_sha256_verify (
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_verify (&bbs_sha256_cipher_suite,
				     pk,
				     signature,
				     header,
				     header_len,
				     num_messages,
				     args);
	va_end (args);
	return result;
}


int
bbs_shake256_verify (
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_verify (&bbs_shake256_cipher_suite,
				     pk,
				     signature,
				     header,
				     header_len,
				     num_messages,
				     args);
	va_end (args);
	return result;
}


int
bbs_verify (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	va_list               ap
	)
{
	uint8_t  generator_ctx[48 + 8];
	bn_t     e, domain, msg_scalar;
	ep_t     A, B, Q_1, H_i;
	ep2_t    W, tmp_p;
	fp12_t   paired1, paired2;
	uint8_t *msg;
	uint32_t msg_len;
	int      res = BBS_ERROR;

	bn_null (e);
	bn_null (domain);
	bn_null (msg_scalar);
	ep_null (A);
	ep_null (B);
	ep_null (Q_1);
	ep_null (H_i);
	ep2_null (W);
	ep2_null (tmp_p);
	fp12_null (paired1);
	fp12_null (paired2);

	if (! header)
	{
		header     = (uint8_t*) "";
		header_len = 0;
	}

	if (BBS_OK != create_generator_init (cipher_suite,
					     generator_ctx,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_init (cipher_suite, cipher_suite->dom_ctx, pk, num_messages))
	{
		goto cleanup;
	}

	RLC_TRY {
		bn_new (e);
		bn_new (domain);
		bn_new (msg_scalar);
		ep_new (A);
		ep_new (B);
		ep_new (Q_1);
		ep_new (H_i);
		ep2_new (W);
		ep2_new (tmp_p);
		fp12_new (paired1);
		fp12_new (paired2);

		// Initialize B to P1, and parse signature
		ep_read_bbs (B, cipher_suite->p1);
		ep_read_bbs (A, signature);
		bn_read_bbs (e, signature + BBS_G1_ELEM_LEN);
		ep2_read_bbs (W, pk);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Calculate Q_1
	if (BBS_OK != create_generator_next (cipher_suite,
					     generator_ctx,
					     Q_1,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, Q_1))
	{
		goto cleanup;
	}

	for (int i = 0; i<num_messages; i++)
	{
		// Calculate H_i
		if (BBS_OK != create_generator_next (cipher_suite, generator_ctx, H_i,
						     (uint8_t*) cipher_suite->api_id,
						     cipher_suite->api_id_len)
		    )
		{
			goto cleanup;
		}
		if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, H_i))
		{
			goto cleanup;
		}

		// Calculate msg_scalar (oneshot)
		msg     = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
					      (uint8_t*) cipher_suite->map_dst,
					      cipher_suite->map_dst_len, msg, msg_len, 0))
		{
			goto cleanup;
		}
		RLC_TRY {
			// Update B
			ep_mul (H_i, H_i, msg_scalar);
			ep_add (B, B, H_i);
		}
		RLC_CATCH_ANY {
			goto cleanup;
		}
	}

	// Finalize domain calculation
	if (BBS_OK != calculate_domain_finalize (cipher_suite,
						 cipher_suite->dom_ctx,
						 domain,
						 header,
						 header_len,
						 (uint8_t*) cipher_suite->api_id,
						 cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	RLC_TRY {
		// Update B
		ep_mul (Q_1, Q_1, domain);
		ep_add (B, B, Q_1);

		// Compute pairings e(A, W + BP2 * e) * e(B, -BP2)
		// For valid signatures, this is the identity.
		ep2_mul_gen (tmp_p, e);
		ep2_add (tmp_p, W, tmp_p);
		pp_map_oatep_k12 (paired1, A, tmp_p);

		bn_set_dig (e, 1); // reuse e as -1
		bn_neg (e, e);
		ep2_mul_gen (tmp_p, e);
		pp_map_oatep_k12 (paired2, B, tmp_p);

		fp12_mul (paired1, paired1, paired2);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Check signature equation
	if (RLC_EQ != fp12_cmp_dig (paired1, 1))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	bn_free (e);
	bn_free (domain);
	bn_free (msg_scalar);
	ep_free (A);
	ep_free (B);
	ep_free (Q_1);
	ep_free (H_i);
	ep2_free (W);
	ep2_free (tmp_p);
	fp12_free (paired1);
	fp12_free (paired2);
	return res;
}


// int bbs_sha256_proof_gen_det(
// 	const bbs_public_key  pk,
// 	const bbs_signature   signature,
// 	uint8_t              *proof,
// 	const uint8_t        *header,
// 	uint64_t              header_len,
// 	const uint8_t        *presentation_header,
// 	uint64_t              presentation_header_len,
// 	const uint64_t       *disclosed_indexes,
// 	uint64_t              disclosed_indexes_len,
// 	uint64_t              num_messages,
// 	bbs_bn_prf            prf,
// 	void                 *prf_cookie,
// 	va_list               ap
// ) {
// 	return bbs_proof_gen_det(&bbs_sha256_cipher_suite, pk, signature, proof, header, header_len, presentation_header, presentation_header_len, disclosed_indexes, disclosed_indexes_len, num_messages, prf, prf_cookie, ap);

// }


// bbs_proof_gen, but makes callbacks to prf for random scalars
// We need to control the random scalars for the fixture tests. This way we do
// not need to compile a dedicated library for the tests.
int
bbs_proof_gen_det (
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
	bbs_bn_prf            prf,
	void                 *prf_cookie,
	va_list               ap
	)
{
	va_list  ap2;
	uint8_t  generator_ctx[48 + 8];
	uint8_t  T_buffer[2 * BBS_G1_ELEM_LEN];
	uint8_t  scalar_buffer[BBS_SCALAR_LEN];
	uint8_t *proof_ptr, *msg;
	uint64_t msg_len, be_buffer;
	bn_t     e, domain, msg_scalar, msg_scalar_tilde, r1, r2, e_tilde, r1_tilde, r3_tilde,
		 challenge;
	ep_t     A, B, Q_1, H_i, T1, T2, D, Abar, Bbar;
	uint64_t disclosed_indexes_idx   = 0;
	uint64_t undisclosed_indexes_idx = 0;
	uint64_t undisclosed_indexes_len = num_messages - disclosed_indexes_len;
	int      res                     = BBS_ERROR;

	// We iterate over the messages twice because the spec is ****
	va_copy (ap2, ap);

	if (! header)
	{
		header     = (uint8_t*) "";
		header_len = 0;
	}

	if (! presentation_header)
	{
		presentation_header     = (uint8_t*) "";
		presentation_header_len = 0;
	}

	bn_null (e);
	bn_null (domain);
	bn_null (msg_scalar);
	bn_null (msg_scalar_tilde);
	bn_null (r1);
	bn_null (r2);
	bn_null (e_tilde);
	bn_null (r1_tilde);
	bn_null (r3_tilde);
	bn_null (challenge);
	ep_null (A);
	ep_null (B);
	ep_null (Q_1);
	ep_null (H_i);
	ep_null (T1);
	ep_null (T2);
	ep_null (D);
	ep_null (Abar);
	ep_null (Bbar);

	if (BBS_OK != create_generator_init (cipher_suite,
					     generator_ctx,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_init (cipher_suite, cipher_suite->dom_ctx, pk, num_messages))
	{
		goto cleanup;
	}

	RLC_TRY {
		bn_new (e);
		bn_new (domain);
		bn_new (msg_scalar);
		bn_new (msg_scalar_tilde);
		bn_new (r1);
		bn_new (r2);
		bn_new (e_tilde);
		bn_new (r1_tilde);
		bn_new (r3_tilde);
		bn_new (challenge);
		ep_new (A);
		ep_new (B);
		ep_new (Q_1);
		ep_new (H_i);
		ep_new (T1);
		ep_new (T2);
		ep_new (D);
		ep_new (Abar);
		ep_new (Bbar);

		// Initialize B to P1 and T2 to the identity
		ep_read_bbs (B, cipher_suite->p1);
		ep_set_infty (T2);

		// Parse the signature
		ep_read_bbs (A, signature);
		bn_read_bbs (e, signature + BBS_G1_ELEM_LEN);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Derive random scalars. The msg_scalar_tilde scalars are derived later
	if (BBS_OK != prf (r1,       1, 0, prf_cookie))
		goto cleanup;
	if (BBS_OK != prf (r2,       2, 0, prf_cookie))
		goto cleanup;
	if (BBS_OK != prf (e_tilde,  3, 0, prf_cookie))
		goto cleanup;
	if (BBS_OK != prf (r1_tilde, 4, 0, prf_cookie))
		goto cleanup;
	if (BBS_OK != prf (r3_tilde, 5, 0, prf_cookie))
		goto cleanup;

	// Calculate Q_1
	if (BBS_OK != create_generator_next (cipher_suite,
					     generator_ctx,
					     Q_1,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, Q_1))
	{
		goto cleanup;
	}

	proof_ptr = proof + 3 * BBS_G1_ELEM_LEN + 3 * BBS_SCALAR_LEN; // m_hat
	for (uint64_t i = 0; i<num_messages; i++)
	{
		// Calculate H_i
		if (BBS_OK != create_generator_next (cipher_suite, generator_ctx, H_i,
						     (uint8_t*) cipher_suite->api_id,
						     cipher_suite->api_id_len)
		    )
		{
			goto cleanup;
		}
		if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, H_i))
		{
			goto cleanup;
		}

		// Calculate msg_scalar (oneshot)
		msg     = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
					      (uint8_t*) cipher_suite->map_dst,
					      cipher_suite->map_dst_len, msg, msg_len, 0))
		{
			goto cleanup;
		}
		RLC_TRY {
			// Update B. Use Bbar as temporary buffer, because we
			// need H_i below
			ep_mul (Bbar, H_i, msg_scalar);
			ep_add (B, B, Bbar);
		}
		RLC_CATCH_ANY {
			goto cleanup;
		}

		if (disclosed_indexes_idx < disclosed_indexes_len && disclosed_indexes[
			    disclosed_indexes_idx] == i)
		{
			// This message is disclosed.
			// Here I would like to hash the disclosed messages into the
			// challenge. I can not do that however, since we need to hash
			// the domain first, and we have not calculated that one yet. As
			// a result, we need to iterate over the messages again later.
			// I am still hoping that this issue will be resolved in due
			// time.
			disclosed_indexes_idx++;
		}
		else
		{
			// This message is undisclosed. Derive new random scalar
			// and accumulate it onto T2
			if (BBS_OK != prf (msg_scalar_tilde, 0, undisclosed_indexes_idx, prf_cookie)
			    )
			{
				goto cleanup;
			}

			RLC_TRY {
				// Update T2
				ep_mul (H_i, H_i, msg_scalar_tilde);
				ep_add (T2, T2, H_i);

				// Save msg_scalar in the proof so that one day we
				// do not need to recalculate it
				bn_write_bbs (proof_ptr, msg_scalar);
			}
			RLC_CATCH_ANY {
				goto cleanup;
			}
			undisclosed_indexes_idx++;
			proof_ptr += BBS_SCALAR_LEN;
		}
	}

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	if (disclosed_indexes_idx != disclosed_indexes_len)
	{
		goto cleanup;
	}

	// Finalize domain calculation
	if (BBS_OK != calculate_domain_finalize (cipher_suite,
						 cipher_suite->dom_ctx,
						 domain,
						 header,
						 header_len,
						 (uint8_t*) cipher_suite->api_id,
						 cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	RLC_TRY {
		// Update B
		ep_mul (Q_1, Q_1, domain);
		ep_add (B, B, Q_1);

		// Calculate and write out D to proof
		ep_mul (D, B, r2);
		ep_write_bbs (proof + 2 * BBS_G1_ELEM_LEN, D);

		// Starting here, we no longer need B, so we use it as a
		// temporary variable.

		// Calculate and write out Abar to proof
		ep_mul (Abar, A,    r1);
		ep_mul (Abar, Abar, r2);
		ep_write_bbs (proof, Abar);

		// Calculate and write out Bbar to proof
		ep_mul (Bbar, D,    r1);
		ep_mul (B,    Abar, e);
		ep_neg (B, B);
		ep_add (Bbar, Bbar, B);
		ep_write_bbs (proof + BBS_G1_ELEM_LEN, Bbar);

		// Calculate and write out T1 and T2 for the challenge
		ep_mul (B, D, r3_tilde);
		ep_add (T2, T2, B);
		ep_mul (T1, D,    r1_tilde);
		ep_mul (B,  Abar, e_tilde);
		ep_add (T1, T1, B);
		ep_write_bbs (T_buffer,                   T1);
		ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, T2);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Calculate the challenge
	if (BBS_OK != hash_to_scalar_init (cipher_suite, cipher_suite->ch_ctx))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     proof,
					     3 * BBS_G1_ELEM_LEN))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     T_buffer,
					     2 * BBS_G1_ELEM_LEN))
	{
		goto cleanup;
	}
	be_buffer = UINT64_H2BE (disclosed_indexes_len);
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     (uint8_t*) &be_buffer,
					     8))
	{
		goto cleanup;
	}
	// Given a better spec, we could merge almost all for loops in here...
	for (uint64_t i = 0; i<disclosed_indexes_len; i++)
	{
		be_buffer = UINT64_H2BE (disclosed_indexes[i]);
		if (BBS_OK != hash_to_scalar_update (cipher_suite,
						     cipher_suite->ch_ctx,
						     (uint8_t*) &be_buffer,
						     8))
		{
			goto cleanup;
		}
	}
	// We have to go over all disclosed messages again. Someone please fix
	// this in the spec...
	disclosed_indexes_idx = 0;
	for (uint64_t i = 0; i<num_messages; i++)
	{
		// Calculate msg_scalar (oneshot)
		msg     = va_arg (ap2, uint8_t*);
		msg_len = va_arg (ap2, uint32_t);
		if (disclosed_indexes_idx < disclosed_indexes_len && disclosed_indexes[
			    disclosed_indexes_idx] == i)
		{
			disclosed_indexes_idx++;
			if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
						      (uint8_t*) cipher_suite->map_dst,
						      cipher_suite->map_dst_len, msg, msg_len, 0))
			{
				goto cleanup;
			}
			RLC_TRY {
				bn_write_bbs (scalar_buffer, msg_scalar);
			}
			RLC_CATCH_ANY {
				goto cleanup;
			}
			if (BBS_OK != hash_to_scalar_update (cipher_suite, cipher_suite->ch_ctx,
							     scalar_buffer, BBS_SCALAR_LEN)
			    )
			{
				goto cleanup;
			}
		}
	}
	RLC_TRY {
		// Write out the domain. We reuse scalar_buffer
		bn_write_bbs (scalar_buffer, domain);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     scalar_buffer,
					     BBS_SCALAR_LEN))
	{
		goto cleanup;
	}
	be_buffer = UINT64_H2BE (presentation_header_len);
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     (uint8_t*) &be_buffer,
					     8))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     presentation_header,
					     presentation_header_len))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_finalize (cipher_suite,
					       cipher_suite->ch_ctx,
					       challenge,
					       (uint8_t*) cipher_suite->challenge_dst,
					       cipher_suite->challenge_dst_len))
	{
		goto cleanup;
	}

	proof_ptr = proof + 3 * BBS_G1_ELEM_LEN;
	RLC_TRY {
		// Write out the challenge
		bn_write_bbs (proof + BBS_PROOF_LEN (undisclosed_indexes_len)
			      - BBS_SCALAR_LEN, challenge);

		// e_hat
		bn_mul (e, e, challenge);
		bn_add (e_tilde, e_tilde, e);
		bn_mod (e_tilde, e_tilde, &(core_get ()->ep_r));
		bn_write_bbs (proof_ptr, e_tilde);
		proof_ptr += BBS_SCALAR_LEN;

		// r1_hat
		bn_mul (r1, r1, challenge);
		bn_mod (r1, r1, &(core_get ()->ep_r));
		bn_neg (r1, r1);
		bn_add (r1_tilde, r1_tilde, r1);
		bn_mod (r1_tilde, r1_tilde, &(core_get ()->ep_r)); // This works with negative r1_tilde
		bn_write_bbs (proof_ptr, r1_tilde);
		proof_ptr += BBS_SCALAR_LEN;

		// r3_hat (r2 contains r3)
		bn_mod_inv (r2, r2, &(core_get ()->ep_r));
		bn_mul (r2, r2, challenge);
		bn_mod (r2, r2, &(core_get ()->ep_r));
		bn_neg (r2, r2);
		bn_add (r3_tilde, r3_tilde, r2);
		bn_mod (r3_tilde, r3_tilde, &(core_get ()->ep_r)); // This works with negative r3_tilde
		bn_write_bbs (proof_ptr, r3_tilde);
		proof_ptr += BBS_SCALAR_LEN;
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	for (undisclosed_indexes_idx = 0;
	     undisclosed_indexes_idx < undisclosed_indexes_len;
	     undisclosed_indexes_idx++)
	{
		if (BBS_OK != prf (msg_scalar_tilde, 0, undisclosed_indexes_idx, prf_cookie))
		{
			goto cleanup;
		}
		RLC_TRY {
			// m_j_hat
			bn_read_bbs (msg_scalar, proof_ptr);
			bn_mul (msg_scalar, msg_scalar, challenge);
			bn_add (msg_scalar_tilde, msg_scalar_tilde, msg_scalar);
			bn_mod (msg_scalar_tilde, msg_scalar_tilde, &(core_get ()->ep_r));
			bn_write_bbs (proof_ptr, msg_scalar_tilde);
			proof_ptr += BBS_SCALAR_LEN;
		}
		RLC_CATCH_ANY {
			goto cleanup;
		}
	}

	res = BBS_OK;
cleanup:
	va_end (ap2);
	bn_free (e);
	bn_free (domain);
	bn_free (msg_scalar);
	bn_free (msg_scalar_tilde);
	bn_free (r1);
	bn_free (r2);
	bn_free (e_tilde);
	bn_free (r1_tilde);
	bn_free (r3_tilde);
	bn_free (challenge);
	ep_free (A);
	ep_free (B);
	ep_free (Q_1);
	ep_free (H_i);
	ep_free (T1);
	ep_free (T2);
	ep_free (D);
	ep_free (Abar);
	ep_free (Bbar);
	return res;
}


int
bbs_proof_prf (
	bn_t      out,
	uint8_t   input_type,
	uint64_t  input,
	void     *seed
	)
{
	// All these have length 17
	static uint8_t *dsts[] = {
		(uint8_t*) "random msg scalar", (uint8_t*) "random r_1 scalar",
		(uint8_t*) "random r_2 scalar", (uint8_t*) "random e_t scalar",
		(uint8_t*) "random r1t scalar", (uint8_t*) "random r3t scalar",
	};

	if (input_type >= LEN (dsts))
		return BBS_ERROR;
	return hash_to_scalar (&bbs_sha256_cipher_suite,
			       out,
			       dsts[input_type],
			       17,
			       seed,
			       32,
			       input,
			       8,
			       0);
}

int
bbs_sha256_proof_gen (
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
	va_list ap;
	va_start (ap, num_messages);
	int     result = bbs_proof_gen (&bbs_sha256_cipher_suite,
					pk,
					signature,
					proof,
					header,
					header_len,
					presentation_header,
					presentation_header_len,
					disclosed_indexes,
					disclosed_indexes_len,
					num_messages,
					ap);
	va_end (ap);
	return result;
}


int
bbs_shake256_proof_gen (
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
	va_list ap;
	va_start (ap, num_messages);
	int     result = bbs_proof_gen (&bbs_shake256_cipher_suite,
					pk,
					signature,
					proof,
					header,
					header_len,
					presentation_header,
					presentation_header_len,
					disclosed_indexes,
					disclosed_indexes_len,
					num_messages,
					ap);
	va_end (ap);
	return result;
}


int
bbs_proof_gen (
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
	va_list               ap
	)
{
	uint8_t seed[32];
	int     ret = BBS_ERROR;

	RLC_TRY {
		// Gather randomness. The seed is used for any randomness within this
		// function. In particular, this implies that we do not need to store
		// intermediate derivations. Currently, we derive new values via
		// hash_to_scalar, but we might want to exchange that for
		// something faster later on.
		rand_bytes (seed, 32);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	if (BBS_OK != bbs_proof_gen_det (cipher_suite,
					 pk,
					 signature,
					 proof,
					 header,
					 header_len,
					 presentation_header,
					 presentation_header_len,
					 disclosed_indexes,
					 disclosed_indexes_len,
					 num_messages,
					 bbs_proof_prf,
					 seed,
					 ap))
	{
		goto cleanup;
	}

	ret = BBS_OK;
cleanup:
	return ret;
}


int
bbs_sha256_proof_verify (
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
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_proof_verify (&bbs_sha256_cipher_suite,
					   pk,
					   proof,
					   proof_len,
					   header,
					   header_len,
					   presentation_header,
					   presentation_header_len,
					   disclosed_indexes,
					   disclosed_indexes_len,
					   num_messages,
					   args);
	va_end (args);
	return result;

}


int
bbs_shake256_proof_verify (
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
	...
	)
{
	va_list args;
	va_start (args, num_messages);
	int     result = bbs_proof_verify (&bbs_shake256_cipher_suite,
					   pk,
					   proof,
					   proof_len,
					   header,
					   header_len,
					   presentation_header,
					   presentation_header_len,
					   disclosed_indexes,
					   disclosed_indexes_len,
					   num_messages,
					   args);
	va_end (args);
	return result;

}


int
bbs_proof_verify (
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
	va_list               ap
	)
{
	uint8_t        generator_ctx[48 + 8];
	uint8_t        T_buffer[2 * BBS_G1_ELEM_LEN];
	uint8_t        scalar_buffer[BBS_SCALAR_LEN];
	const uint8_t *proof_ptr, *msg;
	uint64_t       msg_len, be_buffer;
	bn_t           domain, msg_scalar, e_hat, r1_hat, r3_hat, challenge, challenge_prime;
	ep_t           Bv, Q_1, H_i, T1, T2, D, Abar, Bbar;
	ep2_t          W;
	fp12_t         paired1, paired2;
	uint64_t       disclosed_indexes_idx   = 0;
	uint64_t       undisclosed_indexes_idx = 0;
	uint64_t       undisclosed_indexes_len = num_messages - disclosed_indexes_len;
	int            res                     = BBS_ERROR;
	va_list        ap2;

	// Make a copy of the va_list to use for the first iteration
	va_copy (ap2, ap);

	if (! header)
	{
		header     = (uint8_t*) "";
		header_len = 0;
	}

	if (! presentation_header)
	{
		presentation_header     = (uint8_t*) "";
		presentation_header_len = 0;
	}

	bn_null (domain);
	bn_null (msg_scalar);
	bn_null (e_hat);
	bn_null (r1_hat);
	bn_null (r3_hat);
	bn_null (challenge);
	bn_null (challenge_prime);
	ep_null (Bv);
	ep_null (Q_1);
	ep_null (H_i);
	ep_null (T1);
	ep_null (T2);
	ep_null (D);
	ep_null (Abar);
	ep_null (Bbar);
	ep2_null (W);
	fp12_null (paired1);
	fp12_null (paired2);


	// Sanity check. We let the application give us the length explicitly,
	// and perform the length check here.
	if (proof_len != BBS_PROOF_LEN (undisclosed_indexes_len))
	{
		goto cleanup;
	}

	if (BBS_OK != create_generator_init (cipher_suite,
					     generator_ctx,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_init (cipher_suite, cipher_suite->dom_ctx, pk, num_messages))
	{
		goto cleanup;
	}

	RLC_TRY {
		bn_new (domain);
		bn_new (msg_scalar);
		bn_new (e_hat);
		bn_new (r1_hat);
		bn_new (r3_hat);
		bn_new (challenge);
		bn_new (challenge_prime);
		ep_new (Bv);
		ep_new (Q_1);
		ep_new (H_i);
		ep_new (T1);
		ep_new (T2);
		ep_new (D);
		ep_new (Abar);
		ep_new (Bbar);
		ep2_new (W);
		fp12_new (paired1);
		fp12_new (paired2);

		// Parse pk
		ep2_read_bbs (W, pk);

		// Parse the proof excluding the msg_scalar_hat values
		// Those will be read later
		proof_ptr  = proof;
		ep_read_bbs (Abar, proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_read_bbs (Bbar, proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_read_bbs (D,    proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		bn_read_bbs (e_hat,     proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (r1_hat,    proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (r3_hat,    proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (challenge, proof + BBS_PROOF_LEN (undisclosed_indexes_len)
			     - BBS_SCALAR_LEN);

		// Calculate T1. We use T2 as a temporary variable here
		ep_mul (T1, Bbar, challenge);
		ep_mul (T2, Abar, e_hat);
		ep_add (T1, T1, T2);
		ep_mul (T2, D, r1_hat);
		ep_add (T1, T1, T2);

		// Initialize Bv to P1 and T2 to D*r3_hat
		ep_read_bbs (Bv, cipher_suite->p1);
		ep_mul (T2, D, r3_hat);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Calculate Q_1
	if (BBS_OK != create_generator_next (cipher_suite,
					     generator_ctx,
					     Q_1,
					     (uint8_t*) cipher_suite->api_id,
					     cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, Q_1))
	{
		goto cleanup;
	}

	for (uint64_t i = 0; i<num_messages; i++)
	{
		// Calculate H_i
		if (BBS_OK != create_generator_next (cipher_suite, generator_ctx, H_i,
						     (uint8_t*) cipher_suite->api_id,
						     cipher_suite->api_id_len)
		    )
		{
			goto cleanup;
		}
		if (BBS_OK != calculate_domain_update (cipher_suite, cipher_suite->dom_ctx, H_i))
		{
			goto cleanup;
		}

		if (disclosed_indexes_idx < disclosed_indexes_len && disclosed_indexes[
			    disclosed_indexes_idx] == i)
		{
			// This message is disclosed.
			// Read in the message and accumulate onto Bv
			msg     = va_arg (ap, uint8_t*);
			msg_len = va_arg (ap, uint32_t);

			// Calculate msg_scalar (oneshot)
			if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
						      (uint8_t*) cipher_suite->map_dst,
						      cipher_suite->map_dst_len, msg, msg_len, 0))
			{
				goto cleanup;
			}
			RLC_TRY {
				// Update Bv.
				ep_mul (H_i, H_i, msg_scalar);
				ep_add (Bv, Bv, H_i);
			}
			RLC_CATCH_ANY {
				goto cleanup;
			}
			// Again, I would like to hash msg_scalar into the
			// challenge, but can't yet. Thus we will have to
			// recalculate it later...
			disclosed_indexes_idx++;
		}
		else
		{
			// This message is undisclosed.
			// Read a msg_scalar_hat value and accumulate it onto T2
			RLC_TRY {
				// Update T2.
				bn_read_bbs (msg_scalar, proof_ptr);
				proof_ptr += BBS_SCALAR_LEN;
				ep_mul (H_i, H_i, msg_scalar);
				ep_add (T2, T2, H_i);
			}
			RLC_CATCH_ANY {
				goto cleanup;
			}
			undisclosed_indexes_idx++;
		}
	}

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	if (disclosed_indexes_idx != disclosed_indexes_len)
	{
		goto cleanup;
	}

	// Finalize domain calculation
	if (BBS_OK != calculate_domain_finalize (cipher_suite,
						 cipher_suite->dom_ctx,
						 domain,
						 header,
						 header_len,
						 (uint8_t*) cipher_suite->api_id,
						 cipher_suite->api_id_len))
	{
		goto cleanup;
	}
	RLC_TRY {
		// Finalize Bv
		ep_mul (Q_1, Q_1, domain);
		ep_add (Bv, Bv, Q_1);

		// Finalize T2
		ep_mul (Bv, Bv, challenge);
		ep_add (T2, T2, Bv);

		// Write out T1 and T2 for the challenge
		ep_write_bbs (T_buffer,                   T1);
		ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, T2);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Calculate the challenge
	if (BBS_OK != hash_to_scalar_init (cipher_suite, cipher_suite->ch_ctx))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     proof,
					     3 * BBS_G1_ELEM_LEN))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     T_buffer,
					     2 * BBS_G1_ELEM_LEN))
	{
		goto cleanup;
	}
	be_buffer = UINT64_H2BE (disclosed_indexes_len);
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     (uint8_t*) &be_buffer,
					     8))
	{
		goto cleanup;
	}
	// Given a better spec, we could merge almost all for loops in here...
	for (uint64_t i = 0; i<disclosed_indexes_len; i++)
	{
		be_buffer = UINT64_H2BE (disclosed_indexes[i]);
		if (BBS_OK != hash_to_scalar_update (cipher_suite, cipher_suite->ch_ctx,
						     (uint8_t*) &be_buffer, 8))
		{
			goto cleanup;
		}
	}
	// We have to go over all disclosed messages again. Someone please fix
	// this in the spec...
	for (disclosed_indexes_idx = 0; disclosed_indexes_idx<disclosed_indexes_len;
	     disclosed_indexes_idx++)
	{
		// Calculate msg_scalar (oneshot)
		msg     = va_arg (ap2, uint8_t*);
		msg_len = va_arg (ap2, uint32_t);
		if (BBS_OK != hash_to_scalar (cipher_suite, msg_scalar,
					      (uint8_t*) cipher_suite->map_dst,
					      cipher_suite->map_dst_len, msg, msg_len, 0))
		{
			goto cleanup;
		}
		RLC_TRY {
			bn_write_bbs (scalar_buffer, msg_scalar);
		}
		RLC_CATCH_ANY {
			goto cleanup;
		}
		if (BBS_OK != hash_to_scalar_update (cipher_suite, cipher_suite->ch_ctx,
						     scalar_buffer, BBS_SCALAR_LEN))
		{
			goto cleanup;
		}
	}
	va_end (ap2);
	RLC_TRY {
		// Write out the domain. We reuse scalar_buffer
		bn_write_bbs (scalar_buffer, domain);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     scalar_buffer,
					     BBS_SCALAR_LEN))
	{
		goto cleanup;
	}
	be_buffer = UINT64_H2BE (presentation_header_len);
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     (uint8_t*) &be_buffer,
					     8))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_update (cipher_suite,
					     cipher_suite->ch_ctx,
					     presentation_header,
					     presentation_header_len))
	{
		goto cleanup;
	}
	if (BBS_OK != hash_to_scalar_finalize (cipher_suite,
					       cipher_suite->ch_ctx,
					       challenge_prime,
					       (uint8_t*) cipher_suite->challenge_dst,
					       cipher_suite->challenge_dst_len))
	{
		goto cleanup;
	}

	// Verification Step 1: The PoK was valid
	if (RLC_EQ != bn_cmp (challenge, challenge_prime))
	{
		goto cleanup;
	}

	// Verification Step 2: The original signature was valid
	RLC_TRY {
		// Compute pairings e(Abar, W) * e(Bbar, -BP2)
		// For valid signatures, this is the identity.
		pp_map_oatep_k12 (paired1, Abar, W);

		ep2_curve_get_gen (W); // Reuse W
		ep2_neg (W, W);
		pp_map_oatep_k12 (paired2, Bbar, W);

		fp12_mul (paired1, paired1, paired2);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	// Check signature equation
	if (RLC_EQ != fp12_cmp_dig (paired1, 1))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	bn_free (domain);
	bn_free (msg_scalar);
	bn_free (e_hat);
	bn_free (r1_hat);
	bn_free (r3_hat);
	bn_free (challenge);
	bn_free (challenge_prime);
	ep_free (Bv);
	ep_free (Q_1);
	ep_free (H_i);
	ep_free (T1);
	ep_free (T2);
	ep_free (D);
	ep_free (Abar);
	ep_free (Bbar);
	ep2_free (W);
	fp12_free (paired1);
	fp12_free (paired2);
	return res;
}
