#include "bbs.h"
#include "bbs_util.h"

inline void
bn_write_bbs (
	uint8_t     bin[BBS_SCALAR_LEN],
	const bn_t  n
	)
{
	bn_write_bin (bin, BBS_SCALAR_LEN, n);
}


inline void
bn_read_bbs (
	bn_t           n,
	const uint8_t  bin[BBS_SCALAR_LEN]
	)
{
	bn_read_bin (n, bin, BBS_SCALAR_LEN);
	if (bn_cmp (n, &core_get ()->prime) != RLC_LT)
	{
		RLC_THROW (ERR_NO_VALID);
	}
}


void
ep_write_bbs (
	uint8_t     bin[BBS_G1_ELEM_LEN],
	const ep_t  p
	)
{
	ep_t t;
	ep_null (t);

	if (ep_is_infty (p))
	{
		RLC_THROW (ERR_NO_VALID);
	}

	ep_norm (t, p);
	ep_pck (t, t);
	fp_write_bin (bin, BBS_G1_ELEM_LEN, t->x);
	bin[0] |= (1 << 7) | (fp_get_bit (t->y, 0) << 5);
	ep_free (t);
}


void
ep_read_bbs (
	ep_t           p,
	const uint8_t  bin[BBS_G1_ELEM_LEN]
	)
{
	uint8_t buffer[BBS_G1_ELEM_LEN];
	uint8_t flags = bin[0] & 0xe0;

	for (int i = 0; i<BBS_G1_ELEM_LEN / 8; i++)
		((uint64_t*) buffer)[i] = ((uint64_t*) bin)[i];
	buffer[0] ^= flags;
	if (0x80 != flags && 0xa0 != flags)
	{
		// In particular, we should never read the neutral element!
		// Allowing that would make the algorithms insecure.
		RLC_THROW (ERR_NO_VALID);
	}

	p->coord = BASIC;
	fp_read_bin (p->x, buffer, BBS_G1_ELEM_LEN);
	fp_zero (p->y);
	fp_set_bit (p->y, 0, (flags >> 5) & 1);
	fp_set_dig (p->z, 1);
	ep_upk (p, p);

	if (! ep_on_curve (p))
	{
		RLC_THROW (ERR_NO_VALID);
	}
}


void
ep2_write_bbs (
	uint8_t      bin[BBS_G2_ELEM_LEN],
	const ep2_t  p
	)
{
	ep2_t t;
	ep2_null (t);

	if (ep2_is_infty (p))
	{
		// Should not happen
		RLC_THROW (ERR_NO_VALID);
	}

	ep2_norm (t, p);
	ep2_pck (t, t);
	fp_write_bin (bin,                       BBS_G2_ELEM_LEN / 2, t->x[1]);
	fp_write_bin (bin + BBS_G2_ELEM_LEN / 2, BBS_G2_ELEM_LEN / 2, t->x[0]);
	bin[0] |= (1 << 7) | (fp_get_bit (t->y[0], 0) << 5);
	ep2_free (t);
}


void
ep2_read_bbs (
	ep2_t          p,
	const uint8_t  bin[BBS_G2_ELEM_LEN]
	)
{
	uint8_t buffer[BBS_G2_ELEM_LEN];
	uint8_t flags = bin[0] & 0xe0;

	for (int i = 0; i<BBS_G2_ELEM_LEN / 8; i++)
		((uint64_t*) buffer)[i] = ((uint64_t*) bin)[i];
	buffer[0] ^= flags;
	if (0x80 != flags && 0xa0 != flags)
	{
		// In particular, we should never read the neutral element!
		// Allowing that would make the algorithms insecure.
		RLC_THROW (ERR_NO_VALID);
	}

	p->coord = BASIC;
	fp_read_bin (p->x[1], buffer,                       BBS_G2_ELEM_LEN / 2);
	fp_read_bin (p->x[0], buffer + BBS_G2_ELEM_LEN / 2, BBS_G2_ELEM_LEN / 2);
	fp2_zero (p->y);
	fp_set_bit (p->y[0], 0, (flags >> 5) & 1);
	fp_zero (p->y[1]);
	fp2_set_dig (p->z, 1);
	ep2_upk (p, p);

	if (! ep2_on_curve (p))
	{
		RLC_THROW (ERR_NO_VALID);
	}
}


// Note: Incremental expand_message API with fixed 48B output needed multiple times during BBS execution. 
// During generator creation bigger outputs are needed, however not with an incremental API.

// SHA256
int expand_message_init_sha256 (
	union bbs_hash_context *ctx
	)
{
	uint64_t       zero[]  = {0, 0, 0, 0, 0, 0, 0, 0};
	int            res     = BBS_ERROR;

	if (shaSuccess != SHA256Reset (&ctx->sha256))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, (uint8_t*) zero, 64))
		goto cleanup;

	res = BBS_OK;
cleanup:
	return res;
}


int expand_message_update_sha256 (
	union bbs_hash_context *ctx,
	const uint8_t *msg,
	uint32_t       msg_len
	)
{
	int            res     = BBS_ERROR;

	if (shaSuccess != SHA256Input (&ctx->sha256, msg, msg_len))
		goto cleanup;

	res = BBS_OK;
cleanup:
	return res;
}


int expand_message_finalize_48B_sha256 (
	union bbs_hash_context *ctx,
	uint8_t        out[48],
	const uint8_t *dst,
	uint8_t        dst_len
	)
{
	uint8_t        b_0[32];
	uint8_t        b_1[32];
	uint8_t        b_2[32];
	int            res     = BBS_ERROR;
	uint8_t        num     = 0;

	if (shaSuccess != SHA256Input (&ctx->sha256, &num, 1))
		goto cleanup;
	num = 48;
	if (shaSuccess != SHA256Input (&ctx->sha256, &num, 1))
		goto cleanup;
	num = 0;
	if (shaSuccess != SHA256Input (&ctx->sha256, &num, 1))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, dst, dst_len))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, &dst_len, 1))
		goto cleanup;
	if (shaSuccess != SHA256Result (&ctx->sha256, b_0))
		goto cleanup;

	// b_1 = H( b_0, I2OSP(1,1), dst, I2OSP(dst_len, 1))
	if (shaSuccess != SHA256Reset (&ctx->sha256))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, b_0, 32))
		goto cleanup;
	num = 1;
	if (shaSuccess != SHA256Input (&ctx->sha256, &num, 1))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, dst, dst_len))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, &dst_len, 1))
		goto cleanup;
	if (shaSuccess != SHA256Result (&ctx->sha256, b_1))
		goto cleanup;

	// b_0 ^= b_1
	for (int i = 0; i<4; i++)
		((uint64_t*) b_0)[i] ^= ((uint64_t*) b_1)[i];

	// b_2 = H( b_0, I2OSP(2,1), dst, I2OSP(dst_len, 1))
	if (shaSuccess != SHA256Reset (&ctx->sha256))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, b_0, 32))
		goto cleanup;
	num = 2;
	if (shaSuccess != SHA256Input (&ctx->sha256, &num, 1))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, dst, dst_len))
		goto cleanup;
	if (shaSuccess != SHA256Input (&ctx->sha256, &dst_len, 1))
		goto cleanup;
	if (shaSuccess != SHA256Result (&ctx->sha256, b_2))
		goto cleanup;

	for (int i = 0; i<4; i++)
		((uint64_t*) out)[i] = ((uint64_t*) b_1)[i];
	for (int i = 4; i<6; i++)
		((uint64_t*) out)[i] = ((uint64_t*) b_2)[i - 4];

	res = BBS_OK;
cleanup:
	return res;
}


int expand_message_dyn_sha256 (
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *msg,
	uint32_t       msg_len,
	const uint8_t *dst,
	uint8_t        dst_len
	)
{
	// Hash to curve g1
	// relic does implement this as ep_map_sswum, but hard-codes the dst, so
	// we need to reimplement the high level parts here
	RLC_TRY {
		md_xmd (out, out_len, msg, msg_len, dst, dst_len);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}
	return BBS_OK;
}


// SHAKE256
int expand_message_init_shake256 (
	union bbs_hash_context *ctx
	)
{
	int           res       = shake256_init (&ctx->shake256);
	if (res)
	{
		return BBS_OK;
	}
	else
	{
		return BBS_ERROR;
	}
}


int expand_message_update_shake256 (
	union bbs_hash_context *ctx,
	const uint8_t *msg,
	uint32_t       msg_len
	)
{
	int           res       = shake_update (&ctx->shake256, msg, msg_len);
	if (res)
	{
		return BBS_OK;
	}
	else
	{
		return BBS_ERROR;
	}
}


/**
 * @brief Finalizes the expand_message xof operation with flexible output size.
 *
 * https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xof
*/
int
expand_message_finalize_dyn_shake256 (
	union bbs_hash_context *ctx,
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *dst,
	uint8_t        dst_len
	)
{
	int res = BBS_ERROR;
	if (out_len > 65535)
	{
		goto cleanup;
	}
	if (dst_len > 255)
	{
		goto cleanup;
	}
	// H(msg || I2OSP(len_in_bytes, 2) || DST || I2OSP(len(DST), 1), len_in_bytes)
	uint8_t num = out_len / 256;
	if (shake_update (&ctx->shake256, &num, 1) == 0)
		goto cleanup;
	num = out_len % 256;
	if (shake_update (&ctx->shake256, &num, 1) == 0)
		goto cleanup;
	if (shake_update (&ctx->shake256, dst, dst_len) == 0)
		goto cleanup;
	if (shake_update (&ctx->shake256, &dst_len, 1) == 0)
		goto cleanup;

	shake_xof (&ctx->shake256);
	// if (Keccak_HashFinal (&ctx->shake256, NULL) != KECCAK_SUCCESS)
	//	goto cleanup;
	shake_out (&ctx->shake256, out, out_len);
	res = BBS_OK;
cleanup:
	return res;
}


/**
 * @brief Finalizes the expand_message xof operation with fixed output size of 48 bytes.
 *
 * https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xof
*/
int expand_message_finalize_48B_shake256 (
	union bbs_hash_context *ctx,
	uint8_t        out[48],
	const uint8_t *dst,
	uint8_t        dst_len
	)
{
	return expand_message_finalize_dyn_shake256 (ctx, out, 48, dst, dst_len);
}


int
expand_message_dyn_shake256 (
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *msg,
	uint32_t       msg_len,
	const uint8_t *dst,
	uint8_t        dst_len
	)
{
	union bbs_hash_context ctx;
	int                  res       = BBS_ERROR;

	if (BBS_OK !=  expand_message_init_shake256 (&ctx))
	{
		goto cleanup;
	}

	if (BBS_OK != expand_message_update_shake256 (&ctx, msg, msg_len))
	{
		goto cleanup;
	}

	if (BBS_OK != expand_message_finalize_dyn_shake256 (&ctx,
								out,
								out_len,
								dst,
								dst_len))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


inline int
hash_to_scalar_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx
	)
{
	return cipher_suite->expand_message_init (ctx);
}


inline int
hash_to_scalar_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t      *msg,
	uint32_t            msg_len
	)
{
	return cipher_suite->expand_message_update (ctx, msg, msg_len);
}


inline int
hash_to_scalar_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	bn_t                out,
	const uint8_t      *dst,
	uint8_t             dst_len
	)
{
	uint8_t buffer[48];
	int     res = BBS_ERROR;

	if (BBS_OK != cipher_suite->expand_message_finalize_48B (ctx, buffer, dst, dst_len))
	{
		goto cleanup;
	}

	RLC_TRY {
		bn_read_bin (out, buffer, 48);
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
hash_to_scalar (
	bbs_cipher_suite_t *cipher_suite,
	bn_t                out,
	const uint8_t      *dst,
	uint8_t             dst_len,
	uint64_t            num_messages,
	...
	)
{
	va_list  ap;
	uint8_t *msg     = 0;
	uint32_t msg_len = 0;
	union bbs_hash_context hash_ctx;
	int      res     = BBS_ERROR;

	if (BBS_OK != hash_to_scalar_init (cipher_suite, &hash_ctx))
	{
		goto cleanup;
	}

	va_start (ap, num_messages);
	for(uint64_t i=0; i< num_messages; i++)
	{
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		if (BBS_OK != hash_to_scalar_update (cipher_suite,
						     &hash_ctx,
						     msg,
						     msg_len))
		{
			goto cleanup;
		}
	}
	va_end (ap);

	if (BBS_OK != hash_to_scalar_finalize (cipher_suite,
					       &hash_ctx,
					       out,
					       dst,
					       dst_len))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


int
calculate_domain_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages
	)
{
	uint64_t num_messages_be = UINT64_H2BE (num_messages);
	int      res             = BBS_ERROR;

	if (BBS_OK != hash_to_scalar_init (cipher_suite, ctx))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, pk, BBS_PK_LEN))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, (uint8_t*) &num_messages_be, 8))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


int
calculate_domain_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const ep_t          generator
	)
{
	int     res = BBS_ERROR;
	uint8_t buffer[BBS_G1_ELEM_LEN];

	RLC_TRY {
		ep_write_bbs (buffer, generator);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, buffer, BBS_G1_ELEM_LEN))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


int
calculate_domain_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	bn_t                out,
	const uint8_t      *header,
	uint64_t            header_len,
	const uint8_t      *api_id,
	uint8_t             api_id_len
	)
{
	int      res           = BBS_ERROR;
	uint8_t  domain_dst[256];
	uint64_t header_len_be = UINT64_H2BE (header_len);

	if (api_id_len > 251)
	{
		goto cleanup;
	}

	for (int i = 0; i < api_id_len; i++)
		domain_dst[i] = api_id[i];
	for (int i = 0; i < 4; i++)
		domain_dst[i + api_id_len] = "H2S_"[i];

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, api_id, api_id_len))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, (uint8_t*) &header_len_be, 8))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_update (cipher_suite, ctx, header, header_len))
	{
		goto cleanup;
	}

	if (BBS_OK != hash_to_scalar_finalize (cipher_suite, ctx, out, domain_dst, api_id_len + 4))
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}

/*
int
calculate_domain (
	bbs_cipher_suite_t *cipher_suite,
	bn_t                out,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages,
	const uint8_t      *header,
	uint64_t            header_len,
	const uint8_t      *api_id,
	uint8_t             api_id_len,
	...
	)
{
	va_list ap;
	ep_t   *generator;
	union bbs_hash_context hash_ctx;
	int     res = BBS_ERROR;

	if (BBS_OK != calculate_domain_init (cipher_suite, &hash_ctx, pk,
					     num_messages))
	{
		goto cleanup;
	}

	va_start (ap, api_id_len);
	while ((generator = va_arg (ap, ep_t*)))
	{
		if (BBS_OK != calculate_domain_update (cipher_suite,
						       &hash_ctx,
						       *generator))
		{
			goto cleanup;
		}
	}
	va_end (ap);

	if (BBS_OK != calculate_domain_finalize (cipher_suite,
						 &hash_ctx,
						 out,
						 header,
						 header_len,
						 api_id,
						 api_id_len)
	    )
	{
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}
*/

int
create_generator_init (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	const uint8_t      *api_id,
	uint32_t            api_id_len
	)
{
	uint8_t buffer[256];
	union bbs_hash_context hash_ctx;
	int     res = BBS_ERROR;

	if (api_id_len > 255 - 19)
	{
		goto cleanup;
	}

	for (int i = 0; i < api_id_len; i++)
		buffer[i] = api_id[i];
	for (int i = 0; i < 19; i++)
		buffer[i + api_id_len] = "SIG_GENERATOR_SEED_"[i];

	if (BBS_OK != cipher_suite->expand_message_init (&hash_ctx))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_update (&hash_ctx,
					     api_id,
					     api_id_len))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_update (&hash_ctx,
					     (uint8_t*) "MESSAGE_GENERATOR_SEED",
					     22))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_finalize_48B (&hash_ctx,
						   state,
						   buffer,
						   api_id_len + 19))
	{
		goto cleanup;
	}

	*((uint64_t*) (state + 48)) = 1LL;

	res                         = BBS_OK;
cleanup:
	return res;
}


//
// BEGIN Excerpt from relic's src/ep/relic_ep_map.c
//
#include <relic_tmpl_map.h>
TMPL_MAP_HORNER (fp, fp_st);
TMPL_MAP_ISOGENY_MAP (ep, fp, iso);
#define EP_MAP_COPY_COND(O, I, C) dv_copy_cond (O, I, RLC_FP_DIGS, C)
TMPL_MAP_SSWU (ep, fp, dig_t, EP_MAP_COPY_COND);

static void
ep_map_from_field (ep_t p,
		   const uint8_t *uniform_bytes,
		   size_t len,
		   void (*const map_fn)(ep_t, const fp_t)
		   )
{
	bn_t         k;
	fp_t         t;
	ep_t         q;
	int          neg;
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t len_per_elm = (FP_PRIME + ep_param_level () + 7) / 8;

	bn_null (k);
	fp_null (t);
	ep_null (q);

	RLC_TRY {
		if (len != 2 * len_per_elm)
		{
			RLC_THROW (ERR_NO_VALID);
		}

		bn_new (k);
		fp_new (t);
		ep_new (q);

#define EP_MAP_CONVERT_BYTES(IDX)                                                                                       \
	do {                                                                                                                                        \
		bn_read_bin (k, uniform_bytes + IDX * len_per_elm, len_per_elm);         \
		fp_prime_conv (t, k);                                                                                            \
	} while (0)

#define EP_MAP_APPLY_MAP(PT)                                                                                            \
	do {                                                                                                                                        \
		/* check sign of t */                                                                                           \
		neg = fp_is_even (t);                                                                                            \
		/* convert */                                                                                                           \
		map_fn (PT, t);                                                                                                          \
		/* compare sign of y and sign of t; fix if necessary */                         \
		neg = neg != fp_is_even (PT->y);                                                                         \
		fp_neg (t, PT->y);                                                                                                       \
		dv_copy_cond (PT->y, t, RLC_FP_DIGS, neg);                                                       \
	} while (0)

		/* first map invocation */
		EP_MAP_CONVERT_BYTES (0);
		EP_MAP_APPLY_MAP (p);
		TMPL_MAP_CALL_ISOMAP (ep, p);

		/* second map invocation */
		EP_MAP_CONVERT_BYTES (1);
		EP_MAP_APPLY_MAP (q);
		TMPL_MAP_CALL_ISOMAP (ep, q);

		/* XXX(rsw) could add p and q and then apply isomap,
		 * but need ep_add to support addition on isogeny curves */

#undef EP_MAP_CONVERT_BYTES
#undef EP_MAP_APPLY_MAP

		/* sum the result */
		ep_add (p, p, q);
		ep_norm (p, p);
		ep_mul_cof (p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW (ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free (k);
		fp_free (t);
		ep_free (q);
	}
}


//
// END Excerpt from relic's src/ep/relic_ep_map.c
//

int
create_generator_next (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	ep_t                generator,
	const uint8_t      *api_id,
	uint32_t            api_id_len
	)
{
	uint8_t  dst_buf[256];
	uint8_t  rand_buf[128];
	uint64_t i_be = UINT64_H2BE (*((uint64_t*) (state + 48)));
	union bbs_hash_context hash_ctx;
	int      res  = BBS_ERROR;

	if (api_id_len > 255 - 19)
	{
		goto cleanup;
	}

	// check that count (i.e. *((uint64_t*) state + 48) < 2**64
	if (0xffffffffffffffff == *((uint64_t*) (state + 48)))
	{
		goto cleanup;
	}

	*((uint64_t*) (state + 48)) += 1LL;

	for (int i = 0; i < api_id_len; i++)
		dst_buf[i] = api_id[i];
	for (int i = 0; i < 19; i++)
		dst_buf[i + api_id_len] = "SIG_GENERATOR_SEED_"[i];

	if (BBS_OK != cipher_suite->expand_message_init (&hash_ctx))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_update (&hash_ctx, state, 48))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_update (&hash_ctx,
					     (uint8_t*) &i_be,
					     8))
	{
		goto cleanup;
	}

	if (BBS_OK != cipher_suite->expand_message_finalize_48B (&hash_ctx,
						   state,
						   dst_buf,
						   api_id_len + 19))
	{
		goto cleanup;
	}

	for (int i = 0; i < 18; i++)
		dst_buf[i + api_id_len] = "SIG_GENERATOR_DST_"[i];

	if (BBS_OK != cipher_suite->expand_message_dyn (rand_buf,
							128,
							state,
							48,
							dst_buf,
							cipher_suite->api_id_len + 18))
	{
		goto cleanup;
	}

	RLC_TRY {
		ep_map_from_field (generator, rand_buf, 128, ep_map_sswu);
	}
	RLC_CATCH_ANY {
		goto cleanup;
	}

	res = BBS_OK;
cleanup:
	return res;
}


// Notes on hash_to_curve for g1:
//
// hash_to_curve(msg): (Includes DST for hash_to_field)
// 1. u = hash_to_field(msg, 2)
// 2. Q0 = map_to_curve(u[0])
// 3. Q1 = map_to_curve(u[1])
// 4. R = Q0 + Q1              # Point addition
// 5. P = clear_cofactor(R)
// 6. return P
//
// hash_to_field(msg,count): (Requires a DST)
// 1. len_in_bytes = count * m * L
// 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
// 3. for i in (0, ..., count - 1):
// 4.   for j in (0, ..., m - 1):
// 5.     elm_offset = L * (j + i * m)
// 6.     tv = substr(uniform_bytes, elm_offset, L)
// 7.     e_j = OS2IP(tv) mod p
// 8.   u_i = (e_0, ..., e_(m - 1))
// 9. return (u_0, ..., u_(count - 1))
//
// m = 1
// L = 64
//
// clear_cofactor(P) := h_eff * P
//
// h_eff = 0xd201000000010001 (implemented by relic?)
//
// map_to_curve(u):
// 1. (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E'
// 2.   (x, y) = iso_map(x', y')               # (x, y) is on E
// 3. return (x, y)
