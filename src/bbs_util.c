#include "bbs.h"
#include "bbs_util.h"

#include <assert.h>

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

inline void
hash_to_scalar_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx
	)
{
	cipher_suite->expand_message_init (ctx);
}


inline void
hash_to_scalar_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t      *msg,
	uint32_t            msg_len
	)
{
	cipher_suite->expand_message_update (ctx, msg, msg_len);
}


inline void
hash_to_scalar_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	bn_t                out,
	const uint8_t      *dst,
	uint8_t             dst_len
	)
{
	uint8_t buffer[48];

	cipher_suite->expand_message_finalize (ctx, buffer, 48, dst, dst_len);

	RLC_TRY {
		bn_read_bin (out, buffer, 48);
		bn_mod (out, out, &(core_get ()->ep_r));
	}
	RLC_CATCH_ANY {
		// Should not happen
		assert(0);
		;
	}
}


void
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

	va_start (ap, num_messages);
	hash_to_scalar_init (cipher_suite, &hash_ctx);
	for(uint64_t i=0; i< num_messages; i++)
	{
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		hash_to_scalar_update (cipher_suite, &hash_ctx, msg, msg_len);
	}
	hash_to_scalar_finalize (cipher_suite, &hash_ctx, out, dst, dst_len);
	va_end (ap);
}


void
calculate_domain_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages
	)
{
	uint64_t num_messages_be = UINT64_H2BE (num_messages);

	hash_to_scalar_init (cipher_suite, ctx);
	hash_to_scalar_update (cipher_suite, ctx, pk, BBS_PK_LEN);
	hash_to_scalar_update (cipher_suite, ctx, (uint8_t*) &num_messages_be, 8);
}


void
calculate_domain_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const ep_t          generator
	)
{
	uint8_t buffer[BBS_G1_ELEM_LEN];

	RLC_TRY {
		ep_write_bbs (buffer, generator);
	}
	RLC_CATCH_ANY {
		// If we ever end up here, one of the generators is the identity
		// element. This means that the public key cannot be safely used
		// and you should generate a new one.
		// This is unlikely to ever happen, anywhere.
		assert(0);
		;
	}

	hash_to_scalar_update (cipher_suite, ctx, buffer, BBS_G1_ELEM_LEN);
}


void
calculate_domain_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	bn_t                out,
	const uint8_t      *header,
	uint64_t            header_len
	)
{
	const uint8_t      *api_id = (uint8_t*) cipher_suite->api_id;
	uint8_t             api_id_len = cipher_suite->api_id_len;
	uint8_t  domain_dst[api_id_len + 4];
	uint64_t header_len_be = UINT64_H2BE (header_len);

	for (int i = 0; i < api_id_len; i++)
		domain_dst[i] = api_id[i];
	for (int i = 0; i < 4; i++)
		domain_dst[i + api_id_len] = "H2S_"[i];

	hash_to_scalar_update (cipher_suite, ctx, api_id, api_id_len);
	hash_to_scalar_update (cipher_suite, ctx, (uint8_t*) &header_len_be, 8);
	hash_to_scalar_update (cipher_suite, ctx, header, header_len);
	hash_to_scalar_finalize (cipher_suite, ctx, out, domain_dst, api_id_len + 4);
}

void
create_generator_init (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8]
	)
{
	const uint8_t      *api_id = (uint8_t*)cipher_suite->api_id;
	uint32_t            api_id_len = cipher_suite->api_id_len;
	uint8_t buffer[api_id_len + 19];
	union bbs_hash_context hash_ctx;

	for (uint32_t i = 0; i < api_id_len; i++)
		buffer[i] = api_id[i];
	for (uint32_t i = 0; i < 19; i++)
		buffer[i + api_id_len] = "SIG_GENERATOR_SEED_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, api_id, api_id_len);
	cipher_suite->expand_message_update (&hash_ctx, (uint8_t*) "MESSAGE_GENERATOR_SEED", 22);
	cipher_suite->expand_message_finalize(&hash_ctx, state, 48, buffer, api_id_len + 19);
	*((uint64_t*) (state + 48)) = 1LL;
}

void
create_generator_next (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	ep_t                generator
	)
{
	const uint8_t      *api_id = (uint8_t*)cipher_suite->api_id;
	uint32_t            api_id_len = cipher_suite->api_id_len;
	uint8_t  dst_buf[api_id_len + 19];
	uint8_t  rand_buf[128];
	uint64_t i_be = UINT64_H2BE (*((uint64_t*) (state + 48)));
	union bbs_hash_context hash_ctx;

	// check that count (i.e. *((uint64_t*) state + 48) < 2**64
	if (0xffffffffffffffff == *((uint64_t*) (state + 48)))
	{
		assert(0);
	}

	*((uint64_t*) (state + 48)) += 1LL;

	for (uint32_t i = 0; i < api_id_len; i++)
		dst_buf[i] = api_id[i];
	for (uint32_t i = 0; i < 19; i++)
		dst_buf[i + api_id_len] = "SIG_GENERATOR_SEED_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, state, 48);
	cipher_suite->expand_message_update (&hash_ctx, (uint8_t*) &i_be, 8);
	cipher_suite->expand_message_finalize (&hash_ctx, state, 48, dst_buf, api_id_len + 19);

	for (int i = 0; i < 18; i++)
		dst_buf[i + api_id_len] = "SIG_GENERATOR_DST_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, state, 48);
	cipher_suite->expand_message_finalize (&hash_ctx, rand_buf, 128, dst_buf, api_id_len + 18);

	RLC_TRY {
		ep_map_rnd(generator, rand_buf, 128);
	}
	RLC_CATCH_ANY {
		// Should not happen
		assert(0);
	}
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
