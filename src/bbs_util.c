#include "bbs.h"
#include "bbs_util.h"

#include <assert.h>

inline void
bn_write_bbs (
	uint8_t     bin[BBS_SCALAR_LEN],
	const blst_scalar  *n
	)
{
	blst_bendian_from_scalar(bin, n);
}


// Leaks success status via timing
inline int
bn_read_bbs (
	blst_scalar           *n,
	const uint8_t  bin[BBS_SCALAR_LEN]
	)
{
	blst_scalar_from_bendian(n, bin);
	return blst_sk_check(n) ? BBS_OK : BBS_ERROR; // Always checked
}


void
ep_write_bbs (
	uint8_t     bin[BBS_G1_ELEM_LEN],
	const blst_p1  *p
	)
{
	// NOTE: Rare error condition
	// if(blst_p1_is_inf(p)) ERROR
	blst_p1_compress(bin, p);
}


int
ep_read_bbs (
	blst_p1           *p,
	const uint8_t  bin[BBS_G1_ELEM_LEN]
	)
{
	blst_p1_affine pa;
	if(BLST_SUCCESS != blst_p1_uncompress(&pa, bin)) return BBS_ERROR;
	blst_p1_from_affine(p, &pa);
	if(!blst_p1_in_g1(p)) return BBS_ERROR;
	// Reject the neutral element here, so we never have to deal with it
	return blst_p1_is_inf(p) ? BBS_ERROR : BBS_OK;
}


void
ep2_write_bbs (
	uint8_t      bin[BBS_G2_ELEM_LEN],
	const blst_p2  *p
	)
{
	// NOTE: Rare error condition
	// if(blst_p2_is_inf(p)) ERROR
	blst_p2_compress(bin, p);
}

int
ep2_read_bbs (
	blst_p2          *p,
	const uint8_t  bin[BBS_G2_ELEM_LEN]
	)
{
	blst_p2_affine pa;
	if(BLST_SUCCESS != blst_p2_uncompress(&pa, bin)) return BBS_ERROR;
	blst_p2_from_affine(p, &pa);
	if(!blst_p2_in_g2(p)) return BBS_ERROR;
	// Reject the neutral element here, so we never have to deal with it
	return blst_p2_is_inf(p) ? BBS_ERROR : BBS_OK;
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
	blst_scalar                *out,
	const uint8_t      *dst,
	uint8_t             dst_len
	)
{
	uint8_t buffer[48];

	cipher_suite->expand_message_finalize (ctx, buffer, 48, dst, dst_len);
	blst_scalar_from_be_bytes(out, buffer, 48);
}


void
hash_to_scalar (
	bbs_cipher_suite_t *cipher_suite,
	blst_scalar        *out,
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
	uint64_t num_messages_be = htobe64 (num_messages);

	hash_to_scalar_init (cipher_suite, ctx);
	hash_to_scalar_update (cipher_suite, ctx, pk, BBS_PK_LEN);
	hash_to_scalar_update (cipher_suite, ctx, (uint8_t*) &num_messages_be, 8);
}


void
calculate_domain_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const blst_p1          *generator
	)
{
	uint8_t buffer[BBS_G1_ELEM_LEN];

	ep_write_bbs (buffer, generator);
	hash_to_scalar_update (cipher_suite, ctx, buffer, BBS_G1_ELEM_LEN);
}


void
calculate_domain_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	blst_scalar               *out,
	const uint8_t      *header,
	uint64_t            header_len
	)
{
	const uint8_t      *api_id = (uint8_t*) cipher_suite->api_id;
	uint8_t             api_id_len = cipher_suite->api_id_len;
	uint8_t  domain_dst[api_id_len + 4];
	uint64_t header_len_be = htobe64 (header_len);

	for (uint8_t i = 0; i < api_id_len; i++)
		domain_dst[i] = api_id[i];
	for (uint8_t i = 0; i < 4; i++)
		domain_dst[i + api_id_len] = (uint8_t)"H2S_"[i];

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
		buffer[i + api_id_len] = (uint8_t)"SIG_GENERATOR_SEED_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, api_id, api_id_len);
	cipher_suite->expand_message_update (&hash_ctx, (uint8_t*) "MESSAGE_GENERATOR_SEED", 22);
	cipher_suite->expand_message_finalize(&hash_ctx, state, 48, buffer, api_id_len + 19);
	*((uint64_t*) (state + 48)) = (uint64_t)1;
}


void
create_generator_next (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	blst_p1               *generator
	)
{
	const uint8_t      *api_id = (uint8_t*)cipher_suite->api_id;
	uint32_t            api_id_len = cipher_suite->api_id_len;
	uint8_t  dst_buf[api_id_len + 19];
	uint8_t  rand_buf[128];
	uint64_t i_be = htobe64 (*((uint64_t*) (state + 48)));
	union bbs_hash_context hash_ctx;
	blst_fp u,v;

	// check that count (i.e. *((uint64_t*) state + 48) < 2**64
	if ((uint64_t)0xffffffffffffffff == *((uint64_t*) (state + 48)))
	{
		assert(0);
	}

	*((uint64_t*) (state + 48)) += 1LL;

	for (uint32_t i = 0; i < api_id_len; i++)
		dst_buf[i] = api_id[i];
	for (uint32_t i = 0; i < 19; i++)
		dst_buf[i + api_id_len] = (uint8_t)"SIG_GENERATOR_SEED_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, state, 48);
	cipher_suite->expand_message_update (&hash_ctx, (uint8_t*) &i_be, 8);
	cipher_suite->expand_message_finalize (&hash_ctx, state, 48, dst_buf, api_id_len + 19);

	for (uint32_t i = 0; i < 18; i++)
		dst_buf[i + api_id_len] = (uint8_t)"SIG_GENERATOR_DST_"[i];

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, state, 48);
	cipher_suite->expand_message_finalize (&hash_ctx, rand_buf, 128, dst_buf, api_id_len + 18);

	blst_fp_from_be_bytes(&u, rand_buf,    64);
	blst_fp_from_be_bytes(&v, rand_buf+64, 64);
	blst_map_to_g1(generator, &u, &v);
}

