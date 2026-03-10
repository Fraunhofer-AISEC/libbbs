// SPDX-License-Identifier: Apache-2.0
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
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context *ctx
	)
{
	cipher_suite->expand_message_init (ctx);
}


inline void
hash_to_scalar_update (
	const bbs_ciphersuite  *cipher_suite,
	union bbs_hash_context *ctx,
	bbs_message             msg
	)
{
	cipher_suite->expand_message_update (ctx, msg);
}


inline void
hash_to_scalar_finalize (
	const bbs_ciphersuite  *cipher_suite,
	union bbs_hash_context *ctx,
	blst_scalar            *out,
	bbs_message             dst
	)
{
	uint8_t buffer[48];

	cipher_suite->expand_message_finalize (ctx, BBS_OUTMSG(buffer, sizeof(buffer)), dst);
	blst_scalar_from_be_bytes(out, buffer, sizeof(buffer));
}


void
hash_to_scalar (
	const bbs_ciphersuite *cipher_suite,
	blst_scalar           *out,
	bbs_message            dst,
	uint64_t               num_messages,
	bbs_message           *messages
	)
{
	union bbs_hash_context hash_ctx;

	hash_to_scalar_init (cipher_suite, &hash_ctx);
	for(uint64_t i=0; i < num_messages; i++)
	{
		hash_to_scalar_update (cipher_suite, &hash_ctx, messages[i]);
	}
	hash_to_scalar_finalize (cipher_suite, &hash_ctx, out, dst);
}


void
calculate_domain_init (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages
	)
{
	uint64_t num_messages_be = htobe64 (num_messages);

	hash_to_scalar_init   (cipher_suite, ctx);
	hash_to_scalar_update (cipher_suite, ctx, BBS_MSG(pk, BBS_PK_LEN));
	hash_to_scalar_update (cipher_suite, ctx, BBS_CMSG(num_messages_be));
}


void
calculate_domain_update (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context *ctx,
	const blst_p1          *generator
	)
{
	uint8_t buffer[BBS_G1_ELEM_LEN];

	ep_write_bbs (buffer, generator);
	hash_to_scalar_update (cipher_suite, ctx, BBS_CMSG(buffer));
}


void
calculate_domain_finalize (
	const bbs_ciphersuite  *cipher_suite,
	union bbs_hash_context *ctx,
	blst_scalar            *out,
	bbs_message             header
	)
{
	bbs_message api_id = cipher_suite->api_id;
	uint8_t  domain_dst[api_id.len + 4];
	uint64_t header_len_be = htobe64((uint64_t)header.len);

	bbs_memcpy(domain_dst, api_id.loc, api_id.len);
	bbs_memcpy(domain_dst + api_id.len, "H2S_", 4);

	hash_to_scalar_update (cipher_suite, ctx, api_id);
	hash_to_scalar_update (cipher_suite, ctx, BBS_CMSG(header_len_be));
	hash_to_scalar_update (cipher_suite, ctx, header);
	hash_to_scalar_finalize (cipher_suite, ctx, out, BBS_CMSG(domain_dst));
}

void
create_generator_init (
	const bbs_ciphersuite *cipher_suite,
	uint8_t             state[48 + 8]
	)
{
	bbs_message api_id = cipher_suite->api_id;
	uint8_t buffer[api_id.len + 19];
	union bbs_hash_context hash_ctx;

	bbs_memcpy(buffer, api_id.loc, api_id.len);
	bbs_memcpy(buffer + api_id.len, "SIG_GENERATOR_SEED_", 19);

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, api_id);
	cipher_suite->expand_message_update (&hash_ctx, BBS_LSMSG("MESSAGE_GENERATOR_SEED"));
	cipher_suite->expand_message_finalize(&hash_ctx, BBS_OUTMSG(state, 48), BBS_CMSG(buffer));
	*((uint64_t*) (state + 48)) = (uint64_t)1;
}


void
create_generator_next (
	const bbs_ciphersuite *cipher_suite,
	uint8_t             state[48 + 8],
	blst_p1               *generator
	)
{
	bbs_message api_id = cipher_suite->api_id;
	uint8_t  dst_buf[api_id.len + 19];
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

	bbs_memcpy(dst_buf, api_id.loc, api_id.len);
	bbs_memcpy(dst_buf + api_id.len, "SIG_GENERATOR_SEED_", 19);

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, BBS_MSG(state, 48));
	cipher_suite->expand_message_update (&hash_ctx, BBS_CMSG(i_be));
	cipher_suite->expand_message_finalize (&hash_ctx, BBS_OUTMSG(state, 48), BBS_CMSG(dst_buf));

	bbs_memcpy(dst_buf + api_id.len, "SIG_GENERATOR_DST_", 18);

	cipher_suite->expand_message_init (&hash_ctx);
	cipher_suite->expand_message_update (&hash_ctx, BBS_MSG(state, 48));
	cipher_suite->expand_message_finalize (&hash_ctx,
			BBS_OUTMSG(rand_buf, sizeof(rand_buf)), BBS_MSG(dst_buf, api_id.len + 18));

	blst_fp_from_be_bytes(&u, rand_buf,    64);
	blst_fp_from_be_bytes(&v, rand_buf+64, 64);
	blst_map_to_g1(generator, &u, &v);
}

