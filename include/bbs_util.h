#ifndef BBS_UTIL_H
#define BBS_UTIL_H

#include "bbs.h"

#include <sha.h>
#include "KeccakHash.h"

#undef ALIGN
#include <relic.h>

// This header specifies useful functions for several utility algorithms.
// Use these if you want to hack on BBS signatures and want to stay close to the
// RFC draft.

#define LEN(m)          (sizeof(m) / sizeof(m[0]))
#define DEBUG(p, a, l)  do { puts (p); for (int xx = 0; xx<l; xx++) printf ("%02x ", a[xx]); \
			     puts (""); } while (0);

#define BBS_SCALAR_LEN  32
#define BBS_G1_ELEM_LEN 48
#define BBS_G2_ELEM_LEN 96

// Serialization
// These functions should be called in a RLC_TRY block
void bn_write_bbs (
	uint8_t     bin[BBS_SCALAR_LEN],
	const bn_t  n
	);

void ep_write_bbs (
	uint8_t     bin[BBS_G1_ELEM_LEN],
	const ep_t  p
	);

void ep2_write_bbs (
	uint8_t      bin[BBS_G2_ELEM_LEN],
	const ep2_t  p
	);

// Deserialization
// These functions should be called in a RLC_TRY block
void bn_read_bbs (
	bn_t           n,
	const uint8_t  bin[BBS_SCALAR_LEN]
	);

void ep_read_bbs (
	ep_t           p,
	const uint8_t  bin[BBS_G1_ELEM_LEN]
	);

void ep2_read_bbs (
	ep2_t          p,
	const uint8_t  bin[BBS_G2_ELEM_LEN]
	);

// The following functions are provided as an incremental and as a one-shot API.
// The varargs for the one-shot API consist of several of the non context
// arguments of the corresponding update function, in order, terminated by a
// NULL value.
// E.g. if update takes inputs (ctx, a, b), then varargs for the one-shot API
// are (a1, b1, a2, b2, ..., an, bn, 0).
// Array types (e.g. ep_t) are given by reference to the one-shot API


// Implementation of expand_message with expand_len = 48
// relic implements this as md_xmd, but here we built it with an incremental API
// or varargs for the message
int expand_message_init (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx
	);

int bbs_sha256_expand_message_init (
	void *ctx
	);

int bbs_shake256_expand_message_init (
	void *ctx
	);

int expand_message_update (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	const uint8_t      *msg,
	uint32_t            msg_len
	);

int bbs_sha256_expand_message_update (
	void          *ctx,
	const uint8_t *msg,
	uint32_t       msg_len
	);

int bbs_shake256_expand_message_update (
	void          *ctx,
	const uint8_t *msg,
	uint32_t       msg_len
	);

int expand_message_finalize_48B (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	uint8_t             out[48],
	const uint8_t      *dst,
	uint8_t             dst_len
	);

int bbs_sha256_expand_message_finalize_48B (
	void          *ctx,
	uint8_t        out[48],
	const uint8_t *dst,
	uint8_t        dst_len
	);

int bbs_shake256_expand_message_finalize_48B (
	void          *ctx,
	uint8_t        out[48],
	const uint8_t *dst,
	uint8_t        dst_len
	);

int bbs_shake256_expand_message_finalize_dyn (
	void          *ctx,
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *dst,
	uint8_t        dst_len
	);

/// @brief Expand a message to a dynamically sized output
/// @return BBS_OK if the message was expanded successfully, BBS_ERROR otherwise
int expand_message_dyn (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	uint8_t            *out,
	uint32_t            out_len,
	const uint8_t      *msg,
	uint32_t            msg_len,
	const uint8_t      *dst,
	uint8_t             dst_len
	);

/// @brief Expand a message to a dynamically sized output with sha256 hashing
/// @return BBS_OK if the message was expanded successfully, BBS_ERROR otherwise
int bbs_sha256_expand_message_dyn (
	void          *ctx,
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *msg,
	uint32_t       msg_len,
	const uint8_t *dst,
	uint8_t        dst_len
	);

/// @brief Expand a message to a 128 byte output with shake256 hashing
/// @return BBS_OK if the message was expanded successfully, BBS_ERROR otherwise
int bbs_shake256_expand_message_dyn (
	void          *ctx,
	uint8_t       *out,
	uint32_t       out_len,
	const uint8_t *msg,
	uint32_t       msg_len,
	const uint8_t *dst,
	uint8_t        dst_len
	);

/// Expand a message to a 48 byte output
int expand_message_48B (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             out[48],
	const uint8_t      *dst,
	uint8_t             dst_len,
	...
	);

// Hash to Scalar
int hash_to_scalar_init (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx
	);

int hash_to_scalar_update (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	const uint8_t      *msg,
	uint32_t            msg_len
	);

int hash_to_scalar_finalize (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	bn_t                out,
	const uint8_t      *dst,
	uint8_t             dst_len
	);

int hash_to_scalar (
	bbs_cipher_suite_t *cipher_suite,
	bn_t                out,
	const uint8_t      *dst,
	uint8_t             dst_len,
	...
	);

// you need to call update exactly num_messages + 1 times.
int calculate_domain_init (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages
	);

int calculate_domain_update (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	const ep_t          generator
	);

int calculate_domain_finalize (
	bbs_cipher_suite_t *cipher_suite,
	void               *ctx,
	bn_t                out,
	const uint8_t      *header,
	uint64_t            header_len,
	const uint8_t      *api_id,
	uint8_t             api_id_len
	);

int calculate_domain (
	bbs_cipher_suite_t *cipher_suite,
	bn_t                out,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages,
	const uint8_t      *header,
	uint64_t            header_len,
	const uint8_t      *api_id,
	uint8_t             api_id_len,
	...
	);

/**
 * @brief Create a generator for the BBS+ signature scheme
 * @param state The state of the generator, includes counter `i` as last 8 bytes
 * @param api_id The API ID
 * @param api_id_len The length of the API ID
 * @return BBS_OK if the generator was created successfully, BBS_ERROR otherwise
 *
 * @note Always supply the same api_id to next as you did to init
*/
int create_generator_init (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	const uint8_t      *api_id,
	uint8_t             api_id_len
	);

/**
 * @brief Create the next generator for the BBS+ signature scheme
 * @param state The state of the generator, as set by init / previous call
 * @param generator The generator to be created
 * @param api_id The API ID
 * @param api_id_len The length of the API ID
 * @return BBS_OK if the generator was created successfully, BBS_ERROR otherwise
 *
 * @note Always supply the same api_id to next as you did to init
 */
int create_generator_next (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	ep_t                generator,
	const uint8_t      *api_id,
	uint8_t             api_id_len
	);

// You can control the randomness for bbs_proof_gen by supplying a prf.
// This is also how the fixture tests work.
// Be warned that the function becomes horribly insecure if the values are not
// pseudorandom. Returned values should be unique and independent for each (input_type, input)
// tuple. In terms of the spec, the indices from calculate_random_scalars map to
// input_types and inputs as follows:
// For per-message scalars input_type is 0 and input i indicates the i-th such
// message scalar, other scalars have input 0 and input_type i indicates the
// i-th such scalar. This is because there may be up to 2^64 messages, bringing
// the total possible message count slightly above 2^64.
typedef int (bbs_bn_prf)(bn_t      out,
			 uint8_t   input_type,
			 uint64_t  input,
			 void     *cookie
			 );

// Defined in bbs.c, but included here to hide it from bbs.h importers
int bbs_proof_gen_det (
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
	);

// Big endian conversion
#define UINT64_H2BE(x) (((x & 0xff00000000000000LL) >> 56) | \
			((x & 0x00ff000000000000LL) >> 40) | \
			((x & 0x0000ff0000000000LL) >> 24) | \
			((x & 0x000000ff00000000LL) >>  8) | \
			((x & 0x00000000ff000000LL) <<  8) | \
			((x & 0x0000000000ff0000LL) << 24) | \
			((x & 0x000000000000ff00LL) << 40) | \
			((x & 0x00000000000000ffLL) << 56))

#endif /*BBS_UTIL_H*/
