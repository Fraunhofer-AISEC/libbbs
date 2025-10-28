#ifndef BBS_UTIL_H
#define BBS_UTIL_H

#include "bbs.h"

#include <assert.h>
#include "sha256.h"
#include "shake256.h"
#include <blst.h>

#undef ALIGN

// This header specifies useful functions for several utility algorithms.
// Use these ifyou want to hack on BBS signatures and want to stay close to the
// RFC draft.

#define LEN(m)          (sizeof(m) / sizeof(m[0]))
#define DEBUG(p, a, l)  do { puts (p); for (int xx = 0; xx<l; xx++) printf ("%02x ", a[xx]); \
			     puts (""); } while (0);
#define RLC_ASSERT(expr) RLC_TRY { expr ; } RLC_CATCH_ANY { assert(0); }

#define BBS_SCALAR_LEN  32
#define BBS_G1_ELEM_LEN 48
#define BBS_G2_ELEM_LEN 96

// Enough memory for any defined hash function
union bbs_hash_context {
	sha256_t sha256;
	shake256_t shake256;
};

/// @brief BBS cipher suite interface
/// @note Strategy pattern to dispatch to the correct hash function for the
/// cipher suite, keeping the same overall control flow for the caller.
struct bbs_cipher_suite
{
	uint8_t p1[BBS_G1_ELEM_LEN];

	// Incremental expand_message API
	void (*expand_message_init) (
		union bbs_hash_context *ctx
		);
	void (*expand_message_update) (
		union bbs_hash_context *ctx,
		const uint8_t *msg,
		size_t       msg_len
		);
	void (*expand_message_finalize) (
		union bbs_hash_context *ctx,
		uint8_t       *out,
		uint16_t       out_len, // WARNING: only supports up to 255*256
		const uint8_t *dst,
		size_t        dst_len
		);

	/// DST
	uint8_t *cipher_suite_id;
	uint8_t  cipher_suite_id_len;
	uint8_t *default_key_dst;
	uint8_t  default_key_dst_len;
	uint8_t *api_id;
	uint8_t  api_id_len;
	uint8_t *signature_dst;
	uint8_t  signature_dst_len;
	uint8_t *challenge_dst;
	uint8_t  challenge_dst_len;
	uint8_t *map_dst;
	uint8_t  map_dst_len;
};

// Serialization
void bn_write_bbs (
	uint8_t     bin[BBS_SCALAR_LEN],
	const blst_scalar  *n
	);

void ep_write_bbs (
	uint8_t     bin[BBS_G1_ELEM_LEN],
	const blst_p1  *p
	);

void ep2_write_bbs (
	uint8_t      bin[BBS_G2_ELEM_LEN],
	const blst_p2  *p
	);

// Deserialization
int bn_read_bbs (
	blst_scalar           *n,
	const uint8_t  bin[BBS_SCALAR_LEN]
	);

int ep_read_bbs (
	blst_p1           *p,
	const uint8_t  bin[BBS_G1_ELEM_LEN]
	);

int ep2_read_bbs (
	blst_p2          *p,
	const uint8_t  bin[BBS_G2_ELEM_LEN]
	);

// The following functions are provided as an incremental and as a one-shot API.
// The varargs for the one-shot API consist of several of the non context
// arguments of the corresponding update function, in order, terminated by a
// NULL value.
// E.g. if update takes inputs (ctx, a, b), then varargs for the one-shot API
// are (a1, b1, a2, b2, ..., an, bn, 0).
// Array types (e.g. ep_t) are given by reference to the one-shot API


// Hash to Scalar
void hash_to_scalar_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx
	);

void hash_to_scalar_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t      *msg,
	uint32_t            msg_len
	);

void hash_to_scalar_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	blst_scalar                *out,
	const uint8_t      *dst,
	uint8_t             dst_len
	);

void hash_to_scalar (
	bbs_cipher_suite_t *cipher_suite,
	blst_scalar                *out,
	const uint8_t      *dst,
	uint8_t             dst_len,
	uint64_t            num_messages,
	...
	);

// you need to call update exactly num_messages + 1 times.
void calculate_domain_init (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const uint8_t       pk[BBS_PK_LEN],
	uint64_t            num_messages
	);

void calculate_domain_update (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	const blst_p1          *generator
	);

void calculate_domain_finalize (
	bbs_cipher_suite_t *cipher_suite,
	union bbs_hash_context *ctx,
	blst_scalar                *out,
	const uint8_t      *header,
	uint64_t            header_len
	);


/**
 * @brief Create a generator for the BBS+ signature scheme
 * @param state The state of the generator, includes counter `i` as last 8 bytes
 * @return BBS_OK if the generator was created successfully, BBS_ERROR otherwise
 *
 * @note Always supply the same api_id to next as you did to init
*/
void create_generator_init (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8]
	);

/**
 * @brief Create the next generator for the BBS+ signature scheme
 * @param state The state of the generator, as set by init / previous call
 * @param generator The generator to be created
 * @return BBS_OK if the generator was created successfully, BBS_ERROR otherwise
 *
 * @note Always supply the same api_id to next as you did to init
 */
void create_generator_next (
	bbs_cipher_suite_t *cipher_suite,
	uint8_t             state[48 + 8],
	blst_p1                *generator
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
typedef void (bbs_bn_prf)(bbs_cipher_suite_t *cipher_suite,
			 blst_scalar                *out,
			 uint8_t             input_type,
			 uint64_t            input,
			 void               *cookie
			 );

// Big endian conversion
#define UINT64_H2BE(x) (((x & (uint64_t)0xff00000000000000LL) >> 56) | \
			((x & (uint64_t)0x00ff000000000000LL) >> 40) | \
			((x & (uint64_t)0x0000ff0000000000LL) >> 24) | \
			((x & (uint64_t)0x000000ff00000000LL) >>  8) | \
			((x & (uint64_t)0x00000000ff000000LL) <<  8) | \
			((x & (uint64_t)0x0000000000ff0000LL) << 24) | \
			((x & (uint64_t)0x000000000000ff00LL) << 40) | \
			((x & (uint64_t)0x00000000000000ffLL) << 56))

#endif /*BBS_UTIL_H*/
