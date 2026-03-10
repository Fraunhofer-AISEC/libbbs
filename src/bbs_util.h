// SPDX-License-Identifier: Apache-2.0
#ifndef BBS_UTIL_H
#define BBS_UTIL_H

#include "bbs.h"

#include <assert.h>
#include "sha256.h"
#include "shake256.h"
#include "compat-endian.h"
#include <blst.h>

#undef ALIGN

// This header specifies useful functions for several utility algorithms.
// Use these if you want to hack on BBS signatures and want to stay close to the
// RFC draft.

#define LEN(m)          (sizeof(m) / sizeof(m[0]))
#define DEBUG(p, a, l)  do { puts (p); for (size_t xx = 0; xx<l; xx++) printf ("%02x ", ((uint8_t*)a)[xx]); \
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
struct _bbs_ciphersuite
{
	// A special point to domain separate cipher suites...
	uint8_t p1[BBS_G1_ELEM_LEN];

	// Incremental expand_message API
	void (*expand_message_init)     (union bbs_hash_context *ctx);
	void (*expand_message_update)   (union bbs_hash_context *ctx, bbs_message msg);
	void (*expand_message_finalize) (union bbs_hash_context *ctx, bbs_out_message out, bbs_message dst);

	/// Domain Separation Tags
	bbs_message cipher_suite_id;
	bbs_message default_key_dst;
	bbs_message api_id;
	bbs_message signature_dst;
	bbs_message challenge_dst;
	bbs_message map_dst;
};

// Serialization
void bn_write_bbs  (uint8_t bin[BBS_SCALAR_LEN],  const blst_scalar *n);
void ep_write_bbs  (uint8_t bin[BBS_G1_ELEM_LEN], const blst_p1     *p);
void ep2_write_bbs (uint8_t bin[BBS_G2_ELEM_LEN], const blst_p2     *p);

// Deserialization
int bn_read_bbs  (blst_scalar *n, const uint8_t bin[BBS_SCALAR_LEN]);
int ep_read_bbs  (blst_p1     *p, const uint8_t bin[BBS_G1_ELEM_LEN]);
int ep2_read_bbs (blst_p2     *p, const uint8_t bin[BBS_G2_ELEM_LEN]);

// The following functions are provided as an incremental and as a one-shot API.
// The varargs for the one-shot API consist of several of the non context
// arguments of the corresponding update function, in order, terminated by a
// NULL value.
// E.g. if update takes inputs (ctx, a, b), then varargs for the one-shot API
// are (a1, b1, a2, b2, ..., an, bn, 0).
// Array types (e.g. ep_t) are given by reference to the one-shot API


// Hash to Scalar
void hash_to_scalar_init (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context *ctx
	);

void hash_to_scalar_update (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context   *ctx,
	bbs_message               msg
	);

void hash_to_scalar_finalize (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context   *ctx,
	blst_scalar              *out,
	bbs_message               dst
	);

void hash_to_scalar (
	const bbs_ciphersuite *cipher_suite,
	blst_scalar              *out,
	bbs_message               dst,
	uint64_t                  num_messages,
	bbs_message              *messages
	);

// You need to call update exactly num_messages + 1 times.
void calculate_domain_init (
	const bbs_ciphersuite  *cipher_suite,
	union bbs_hash_context *ctx,
	const bbs_public_key    pk,
	uint64_t                num_messages
	);

void calculate_domain_update (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context *ctx,
	const blst_p1          *generator
	);

void calculate_domain_finalize (
	const bbs_ciphersuite *cipher_suite,
	union bbs_hash_context   *ctx,
	blst_scalar              *out,
	bbs_message               header
	);


/**
 * @brief Create a generator for the BBS+ signature scheme
 * @param state The state of the generator, includes counter `i` as last 8 bytes
 * @return BBS_OK if the generator was created successfully, BBS_ERROR otherwise
 *
 * @note Always supply the same api_id to next as you did to init
*/
void create_generator_init (
	const bbs_ciphersuite *cipher_suite,
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
	const bbs_ciphersuite *cipher_suite,
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
typedef void (bbs_bn_prf)(const bbs_ciphersuite *cipher_suite,
			 blst_scalar               *out,
			 uint8_t                    input_type,
			 uint64_t                   input,
			 void                      *cookie
			 );

int
__bbs_proof_gen_deterministic (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	bbs_out_message        proof,
	bbs_message            header,
	bbs_message            presentation_header,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	const bbs_message     *messages,
	size_t                 n,
	bbs_bn_prf             prf,
	void                  *prf_cookie
	);

#endif /*BBS_UTIL_H*/
