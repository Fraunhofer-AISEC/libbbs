// SPDX-License-Identifier: Apache-2.0
/**
 * (C) 2025 Fraunhofer AISEC
 */

/**
 * @file bbs.h
 * @author Thomas Bellebaum
 * @author Sebastian Schmiedmayer
 * @author Martin Schanzenbach
 * @date 2 Jun 2025
 * @brief The main libbbs header file.
 */

#ifndef BBS_H
#define BBS_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* Length definitions */
#define BBS_SK_LEN                     32
#define BBS_PK_LEN                     96
#define BBS_SIG_LEN                    80
#define BBS_PROOF_BASE_LEN             272
#define BBS_PROOF_UD_ELEM_LEN          32
#define BBS_PROOF_LEN(num_undisclosed) (BBS_PROOF_BASE_LEN + (num_undisclosed) * BBS_PROOF_UD_ELEM_LEN \
					)
/* Return values. Other error codes may be defined in the future */
#define BBS_OK    0
#define BBS_ERROR 1

/* Types */
typedef uint8_t  bbs_secret_key[BBS_SK_LEN];
typedef uint8_t  bbs_public_key[BBS_PK_LEN];
typedef uint8_t  bbs_signature[BBS_SIG_LEN];
/* typedef uint8_t proof[BBS_PROOF_LEN(num_undisclosed)]; */
typedef struct _bbs_ciphersuite bbs_ciphersuite;

/* Key Generation */
int bbs_keygen_full (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key         sk,
	bbs_public_key         pk
	);
int bbs_keygen (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key         sk,
	const void            *key_material,
	size_t                 key_material_len,
	const void            *key_info,
	size_t                 key_info_len,
	const void            *key_dst,
	size_t                 key_dst_len
	);
int bbs_sk_to_pk (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key   sk,
	bbs_public_key         pk
	);

/* Signature Creation / Verification */
int bbs_sign_v (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key   sk,
	const bbs_public_key   pk,
	bbs_signature          signature,
	const void            *header,
	size_t                 header_len,
	size_t                 n,
	...
	);
int bbs_sign (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key   sk,
	const bbs_public_key   pk,
	bbs_signature          signature,
	const void            *header,
	size_t                 header_len,
	size_t                 n,
	const void *const     *messages,
	const size_t          *messages_lens
	);
int bbs_verify_v (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	const void            *header,
	size_t                 header_len,
	size_t                 n,
	...
	);
int bbs_verify (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	const void            *header,
	size_t                 header_len,
	size_t                 n,
	const void *const     *messages,
	const size_t          *messages_lens
	);

/* Proof Creation / Verification */
int bbs_proof_gen_v (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	void                  *proof,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	size_t                 n,
	...
	);
int bbs_proof_gen (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	void                  *proof,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	size_t                 n,
	const void *const     *messages,
	const size_t          *messages_lens
	);
int bbs_proof_verify_v (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const void            *proof,
	size_t                 proof_len,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	size_t                 n,
	...
	);
int bbs_proof_verify (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const void            *proof,
	size_t                 proof_len,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	size_t                 n,
	const void *const     *messages,
	const size_t          *messages_lens
	);

/* Cipher Suites */
extern const bbs_ciphersuite *const bbs_sha256_ciphersuite;
extern const bbs_ciphersuite *const bbs_shake256_ciphersuite;

/* Helpful Macros */
#define bbs_sha256_keygen_full(...)  bbs_keygen_full(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_keygen(...)       bbs_keygen(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sk_to_pk(...)     bbs_sk_to_pk(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sign(...)         bbs_sign(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_verify(...)       bbs_verify(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_gen(...)    bbs_proof_gen(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_verify(...) bbs_proof_verify(bbs_sha256_cipher_suite,__VA_ARGS__)

#define bbs_shake256_keygen_full(...)  bbs_keygen_full(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_keygen(...)       bbs_keygen(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sk_to_pk(...)     bbs_sk_to_pk(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sign(...)         bbs_sign(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_verify(...)       bbs_verify(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_gen(...)    bbs_proof_gen(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_verify(...) bbs_proof_verify(bbs_shake256_cipher_suite,__VA_ARGS__)

#endif
