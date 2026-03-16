// SPDX-License-Identifier: Apache-2.0
// (C) 2025 Fraunhofer AISEC

/**
 * @file bbs.h
 * @author Thomas Bellebaum
 * @author Sebastian Schmiedmayer
 * @author Martin Schanzenbach
 * @date 2 Jun 2025
 * @brief The main libbbs header file.
 *
 * Using the BBS signature scheme requires several non-standard considerations,
 * such as keeping the signature secret. For an introduction, see bbs(7), as
 * well as the man-pages for each function.
 *
 * For the latest revision, up to date man-pages are also available as HTML at
 * https://fraunhofer-aisec.github.io/libbbs/
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
#define BBS_PROOF_LEN(num_undisclosed) (272 + (num_undisclosed) * 32)

/* Return values. Other error codes may be defined in the future */
#define BBS_OK    0
#define BBS_ERROR 1

/* Types */
typedef uint8_t                                 bbs_secret_key[BBS_SK_LEN];
typedef uint8_t                                 bbs_public_key[BBS_PK_LEN];
typedef uint8_t                                 bbs_signature[BBS_SIG_LEN];
typedef struct { const void *loc; size_t len; } bbs_message;
typedef struct {       void *loc; size_t len; } bbs_out_message;
typedef struct _bbs_ciphersuite                 bbs_ciphersuite;

/* Key Generation */
int bbs_keygen_full (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key         sk,
	bbs_public_key         pk
	);
int bbs_keygen (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key         sk,
	bbs_message            key_material,
	bbs_message            key_info,
	bbs_message            key_dst
	);
int bbs_sk_to_pk (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key   sk,
	bbs_public_key         pk
	);

/* Signature Creation / Verification */
int bbs_sign (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key   sk,
	const bbs_public_key   pk,
	bbs_signature          signature,
	bbs_message            header,
	const bbs_message     *messages,
	size_t                 n
	);
int bbs_verify (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	bbs_message            header,
	const bbs_message     *messages,
	size_t                 n
	);

/* Proof Creation / Verification */
int bbs_proof_gen (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const bbs_signature    signature,
	bbs_out_message        proof,
	bbs_message            header,
	bbs_message            presentation_header,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	const bbs_message     *messages,
	size_t                 n
	);
int bbs_proof_verify (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	bbs_message            proof,
	bbs_message            header,
	bbs_message            presentation_header,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	const bbs_message     *messages,
	size_t                 n
	);

/* Cipher Suites */
extern const bbs_ciphersuite *const bbs_sha256_ciphersuite;
extern const bbs_ciphersuite *const bbs_shake256_ciphersuite;

/* Helpful Macros to construct messages */
#define BBS_MSG(loc, len) ((bbs_message){ loc, len })
#define BBS_CMSG(var)          BBS_MSG(&var, sizeof(var))      // Compile-time size
#define BBS_SMSG(string)       BBS_MSG(string, strlen(string)) // C String, requires <string.h>
#define BBS_LSMSG(str_literal) BBS_MSG("" str_literal, sizeof(str_literal) - 1) // String literal
#define BBS_UNDISCLOSED_MSG    BBS_MSG((void*)0, 0)
#define BBS_OUT_MSG(loc, len) ((bbs_out_message){ loc, len })
#define BBS_OUT_CMSG(var) BBS_OUT_MSG(&var, sizeof(var))

/* Variadic variants of the above API */
#define __BBS_MSGVEC(...) ((bbs_message[]){__VA_ARGS__})
#define __BBS_MSGVEC_LEN(...) (sizeof(__BBS_MSGVEC(__VA_ARGS__)) / sizeof(bbs_message))
#define bbs_sign_v(suite, sk, pk, sig, header, ...) \
	bbs_sign(suite, sk, pk, sig, header, __BBS_MSGVEC(__VA_ARGS__), __BBS_MSGVEC_LEN(__VA_ARGS__))
#define bbs_verify_v(suite, pk, sig, header, ...) \
	bbs_verify(suite, pk, sig, header, __BBS_MSGVEC(__VA_ARGS__), __BBS_MSGVEC_LEN(__VA_ARGS__))
#define bbs_proof_gen_v(suite, pk, sig, proof, header, ph, di, dilen, ...) \
	bbs_proof_gen(suite, pk, sig, proof, header, ph, di, dilen, \
			__BBS_MSGVEC(__VA_ARGS__), __BBS_MSGVEC_LEN(__VA_ARGS__))
#define bbs_proof_verify_v(suite, pk, proof, header, ph, di, dilen, ...) \
	bbs_proof_verify(suite, pk, proof, header, ph, di, dilen, \
			__BBS_MSGVEC(__VA_ARGS__), __BBS_MSGVEC_LEN(__VA_ARGS__))

#define bbs_sha256_keygen_full(...)    bbs_keygen_full   (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_keygen(...)         bbs_keygen        (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sk_to_pk(...)       bbs_sk_to_pk      (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sign_v(...)         bbs_sign_v        (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_verify_v(...)       bbs_verify_v      (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_gen_v(...)    bbs_proof_gen_v   (bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_verify_v(...) bbs_proof_verify_v(bbs_sha256_cipher_suite,__VA_ARGS__)

#define bbs_shake256_keygen_full(...)    bbs_keygen_full   (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_keygen(...)         bbs_keygen        (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sk_to_pk(...)       bbs_sk_to_pk      (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sign_v(...)         bbs_sign_v        (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_verify_v(...)       bbs_verify_v      (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_gen_v(...)    bbs_proof_gen_v   (bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_verify_v(...) bbs_proof_verify_v(bbs_shake256_cipher_suite,__VA_ARGS__)

#endif
