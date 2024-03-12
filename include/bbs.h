#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdarg.h>

#define BBS_CIPHER_SUITE_BLS12_381_SHA_256 1
#define BBS_CIPHER_SUITE_BLS12_381_SHAKE_256 2

// Octet string lengths
#define BBS_SK_LEN 32
#define BBS_PK_LEN 96
#define BBS_SIG_LEN 80
#define BBS_PROOF_BASE_LEN 272
#define BBS_PROOF_UD_ELEM_LEN 32
#define BBS_PROOF_LEN(num_undisclosed) (BBS_PROOF_BASE_LEN + num_undisclosed * BBS_PROOF_UD_ELEM_LEN)

// Return values
#define BBS_OK 0
#define BBS_ERROR 1

// Typedefs
typedef uint8_t bbs_secret_key[BBS_SK_LEN];
typedef uint8_t bbs_public_key[BBS_PK_LEN];
typedef uint8_t bbs_signature[BBS_SIG_LEN];

// Key Generation
int bbs_keygen_full(
		bbs_secret_key sk,
		bbs_public_key pk
	);

int bbs_keygen(
		bbs_secret_key        sk,
		const uint8_t        *key_material,
		uint16_t              key_material_len,
		const uint8_t        *key_info,
		uint16_t              key_info_len,
		const uint8_t        *key_dst,
		uint8_t               key_dst_len
	);

int bbs_sk_to_pk(
		const bbs_secret_key sk,
		bbs_public_key       pk
	);

// Signing
int bbs_sign(
		const bbs_secret_key  sk,
		const bbs_public_key  pk,
		bbs_signature         signature,
		const uint8_t        *header,
		uint64_t              header_len,
		uint64_t              num_messages,
		...
	);

// Verification
int bbs_verify(
		const bbs_public_key  pk,
		const bbs_signature   signature,
		const uint8_t        *header,
		uint64_t        header_len,
		uint64_t        num_messages,
		...
	);

// Proof Generation
int bbs_proof_gen (
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
	);

// Proof Verification
int bbs_proof_verify (
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
	);

#endif
