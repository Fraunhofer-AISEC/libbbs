#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdarg.h>

#define BBS_CIPHER_SUITE_BLS12_381_SHA_256   1
#define BBS_CIPHER_SUITE_BLS12_381_SHAKE_256 2

// The above collision stems from the ID. Possible oversight? Should not compromise
// security too much...

// Point for the SHA suite
static uint8_t BBS_SHA256_P1[] = {
	0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
	0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
	0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
	0x4e, 0x28, 0xc9
};
static uint8_t BBS_SHAKE256_P1[] = {
	0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
	0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
	0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
	0x15, 0x07, 0x55
};

/// @brief BBS cipher suite interface
/// @note Strategy pattern to dispatch to the correct hash function for the
/// cipher suite, keeping the same overall control flow for the caller.
typedef struct
{
	void    *hash_ctx;
	void    *dom_ctx;
	void    *ch_ctx;
	uint8_t *p1;
	int (*expand_message_init) (
		void *ctx
		);
	int (*expand_message_update) (
		void          *ctx,
		const uint8_t *msg,
		uint32_t       msg_len
		);
	int (*expand_message_finalize_48B) (
		void          *ctx,
		uint8_t        out[48],
		const uint8_t *dst,
		uint8_t        dst_len
		);
	int (*expand_message_dyn)(
		void          *ctx,
		uint8_t       *out,
		uint32_t       out_len,
		const uint8_t *msg,
		uint32_t       msg_lg,
		const uint8_t *dst,
		uint8_t        dst_len
		);
	char    *cipher_suite_id;
	uint8_t  cipher_suite_id_len;
	char    *default_key_dst;
	uint8_t  default_key_dst_len;
	char    *api_id;
	uint8_t  api_id_len;
	char    *signature_dst;
	uint8_t  signature_dst_len;
	char    *challenge_dst;
	uint8_t  challenge_dst_len;
	char    *map_dst;
	uint8_t  map_dst_len;
} bbs_cipher_suite_t;

extern bbs_cipher_suite_t bbs_sha256_cipher_suite;
extern bbs_cipher_suite_t bbs_shake256_cipher_suite;

// Octet string lengths
#define BBS_SK_LEN                     32
#define BBS_PK_LEN                     96
#define BBS_SIG_LEN                    80
#define BBS_PROOF_BASE_LEN             272
#define BBS_PROOF_UD_ELEM_LEN          32
#define BBS_PROOF_LEN(num_undisclosed) (BBS_PROOF_BASE_LEN + num_undisclosed * BBS_PROOF_UD_ELEM_LEN \
					)

// Return values
#define BBS_OK    0
#define BBS_ERROR 1

// Typedefs
typedef uint8_t  bbs_secret_key[BBS_SK_LEN];
typedef uint8_t  bbs_public_key[BBS_PK_LEN];
typedef uint8_t  bbs_signature[BBS_SIG_LEN];

#define bbs_sha256_keygen_full   bbs_keygen_full
#define bbs_shake256_keygen_full bbs_keygen_full

// Key Generation
int bbs_keygen_full (
	bbs_secret_key  sk,
	bbs_public_key  pk
	);

int bbs_sha256_keygen (
	bbs_secret_key  sk,
	const uint8_t  *key_material,
	uint16_t        key_material_len,
	const uint8_t  *key_info,
	uint16_t        key_info_len,
	const uint8_t  *key_dst,
	uint8_t         key_dst_len
	);

int bbs_shake256_keygen (
	bbs_secret_key  sk,
	const uint8_t  *key_material,
	uint16_t        key_material_len,
	const uint8_t  *key_info,
	uint16_t        key_info_len,
	const uint8_t  *key_dst,
	uint8_t         key_dst_len
	);

int bbs_keygen (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	const uint8_t      *key_material,
	uint16_t            key_material_len,
	const uint8_t      *key_info,
	uint16_t            key_info_len,
	const uint8_t      *key_dst,
	uint8_t             key_dst_len
	);

#define bbs_sha256_sk_to_pk   bbs_sk_to_pk

#define bbs_shake256_sk_to_pk bbs_sk_to_pk

int bbs_sk_to_pk (
	const bbs_secret_key  sk,
	bbs_public_key        pk
	);

// Signing

int bbs_sha256_sign (
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

int bbs_shake256_sign (
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);


int bbs_sign (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	va_list               ap
	);

// Verification

int bbs_sha256_verify (
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

int bbs_shake256_verify (
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

int bbs_verify (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	va_list               ap
	);

// Proof Generation

#define bbs_sha256_proof_gen   bbs_proof_gen
#define bbs_shake256_proof_gen bbs_proof_gen

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

int bbs_sha256_proof_verify (
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

int bbs_shake256_proof_verify (
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

int bbs_proof_verify (
	bbs_cipher_suite_t   *cipher_suite,
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
	va_list               ap
	);

#endif
