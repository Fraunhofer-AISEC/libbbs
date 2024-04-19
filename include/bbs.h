#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdarg.h>

/// @brief BBS cipher suite interface
/// @note Strategy pattern to dispatch to the correct hash function for the
/// cipher suite, keeping the same overall control flow for the caller.
typedef struct
{
	// Execution needs multiple hash contexts simultaneously
	void    *hash_ctx;
	void    *dom_ctx;
	void    *ch_ctx;
	uint8_t *p1;

	// Incremental expand_message API with fixed 48B output (needed at multiple points in protocol)
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

	// One-shot expand_message API with variable output length (only needed in create_generator_next)
	int (*expand_message_dyn)(
		void          *ctx,
		uint8_t       *out,
		uint32_t       out_len,
		const uint8_t *msg,
		uint32_t       msg_lg,
		const uint8_t *dst,
		uint8_t        dst_len
		);

	/// DST
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

// Key Generation

int bbs_sha256_keygen_full (
	bbs_secret_key  sk,
	bbs_public_key  pk
	);

int bbs_shake256_keygen_full (
	bbs_secret_key  sk,
	bbs_public_key  pk
	);

int bbs_keygen_full (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
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

int bbs_sha256_proof_gen (
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

int bbs_shake256_proof_gen (
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


int bbs_proof_gen (
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
	va_list               ap
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
