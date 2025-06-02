#ifndef BBS_H
#define BBS_H

#include <stdint.h>
#include <stdarg.h>

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
typedef struct bbs_cipher_suite bbs_cipher_suite_t;

// Subsystem init
int
bbs_init (void);

int
bbs_deinit (void);

// Key Generation

int bbs_keygen_full (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
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

int bbs_sk_to_pk (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	bbs_public_key        pk
	);

// Signing
int bbs_sign (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

// Verification
int bbs_verify (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

// Proof Generation
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
	...
	);

// Proof Verification
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
	...
	);

// Supported Cipher Suites
extern bbs_cipher_suite_t *bbs_sha256_cipher_suite;
#define bbs_sha256_keygen_full(...)  bbs_keygen_full(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_keygen(...)       bbs_keygen(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sk_to_pk(...)     bbs_sk_to_pk(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_sign(...)         bbs_sign(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_verify(...)       bbs_verify(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_gen(...)    bbs_proof_gen(bbs_sha256_cipher_suite,__VA_ARGS__)
#define bbs_sha256_proof_verify(...) bbs_proof_verify(bbs_sha256_cipher_suite,__VA_ARGS__)

extern bbs_cipher_suite_t *bbs_shake256_cipher_suite;
#define bbs_shake256_keygen_full(...)  bbs_keygen_full(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_keygen(...)       bbs_keygen(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sk_to_pk(...)     bbs_sk_to_pk(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_sign(...)         bbs_sign(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_verify(...)       bbs_verify(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_gen(...)    bbs_proof_gen(bbs_shake256_cipher_suite,__VA_ARGS__)
#define bbs_shake256_proof_verify(...) bbs_proof_verify(bbs_shake256_cipher_suite,__VA_ARGS__)

#endif
