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

#include <stdint.h>
#include <stdarg.h>

/**
 * @brief Octet string length of secret key
 */
#define BBS_SK_LEN                     32

/**
 * @brief Octet string length of public key
 */
#define BBS_PK_LEN                     96

/**
 * @brief Octet string length of signature
 */
#define BBS_SIG_LEN                    80

/**
 * @brief Minimum octet string length of proof
 */
#define BBS_PROOF_BASE_LEN             272

/**
 * @brief Octet string length of UD element
 */
#define BBS_PROOF_UD_ELEM_LEN          32

/**
 * @brief Macro that calculates the octet string
 * length of proof with @param num_undisclosed number of undisclosed
 * messages.
 */
#define BBS_PROOF_LEN(num_undisclosed) (BBS_PROOF_BASE_LEN + num_undisclosed * BBS_PROOF_UD_ELEM_LEN \
					)

/**
 * @brief return value on success
 */
#define BBS_OK    0

/**
 * @brief return value on error
 */
#define BBS_ERROR 1

/**
 * @brief BBS secret key
 *
 * The secret key is an octet string of
 * length #BBS_SK_LEN.
 */
typedef uint8_t  bbs_secret_key[BBS_SK_LEN];

/**
 * @brief BBS public key
 *
 * The public key is an octet string of
 * length #BBS_PK_LEN.
 */
typedef uint8_t  bbs_public_key[BBS_PK_LEN];

/**
 * @brief BBS signature
 *
 * The BBS signature is an octet string of
 * length #BBS_SIG_LEN.
 */
typedef uint8_t  bbs_signature[BBS_SIG_LEN];

/**
 * @brief BBS cipher suite
 *
 * The cipher suite. Is one of
 * #bbs_sha256_cipher_suite or #bbs_shake256_cipher_suite
 */
typedef struct bbs_cipher_suite bbs_cipher_suite_t;

/**
 * Subsystem initialization
 * Call this function before any other API.
 * Make sure to call #bbs_deinit when done.
 *
 * @return #BBS_OK on success.
 */
int
bbs_init (void);


/**
 * Subsystem cleanup
 * Call this function on global scope exit.
 *
 * @return #BBS_OK on success.
 */
int
bbs_deinit (void);

// Key Generation

/**
 * Generate a public/private key pair
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param sk where to store the secret key
 * @param pk where to store the public key
 * @return 0 on success.
 */
int bbs_keygen_full (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
	);


/**
 * Generate a public/private key pair
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param sk where to store the secret key
 * @param key_material TODO
 * @param key_material_len the length of #key_material
 * @param key_info TODO
 * @param key_info_len the length of #key_info
 * @param key_dst TODO
 * @param key_dst_len the length of #key_dst
 * @return 0 on success.
 */
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

/**
 * Generate public key from secret key.
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param sk secret key.
 * @return #BBS_OK on success.
 */
int bbs_sk_to_pk (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	bbs_public_key        pk
	);

/**
 * @brief Create a signature.
 *
 * The @param num_messages is followed by
 * this amount of varargs that consist of
 * a tuple of uint8_t* pointers to octet strings
 * followed by a uint32_t length indicator.
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param sk secret key.
 * @param pk public key.
 * @param signature where to store the signature.
 * @param header the message header.
 * @param header_len the length of the message header.
 * @param num_messages the number of messages followed by in varargs.
 * @return #BBS_OK on success.
 */
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

/**
 * @brief Verify a signature.
 *
 * The @p num_messages is followed by
 * this amount of varargs that consist of
 * a tuple of uint8_t* pointers to octet strings
 * followed by a uint32_t length indicator.
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param pk public key.
 * @param signature the signature to verify.
 * @param header the message header.
 * @param header_len the length of the message header.
 * @param num_messages the number of messages followed by in varargs.
 * @return #BBS_OK on success.
 */
int bbs_verify (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	);

/**
 * @brief Create a proof over a signature.
 *
 * The @p num_messages is followed by
 * this amount of varargs that consist of
 * a tuple of uint8_t* pointers to octet strings
 * followed by a uint32_t length indicator.
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param pk public key.
 * @param signature the signature to use.
 * @param proof pointer to the proof (must be allocated accordingly by caller).
 * @param header the message header.
 * @param header_len the length of the message header.
 * @param presentation_header the proof presentation header.
 * @param presentation_header_len the length of the proof presentation header.
 * @param disclosed_indexes an array of the indexes of the messages to disclose.
 * @param disclosed_indexes_len the length of @p disclosed_indexes array.
 * @param num_messages the number of messages followed by in varargs.
 * @return #BBS_OK on success.
 */
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

/**
 * @brief Verify a proof over a signature.
 *
 * The @p num_messages is followed by
 * this amount of varargs that consist of
 * a tuple of uint8_t* pointers to octet strings
 * followed by a uint32_t length indicator.
 *
 * @param cipher_suite the cipher suite to use. See #bbs_cipher_suite.
 * @param pk public key.
 * @param signature the signature to use.
 * @param proof pointer to the proof.
 * @param proof_len length of @param proof.
 * @param header the message header.
 * @param header_len the length of the message header.
 * @param presentation_header the proof presentation header.
 * @param presentation_header_len the length of the proof presentation header.
 * @param disclosed_indexes an array of the indexes of the messages that were disclosed.
 * @param disclosed_indexes_len the length of @p disclosed_indexes array.
 * @param num_messages the number of messages followed by in varargs.
 * @return #BBS_OK on success.
 */
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
