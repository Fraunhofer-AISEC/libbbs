#ifndef FIXTURES_H
#define FIXTURES_H

#include <bbs.h>
#include <stddef.h>

// This header file defines several extern constants, which are generated per
// ciphersuite by genfixtures. 

extern const bbs_cipher_suite_t *const *const fixture_cipher_suite;

extern const struct fixture_hash_to_scalar {
	const uint8_t *msg;
	size_t         msg_len;
	const uint8_t *dst;
	size_t         dst_len;
	uint8_t        result[32];
} *const vectors_hash_to_scalar;
extern const size_t vectors_hash_to_scalar_len;

extern const struct fixture_generators {
	const uint8_t (*result)[48]; // Includes Q_1, H_1, ... H_(result_len-1)
	size_t          result_len;
} *const vectors_generators;
extern const size_t vectors_generators_len;

extern const struct fixture_keygen {
	const uint8_t *key_material;
	size_t         key_material_len;
	const uint8_t *key_info;
	size_t         key_info_len;
	const uint8_t *key_dst;
	size_t         key_dst_len;
	uint8_t        result_sk[32];
	uint8_t        result_pk[96];
} *const vectors_keygen;
extern const size_t vectors_keygen_len;

extern const struct fixture_signature {
	uint8_t               sk[32];
	uint8_t               pk[96];
	const uint8_t        *header;
	size_t                header_len;
	size_t                num_messages;
	const uint8_t *const *msgs;
	const size_t         *msg_lens;
	uint8_t               result[80];
	int                   result_valid;
} *const vectors_signature;
extern const size_t vectors_signature_len;

extern const struct fixture_proof {
	uint8_t               pk[96];
	uint8_t               signature[80];
	const uint8_t        *header;
	size_t                header_len;
	const uint8_t        *presentation_header;
	size_t                presentation_header_len;
	size_t                num_messages;
	const uint8_t *const *msgs;
	const size_t         *msg_lens;
	const uint64_t       *disclosed_indexes;
	size_t                disclosed_indexes_len;
	const uint8_t        *result;
	size_t                result_len;
	int                   result_valid;
} *const vectors_proof;
extern const size_t vectors_proof_len;

#endif /* FIXTURES_H */
