#include "bbs.h"
#include "bbs_util.h"

// Magic constants to be used as Domain Separation Tags

#define BBS_SHA256_CIPHER_SUITE_ID        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
#define BBS_SHA256_CIPHER_SUITE_LENGTH    35
#define BBS_SHA256_DEFAULT_KEY_DST        BBS_SHA256_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_SHA256_DEFAULT_KEY_DST_LENGTH BBS_SHA256_CIPHER_SUITE_LENGTH + 11
#define BBS_SHA256_API_ID                 BBS_SHA256_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_SHA256_API_ID_LENGTH          BBS_SHA256_CIPHER_SUITE_LENGTH + 9
#define BBS_SHA256_SIGNATURE_DST          BBS_SHA256_API_ID "H2S_"
#define BBS_SHA256_SIGNATURE_DST_LENGTH   BBS_SHA256_API_ID_LENGTH + 4
#define BBS_SHA256_CHALLENGE_DST          BBS_SHA256_API_ID "H2S_"
#define BBS_SHA256_CHALLENGE_DST_LENGTH   BBS_SHA256_API_ID_LENGTH + 4
#define BBS_SHA256_MAP_DST                BBS_SHA256_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_SHA256_MAP_DST_LENGTH         BBS_SHA256_API_ID_LENGTH + 26

// The above collision stems from the ID. Possible oversight? Should not compromise
// security too much...

#define BBS_SHAKE256_CIPHER_SUITE_ID        "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
#define BBS_SHAKE256_CIPHER_SUITE_LENGTH    37
#define BBS_SHAKE256_DEFAULT_KEY_DST        BBS_SHAKE256_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_SHAKE256_DEFAULT_KEY_DST_LENGTH BBS_SHAKE256_CIPHER_SUITE_LENGTH + 11
#define BBS_SHAKE256_API_ID                 BBS_SHAKE256_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_SHAKE256_API_ID_LENGTH          BBS_SHAKE256_CIPHER_SUITE_LENGTH + 9
#define BBS_SHAKE256_SIGNATURE_DST          BBS_SHAKE256_API_ID "H2S_"
#define BBS_SHAKE256_SIGNATURE_DST_LENGTH   BBS_SHAKE256_API_ID_LENGTH + 4
#define BBS_SHAKE256_CHALLENGE_DST          BBS_SHAKE256_API_ID "H2S_"
#define BBS_SHAKE256_CHALLENGE_DST_LENGTH   BBS_SHAKE256_API_ID_LENGTH + 4
#define BBS_SHAKE256_MAP_DST                BBS_SHAKE256_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_SHAKE256_MAP_DST_LENGTH         BBS_SHAKE256_API_ID_LENGTH + 26

// For conversion
#define EXP_INIT void (*) (union bbs_hash_context *)
#define EXP_UPDATE void (*) (union bbs_hash_context *, const uint8_t *, size_t)
#define EXP_FINALIZE void (*) (union bbs_hash_context *, uint8_t*, uint16_t, const uint8_t *, size_t)

// *INDENT-OFF* - Preserve formatting
static const bbs_cipher_suite_t bbs_sha256_cipher_suite_s = {
	.p1 = {
		0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
		0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
		0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
		0x4e, 0x28, 0xc9
	},
	.expand_message_init = (EXP_INIT) xmd_sha256_init,
	.expand_message_update = (EXP_UPDATE) xmd_sha256_update,
	.expand_message_finalize = (EXP_FINALIZE) xmd_sha256_finalize,
	.cipher_suite_id = (uint8_t*) BBS_SHA256_CIPHER_SUITE_ID,
	.cipher_suite_id_len = BBS_SHA256_CIPHER_SUITE_LENGTH,
	.default_key_dst = (uint8_t*) BBS_SHA256_DEFAULT_KEY_DST,
	.default_key_dst_len = BBS_SHA256_DEFAULT_KEY_DST_LENGTH,
	.api_id = (uint8_t*) BBS_SHA256_API_ID,
	.api_id_len = BBS_SHA256_API_ID_LENGTH,
	.signature_dst = (uint8_t*) BBS_SHA256_SIGNATURE_DST,
	.signature_dst_len = BBS_SHA256_SIGNATURE_DST_LENGTH,
	.challenge_dst = (uint8_t*) BBS_SHA256_CHALLENGE_DST,
	.challenge_dst_len = BBS_SHA256_CHALLENGE_DST_LENGTH,
	.map_dst = (uint8_t*) BBS_SHA256_MAP_DST,
	.map_dst_len = BBS_SHA256_MAP_DST_LENGTH,
};
const bbs_cipher_suite_t *const bbs_sha256_cipher_suite = &bbs_sha256_cipher_suite_s;

static const bbs_cipher_suite_t bbs_shake256_cipher_suite_s = {
	.p1 = {
		0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
		0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
		0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
		0x15, 0x07, 0x55
	},
	.expand_message_init = (EXP_INIT) xof_shake256_init,
	.expand_message_update = (EXP_UPDATE) xof_shake256_update,
	.expand_message_finalize = (EXP_FINALIZE) xof_shake256_finalize,
	.cipher_suite_id = (uint8_t*) BBS_SHAKE256_CIPHER_SUITE_ID,
	.cipher_suite_id_len = BBS_SHAKE256_CIPHER_SUITE_LENGTH,
	.default_key_dst = (uint8_t*) BBS_SHAKE256_DEFAULT_KEY_DST,
	.default_key_dst_len = BBS_SHAKE256_DEFAULT_KEY_DST_LENGTH,
	.api_id = (uint8_t*) BBS_SHAKE256_API_ID,
	.api_id_len = BBS_SHAKE256_API_ID_LENGTH,
	.signature_dst = (uint8_t*) BBS_SHAKE256_SIGNATURE_DST,
	.signature_dst_len = BBS_SHAKE256_SIGNATURE_DST_LENGTH,
	.challenge_dst = (uint8_t*) BBS_SHAKE256_CHALLENGE_DST,
	.challenge_dst_len = BBS_SHAKE256_CHALLENGE_DST_LENGTH,
	.map_dst = (uint8_t*) BBS_SHAKE256_MAP_DST,
	.map_dst_len = BBS_SHAKE256_MAP_DST_LENGTH,
};
const bbs_cipher_suite_t *const bbs_shake256_cipher_suite = &bbs_shake256_cipher_suite_s;
// *INDENT-ON* - Restore formatting

