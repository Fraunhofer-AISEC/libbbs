// SPDX-License-Identifier: Apache-2.0
#include "bbs.h"
#include "bbs_util.h"

// Magic constants to be used as Domain Separation Tags
#define BBS_SHA256   "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
#define BBS_SHAKE256 "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"

#define _KEY_DST(suite)  suite "KEYGEN_DST_"
#define _API_ID(suite)   suite "H2G_HM2S_"
#define _SIG_DST(suite)  _API_ID(suite) "H2S_"
#define _CHL_DST(suite)  _API_ID(suite) "H2S_"
#define _MAP_DST(suite)  _API_ID(suite) "MAP_MSG_TO_SCALAR_AS_HASH_"

// The above collision stems from the ID. Possible oversight? Should not compromise
// security too much...

// For conversion
#define EXP_INIT     void (*) (union bbs_hash_context *)
#define EXP_UPDATE   void (*) (union bbs_hash_context *, bbs_message)
#define EXP_FINALIZE void (*) (union bbs_hash_context *, bbs_out_message, bbs_message)

// C does not count compound literals as constant expressions.
// Thus, here we use nested initializers.
#undef BBS_MSG
#define BBS_MSG(loc, len) { loc, len }

// *INDENT-OFF* - Preserve formatting
static const struct _bbs_ciphersuite _bbs_sha256_ciphersuite = {
	.p1 = {
		0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46, 0x62,
		0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1, 0xfd, 0x22,
		0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b, 0x4e, 0x28, 0xc9
	},
	.expand_message_init     = (EXP_INIT)     xmd_sha256_init,
	.expand_message_update   = (EXP_UPDATE)   xmd_sha256_update,
	.expand_message_finalize = (EXP_FINALIZE) xmd_sha256_finalize,
	.cipher_suite_id = BBS_LSMSG(           BBS_SHA256   ),
	.default_key_dst = BBS_LSMSG( _KEY_DST( BBS_SHA256 ) ),
	.api_id          = BBS_LSMSG( _API_ID ( BBS_SHA256 ) ),
	.signature_dst   = BBS_LSMSG( _SIG_DST( BBS_SHA256 ) ),
	.challenge_dst   = BBS_LSMSG( _CHL_DST( BBS_SHA256 ) ),
	.map_dst         = BBS_LSMSG( _MAP_DST( BBS_SHA256 ) ),
};
const bbs_ciphersuite *const bbs_sha256_ciphersuite = &_bbs_sha256_ciphersuite;

static const struct _bbs_ciphersuite _bbs_shake256_ciphersuite = {
	.p1 = {
		0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93, 0xf8,
		0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48, 0xa5, 0x6c,
		0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14, 0x15, 0x07, 0x55
	},
	.expand_message_init     = (EXP_INIT)     xof_shake256_init,
	.expand_message_update   = (EXP_UPDATE)   xof_shake256_update,
	.expand_message_finalize = (EXP_FINALIZE) xof_shake256_finalize,
	.cipher_suite_id = BBS_LSMSG(BBS_SHAKE256),
	.default_key_dst = BBS_LSMSG( _KEY_DST( BBS_SHAKE256 ) ),
	.api_id          = BBS_LSMSG( _API_ID ( BBS_SHAKE256 ) ),
	.signature_dst   = BBS_LSMSG( _SIG_DST( BBS_SHAKE256 ) ),
	.challenge_dst   = BBS_LSMSG( _CHL_DST( BBS_SHAKE256 ) ),
	.map_dst         = BBS_LSMSG( _MAP_DST( BBS_SHAKE256 ) ),
};
const bbs_ciphersuite *const bbs_shake256_ciphersuite = &_bbs_shake256_ciphersuite;
// *INDENT-ON* - Restore formatting

