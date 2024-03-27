#include "fixtures.h"
#include "test_util.h"
#include "bbs_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

int
bbs_fix_expand_message ()
{
	return 0;
}


#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

int
bbs_fix_expand_message ()
{
	if (core_init () != RLC_OK)
	{
		core_clean ();
		return 1;
	}
	if (pc_param_set_any () != RLC_OK)
	{
		core_clean ();
		return 1;
	}

	bbs_hash_ctx ctx;
	uint8_t      out[rfc_9380_k6_expand_message_xof_out_len_2];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_2,
			       rfc_9380_k6_expand_message_xof_msg_2_len);
	// _expand_message_finalize (&ctx, out, rfc_9380_k6_expand_message_xof_out_len_2,
	// 			  rfc_9380_k6_expand_message_xof_dst,
	// 			  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out, fixture_rfc_9380_k6_expand_message_xof_output_2)
	return 0;
}


#endif