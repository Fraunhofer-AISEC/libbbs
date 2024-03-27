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

	uint8_t      out_1[rfc_9380_k6_expand_message_xof_out_len_1];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_1,
			       rfc_9380_k6_expand_message_xof_msg_1_len);
	_expand_message_finalize (&ctx, out_1, rfc_9380_k6_expand_message_xof_out_len_1,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_1, fixture_rfc_9380_k6_expand_message_xof_output_1)

	uint8_t      out_2[rfc_9380_k6_expand_message_xof_out_len_2];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_2,
			       rfc_9380_k6_expand_message_xof_msg_2_len);
	_expand_message_finalize (&ctx, out_2, rfc_9380_k6_expand_message_xof_out_len_2,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_2, fixture_rfc_9380_k6_expand_message_xof_output_2)

	uint8_t      out_3[rfc_9380_k6_expand_message_xof_out_len_3];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_3,
			       rfc_9380_k6_expand_message_xof_msg_3_len);
	_expand_message_finalize (&ctx, out_3, rfc_9380_k6_expand_message_xof_out_len_3,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_3, fixture_rfc_9380_k6_expand_message_xof_output_3)

	uint8_t      out_4[rfc_9380_k6_expand_message_xof_out_len_4];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_4,
			       rfc_9380_k6_expand_message_xof_msg_4_len);
	_expand_message_finalize (&ctx, out_4, rfc_9380_k6_expand_message_xof_out_len_4,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_4, fixture_rfc_9380_k6_expand_message_xof_output_4)

	uint8_t      out_5[rfc_9380_k6_expand_message_xof_out_len_5];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_5,
			       rfc_9380_k6_expand_message_xof_msg_5_len);
	_expand_message_finalize (&ctx, out_5, rfc_9380_k6_expand_message_xof_out_len_5,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_5, fixture_rfc_9380_k6_expand_message_xof_output_5)

	uint8_t      out_6[rfc_9380_k6_expand_message_xof_out_len_6];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_6,
			       rfc_9380_k6_expand_message_xof_msg_6_len);
	_expand_message_finalize (&ctx, out_6, rfc_9380_k6_expand_message_xof_out_len_6,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_6, fixture_rfc_9380_k6_expand_message_xof_output_6)

	uint8_t      out_7[rfc_9380_k6_expand_message_xof_out_len_7];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_7,
			       rfc_9380_k6_expand_message_xof_msg_7_len);
	_expand_message_finalize (&ctx, out_7, rfc_9380_k6_expand_message_xof_out_len_7,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_7, fixture_rfc_9380_k6_expand_message_xof_output_7)

	uint8_t      out_8[rfc_9380_k6_expand_message_xof_out_len_8];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_8,
			       rfc_9380_k6_expand_message_xof_msg_8_len);
	_expand_message_finalize (&ctx, out_8, rfc_9380_k6_expand_message_xof_out_len_8,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_8, fixture_rfc_9380_k6_expand_message_xof_output_8)

	uint8_t      out_9[rfc_9380_k6_expand_message_xof_out_len_9];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_9,
			       rfc_9380_k6_expand_message_xof_msg_9_len);
	_expand_message_finalize (&ctx, out_9, rfc_9380_k6_expand_message_xof_out_len_9,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_9, fixture_rfc_9380_k6_expand_message_xof_output_9)

	uint8_t      out_10[rfc_9380_k6_expand_message_xof_out_len_10];
	expand_message_init (&ctx);
	expand_message_update (&ctx, rfc_9380_k6_expand_message_xof_msg_10,
			       rfc_9380_k6_expand_message_xof_msg_10_len);
	_expand_message_finalize (&ctx, out_10, rfc_9380_k6_expand_message_xof_out_len_10,
				  rfc_9380_k6_expand_message_xof_dst,
				  rfc_9380_k6_expand_message_xof_dst_len);
	ASSERT_EQ ("expand_message", out_10, fixture_rfc_9380_k6_expand_message_xof_output_10)

	return 0;
}


#endif