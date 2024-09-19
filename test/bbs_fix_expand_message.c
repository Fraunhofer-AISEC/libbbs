#include "fixtures.h"
#include "test_util.h"
#include "bbs_util.h"

typedef struct
{
	uint8_t *msg;
	size_t   msg_len;
	size_t   out_len;
	uint8_t *expected_output;
} expand_message_rfc_9380_expand_message_xof_test;

/// Only tests shake256
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

	uint8_t out_1[
		rfc_9380_k6_expand_message_xof_out_len_1];
	uint8_t out_2[
		rfc_9380_k6_expand_message_xof_out_len_2];
	uint8_t out_3[
		rfc_9380_k6_expand_message_xof_out_len_3];
	uint8_t out_4[
		rfc_9380_k6_expand_message_xof_out_len_4];
	uint8_t out_5[
		rfc_9380_k6_expand_message_xof_out_len_5];
	uint8_t out_6[
		rfc_9380_k6_expand_message_xof_out_len_6];
	uint8_t out_7[
		rfc_9380_k6_expand_message_xof_out_len_7];
	uint8_t out_8[
		rfc_9380_k6_expand_message_xof_out_len_8];
	uint8_t out_9[
		rfc_9380_k6_expand_message_xof_out_len_9];
	uint8_t out_10[
		rfc_9380_k6_expand_message_xof_out_len_10];

	uint8_t *out_buffers[10] = { out_1, out_2, out_3, out_4, out_5, out_6, out_7, out_8, out_9, out_10 };

	expand_message_rfc_9380_expand_message_xof_test test_cases[10] = {
		{
			.msg             = rfc_9380_k6_expand_message_xof_msg_1,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_1_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_1,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_1
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_2,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_2_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_2,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_2
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_3,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_3_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_3,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_3
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_4,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_4_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_4,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_4
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_5,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_5_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_5,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_5
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_6,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_6_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_6,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_6
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_7,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_7_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_7,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_7
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_8,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_8_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_8,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_8
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_9,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_9_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_9,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_9
		},{
			.msg             = rfc_9380_k6_expand_message_xof_msg_10,
			.msg_len         = rfc_9380_k6_expand_message_xof_msg_10_len,
			.out_len         = rfc_9380_k6_expand_message_xof_out_len_10,
			.expected_output = fixture_rfc_9380_k6_expand_message_xof_output_10
		}
	};
	for (int i = 0; i < 10; i++)
	{
		if (BBS_OK != bbs_shake256_cipher_suite->expand_message_dyn (
						  out_buffers[i], test_cases[i].out_len,
						  test_cases[i].msg, test_cases[i].msg_len,
						  rfc_9380_k6_expand_message_xof_dst,
						  rfc_9380_k6_expand_message_xof_dst_len))
		{
			printf ("Error in expand_message_dyn test case %d\n", i);

			return 1;
		}
		ASSERT_EQ_PTR ("expand_message_dyn",
			       out_buffers[i],
			       test_cases[i].expected_output,
			       test_cases[i].out_len);
	}

	return 0;
}
