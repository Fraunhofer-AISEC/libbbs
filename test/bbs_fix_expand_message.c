#include "fixtures.h"
#include "test_util.h"

#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256

int
bbs_fix_expand_message ()
{
	return 0;
}


#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256

int
bss_fix_expand_message ()
{
	return 0;
}


#endif