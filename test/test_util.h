#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "bbs.h"
#include "bbs_util.h"

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

// Magic constants to be used as Domain Separation Tags
#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define BBS_CIPHER_SUITE_ID "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
#define BBS_CIPHER_SUITE_LENGTH 35
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define BBS_CIPHER_SUITE_ID "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
#define BBS_CIPHER_SUITE_LENGTH 37
#endif

#define BBS_DEFAULT_KEY_DST BBS_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_API_ID          BBS_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_API_ID_LENGTH   BBS_CIPHER_SUITE_LENGTH + 9
#define BBS_SIGNATURE_DST   BBS_API_ID "H2S_"
#define BBS_CHALLENGE_DST   BBS_API_ID "H2S_"
#define BBS_MAP_DST         BBS_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_MAP_DST_LENGTH  BBS_API_ID_LENGTH + 26


#define ASSERT_EQ(purpose, actual, ref) \
	for(int i=0; i < sizeof(ref); i++) { \
		if(actual[i] != ref[i]) { \
			puts("Mismatch in " purpose); \
			DEBUG("Should be:", ref, sizeof(ref)); \
			DEBUG("Is:", actual, sizeof(actual)); \
			return 1; \
		} \
	}


struct timespec tp_start;

struct timespec tp_end;

#ifdef ENABLE_BENCHMARK
#define BBS_BENCH_START() \
    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_start);
#define BBS_BENCH_END(hint) \
    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_end); \
    fprintf (stdout, "%s: %"PRIu64" ns\n", hint,                          \
        (((uint64_t)tp_end.tv_sec*1000000000) + tp_end.tv_nsec) -  \
        (((uint64_t)tp_start.tv_sec*1000000000) + tp_start.tv_nsec));
#else
#define BBS_BENCH_START()
#define BBS_BENCH_END(hint)
#endif
#endif /* TEST_UTIL_H */
