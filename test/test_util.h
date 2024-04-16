#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "bbs.h"
#include "bbs_util.h"

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

#define ASSERT_EQ(purpose, actual, ref) \
	for(int i=0; i < sizeof(ref); i++) { \
		if(actual[i] != ref[i]) { \
			puts("Mismatch in " purpose); \
			DEBUG("Should be:", ref, sizeof(ref)); \
			DEBUG("Is:", actual, sizeof(actual)); \
			return 1; \
		} \
	}

#define ASSERT_EQ_PTR(purpose, actual, ref, len) \
    int fail = 0; \
    for(size_t assert_eq_index = 0; assert_eq_index < len; assert_eq_index++) { \
        if (actual[assert_eq_index] != ref[assert_eq_index]) { \
			puts("Mismatch in " purpose); \
			printf("actual[%zu]: %02x\n", assert_eq_index, actual[assert_eq_index]); \
			printf("ref[%zu]: %02x\n", assert_eq_index, ref[assert_eq_index]); \
			DEBUG("Should be:", ref, len); \
			DEBUG("Is:", actual, len); \
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
