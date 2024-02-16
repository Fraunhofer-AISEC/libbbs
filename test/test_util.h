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


struct timespec tp_start;

struct timespec tp_end;

#define BBS_BENCH_START() \
    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_start);
#define BBS_BENCH_END(hint) \
    clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_end); \
    fprintf (stdout, "%s: %"PRIu64" ns\n", hint,                          \
        (((uint64_t)tp_end.tv_sec*1000000000) + tp_end.tv_nsec) -  \
        (((uint64_t)tp_start.tv_sec*1000000000) + tp_start.tv_nsec));
#endif /* TEST_UTIL_H */
