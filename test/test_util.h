#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "bbs.h"
#ifndef BBS_NO_UTIL
#include "bbs_util.h"
#endif

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

#define ASSERT_EQ(purpose, actual, ref) \
	for (int assert_eq_index = 0; assert_eq_index < sizeof(ref); assert_eq_index++) { \
		if (actual[assert_eq_index] != ref[assert_eq_index]) { \
			puts ("Mismatch in " purpose); \
			DEBUG ("Should be:", ref,    sizeof(ref)); \
			DEBUG ("Is:",        actual, sizeof(actual)); \
			return 1; \
		} \
	}

#define ASSERT_EQ_PTR(purpose, actual, ref, len) \
	for (size_t assert_eq_index = 0; assert_eq_index < len; assert_eq_index++) { \
		if (actual[assert_eq_index] != ref[assert_eq_index]) { \
			puts ("Mismatch in " purpose); \
			printf ("actual[%zu]: %02x\n", assert_eq_index, actual[assert_eq_index]); \
			printf ("ref[%zu]: %02x\n",    assert_eq_index, ref[assert_eq_index]); \
			DEBUG ("Should be:", ref,    len); \
			DEBUG ("Is:",        actual, len); \
			return 1; \
		} \
	}


#ifdef ENABLE_BENCHMARK
#define BBS_BENCH_START(hint) \
  struct timespec tp_start_ ## hint; \
  struct timespec tp_end_ ## hint; \
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_start_ ## hint);
#define BBS_BENCH_END(hint,info) \
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tp_end_ ## hint); \
	fprintf (stdout, "%s: %" PRIu64 " ns\n", info,                          \
		 (((uint64_t) tp_end_ ## hint.tv_sec * 1000000000) + tp_end_ ## hint.tv_nsec) -  \
		 (((uint64_t) tp_start_ ## hint.tv_sec * 1000000000) + tp_start_ ## hint .tv_nsec));
#else
#define BBS_BENCH_START(hint)
#define BBS_BENCH_END(hint, info)
#endif
#endif /* TEST_UTIL_H */
