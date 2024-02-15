#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "bbs.h"
#include "bbs_util.h"

#include <stdio.h>

#define ASSERT_EQ(purpose, actual, ref) \
	for(int i=0; i < sizeof(ref); i++) { \
		if(actual[i] != ref[i]) { \
			puts("Mismatch in " purpose); \
			DEBUG("Should be:", ref, sizeof(ref)); \
			DEBUG("Is:", actual, sizeof(actual)); \
			return 1; \
		} \
	}


#endif /* TEST_UTIL_H */
