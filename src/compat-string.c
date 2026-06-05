// SPDX-License-Identifier: Apache-2.0
#include "compat-string.h"
#include <stdint.h>

// Constant-time memory operations for cryptographic use.
//
// Functions that write memory include a compiler barrier to prevent
// dead-store elimination. Functions that read memory execute in time
// independent of the memory contents.
//
// These are intentionally NOT named memset/memcpy/etc. — overriding libc
// symbols affects the entire linked program, breaking performance and
// correctness of unrelated code. The -fno-builtin flag (set in CMakeLists)
// prevents the compiler from replacing these byte loops with calls to libc.

static void *barrier(void *ret) {
#if defined(__GNUC__) || defined(__clang__)
  	__asm__ __volatile__("": : "r"(ret) : "memory");
#endif
	return ret;
}

// GCC's -ftree-loop-distribute-patterns pass recognizes byte-by-byte loops
// and replaces them with calls to memset/memcpy. This attribute disables
// that pass per-function. Clang relies on -fno-builtin instead.
#if defined (__GNUC__) && !defined (__clang__)
# define NO_OPTIMIZE __attribute__((optimize("no-tree-loop-distribute-patterns")))
#else
# define NO_OPTIMIZE
#endif


NO_OPTIMIZE
void *bbs_memcpy(void *dest, const void *src, size_t n) {
	char *sc = (char*)src, *dc = (char*)dest;
	while(n--) *dc++ = *sc++;
	return barrier(dest);
}

NO_OPTIMIZE
void *bbs_memmove(void *dest, const void *src, size_t n) {
	char *sc = (char*)src + n, *dc = (char*)dest + n;
	if(dest <= src) return bbs_memcpy(dest, src, n);
	while(n--) *--dc = *--sc;
	return barrier(dest);
}

// Algorithm from https://github.com/chmike/cst_time_memcmp, altered.
// The logic depends on abs(diff) < 256, so I try to throw the compiler off with
// a public volatile all-zero value.
volatile int _bbs_zero = 0;
NO_OPTIMIZE
int bbs_memcmp(const void *s1, const void *s2, size_t n) {
	char *s1c = (char*)s1 + n, *s2c = (char*)s2 + n;
	volatile int res = 0, diff;
	while(n--) {
		diff = (*--s1c - *--s2c) ^ _bbs_zero;
		res = (res & (((diff-1) & ~diff) >> 8)) | diff; // cselect
	}
	return res;
}

NO_OPTIMIZE
void *bbs_memset(void *s, int c, size_t n) {
	char *sc = (char*)s;
	while(n--) *sc++ = c;
	return barrier(s);
}
