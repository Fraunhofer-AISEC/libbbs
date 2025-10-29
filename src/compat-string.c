#include "compat-string.h"
#include <stdint.h>

// In general, functions which set memory have a memory barrier if the compiler
// supports them, and functions reading from memory should have timing
// independent of the respective memory contents.

static void *barrier(void *ret) {
#if defined(__GNUC__) || defined(__clang__)
  	__asm__ __volatile__("": : "r"(ret) : "memory");
#endif
	return ret;
}

// GCC likes to replace loops with calls to these four functions. That is a) why
// they still have their original symbol names here, and b) why we must use
// function attributes to prevent GCC from implementing e.g. memcpy as a
// recursive call to memcpy *facepalm-emoji*

#if defined (__GNUC__) && !defined (__clang__)
# define NO_OPTIMIZE __attribute__((optimize("no-tree-loop-distribute-patterns")))
#else
# define NO_OPTIMIZE
#endif


NO_OPTIMIZE
void *memcpy(void *dest, const void *src, size_t n) {
	char *sc = (char*)src, *dc = (char*)dest;
	while(n--) *dc++ = *sc++;
	return barrier(dest);
}

NO_OPTIMIZE
void *memmove(void *dest, const void *src, size_t n) {
	char *sc = (char*)src + n, *dc = (char*)dest + n;
	if(src < dest) return memcpy(dest, src, n);
	while(n--) *--dc = *--sc;
	return barrier(dest);
}

// Algorithm from https://github.com/chmike/cst_time_memcmp, altered.
// The logic depends on abs(diff) < 256, so I try to throw the compiler off with
// a public volatile all-zero value.
volatile int _bbs_zero = 0;
NO_OPTIMIZE
int   memcmp(const void *s1, const void *s2, size_t n) {
	char *s1c = (char*)s1 + n, *s2c = (char*)s2 + n;
	volatile int res = 0, diff;
	while(n--) {
		diff = (*--s1c - *--s2c) ^ _bbs_zero;
		res = (res & (((diff-1) & ~diff) >> 8)) | diff; // cselect
	}
	return res; // right shift on signed values was undefined
}

NO_OPTIMIZE
void *memset(void *s, int c, size_t n) {
	char *sc = (char*)s;
	while(n--) *sc++ = c;
	return barrier(s);
}

// gcc likes to generate calls to the four library functions above, unless we
// Since our implementations have some guardrails, so we do not want to let the
// compiler assume we are explicitly using library functions outside this
// compilation unit. However, GCC will replace e.g. memset with
// __builtin_memset, which may be implemented and potentially removed inline.
// Hence the different names given here. That said, do not enable LTO in case
// compilers get smarter.
// An alternative, suggested online, is to use -fno-builtins, which is
// gcc-specific and may in some cases degrade performance.

void *bbs_memset(void *s, int c, size_t n)
	{ return memset(s, c, n); }
int   bbs_memcmp(const void *s1, const void *s2, size_t n)
	{ return memcmp(s1,s2,n); }
void *bbs_memmove(void *dest, const void *src, size_t n)
	{ return memmove(dest,src,n); }
void *bbs_memcpy(void *dest, const void *src, size_t n)
	{ return memcpy(dest,src,n); }

