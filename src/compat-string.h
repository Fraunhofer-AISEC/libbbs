#ifndef STRING_H
#define STRING_H

#include <stddef.h>

// These work exactly like their libc counterparts, but have some guardrails
// built in. Should be constant-time and not optimized out if LTO is disabled.
void *bbs_memset(void *s, int c, size_t n);
int   bbs_memcmp(const void *s1, const void *s2, size_t n);
void *bbs_memmove(void *dest, const void *src, size_t n);
void *bbs_memcpy(void *dest, const void *src, size_t n);

#endif /* STRING_H */
