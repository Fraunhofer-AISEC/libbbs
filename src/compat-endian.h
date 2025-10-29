#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>

// Reimplement some <endian.h> functions inline. Reduces runtime dependencies.
// In particular, some systems do not have modern POSIX headers.
static inline uint16_t htobe16(uint16_t x) {
	const uint16_t le = 1; if(!*(char*)&le) return x;
	return x << 8 | x >> 8;
}

static inline uint32_t htobe32(uint32_t x) {
	const uint16_t le = 1; if(!*(char*)&le) return x;
	return ((x & (uint64_t)0xff000000L) >> 24) |
	       ((x & (uint64_t)0x00ff0000L) >>  8) |
	       ((x & (uint64_t)0x0000ff00L) <<  8) |
	       ((x & (uint64_t)0x000000ffL) << 24) ;
}

static inline uint64_t htobe64(uint64_t x) {
	const uint16_t le = 1; if(!*(char*)&le) return x;
	return ((x & (uint64_t)0xff00000000000000LL) >> 56) |
	       ((x & (uint64_t)0x00ff000000000000LL) >> 40) |
	       ((x & (uint64_t)0x0000ff0000000000LL) >> 24) |
	       ((x & (uint64_t)0x000000ff00000000LL) >>  8) |
	       ((x & (uint64_t)0x00000000ff000000LL) <<  8) |
	       ((x & (uint64_t)0x0000000000ff0000LL) << 24) |
	       ((x & (uint64_t)0x000000000000ff00LL) << 40) |
	       ((x & (uint64_t)0x00000000000000ffLL) << 56) ;
}

#endif /* ENDIAN_H */
