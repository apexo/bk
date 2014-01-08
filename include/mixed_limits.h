#ifndef _BK_MIXED_LIMITS_H
#define _BK_MIXED_LIMITS_H

#include <stdint.h>
#include <limits.h>

#if _FILE_OFFSET_BITS == 64
#define OFFSET_MAX 9223372036854775807L
typedef uint64_t uoff_t;
#else
#error _FILE_OFFSET_BITS must be 64
#endif

#define MIN(a,b) ((a)<(b)?(a):(b))

#define LONG_SIZE_MAX ((long)MIN(LONG_MAX,SIZE_MAX))
#define OFFSET_SIZE_MAX ((off_t)MIN(OFFSET_MAX, SIZE_MAX))
#define SIZE_OFFSET_MAX ((size_t)MIN(OFFSET_MAX, SIZE_MAX))

#endif
