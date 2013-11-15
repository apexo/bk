#ifndef BK_TYPES_H
#define BK_TYPES_H

#include <stdint.h>

#define PAGE_SIZE 4096
#define MIN_BLOCK_SIZE 4096
#define INLINE_THRESHOLD 160
#define BLOCK_KEY_SIZE 32
#define MAX_REF_SIZE (2 + INLINE_THRESHOLD)

typedef char block_key_t[BLOCK_KEY_SIZE];
typedef uint64_t file_offset_t;
typedef uint32_t block_size_t;

#include "filter.h"

typedef struct args {
	int verbose;
	int list_only;
	int xdev;
	int dev;
	filter_t filter;

	size_t path_capacity;
	size_t path_length;
	char *path;
} args_t;

#endif
