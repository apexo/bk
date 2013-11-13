#ifndef BK_BLOCK_STACK_H
#define BK_BLOCK_STACK_H

#include "block.h"

typedef struct block_stack {
	size_t blksize;
	size_t n;
	size_t limit;
	block_t *block;
} block_stack_t;

int block_stack_init(block_stack_t *bs, size_t block_size, size_t recursion_limit);
void block_stack_free(block_stack_t *bs);
block_t* block_stack_get(block_stack_t *bs, size_t idx);

#endif
