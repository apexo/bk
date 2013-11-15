#ifndef BK_BLOCK_STACK_H
#define BK_BLOCK_STACK_H

#include "block.h"

typedef struct block_stack {
	block_thread_state_t block_thread_state;
	size_t blksize;
	size_t n;
	size_t limit;
	block_t *block;
	char **temp;
} block_stack_t;

int block_stack_init(block_stack_t *bs, size_t blksize, size_t recursion_limit);
void block_stack_free(block_stack_t *bs);
block_t* block_stack_get(block_stack_t *bs, size_t idx);
char* block_stack_get_temp(block_stack_t *bs, size_t idx);

#endif
