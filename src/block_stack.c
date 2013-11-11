#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "types.h"
#include "block.h"

int block_stack_init(block_stack_t *bs, size_t blksize, size_t recursion_limit) {
	bs->blksize = blksize;
	bs->n = 0;
	bs->limit = recursion_limit;
	bs->block = malloc(recursion_limit*sizeof(block_t));
	if (!bs->block) {
		perror("out of memory");
		return -1;
	}
	return 0;
}

void block_stack_free(block_stack_t *bs) {
	for (size_t n = 0; n < bs->n; n++) {
		block_free(bs->block + n);
	}
	free(bs->block);
	bs->n = 0;
	bs->block = NULL;
}

block_t* block_stack_get(block_stack_t *bs, size_t idx) {
	if (idx < bs->n) {
		return bs->block + idx;
	}
	assert(bs->n == idx);

	if (idx >= bs->limit) {
		fprintf(stderr, "recursion depth too high\n");
		return NULL;
	}

	if (block_init(bs->block + idx, bs->blksize)) {
		fprintf(stderr, "block_init failed\n");
		return NULL;
	}

	bs->n = idx + 1;
	return bs->block + idx;
}
