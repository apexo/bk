#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "block_stack.h"

int block_stack_init(block_stack_t *bs, size_t blksize, size_t recursion_limit) {
	bs->blksize = blksize;
	bs->n = 0;
	bs->limit = recursion_limit;
	bs->block = malloc(recursion_limit*sizeof(block_t));
	if (!bs->block) {
		perror("out of memory");
		return -1;
	}
	bs->temp = malloc(recursion_limit*sizeof(char*));
	if (!bs->temp) {
		perror("out of memory");
		free(bs->block);
		return -1;
	}
	return 0;
}

void block_stack_free(block_stack_t *bs) {
	for (size_t n = 0; n < bs->n; n++) {
		block_free(bs->block + n);
		free(bs->temp[n]);
	}
	free(bs->block);
	free(bs->temp);
	bs->n = 0;
	bs->block = NULL;
	bs->temp = NULL;
}

static int _block_stack_grow(block_stack_t *bs) {
	if (bs->n == bs->limit) {
		fprintf(stderr, "recursion depth too high\n");
		return -1;
	}

	if (!(bs->temp[bs->n] = malloc(bs->blksize))) {
		perror("out of memory");
		return -1;
	}

	if (block_init(bs->block + bs->n, bs->blksize)) {
		fprintf(stderr, "block_init failed\n");
		free(bs->temp[bs->n]);
		bs->temp[bs->n] = NULL;
		return -1;
	}

	bs->n++;
	return 0;
}

block_t* block_stack_get(block_stack_t *bs, size_t idx) {
	while (idx >= bs->n) {
		if (_block_stack_grow(bs)) {
			fprintf(stderr, "_block_stack_grow failed\n");
			return NULL;
		}
	}

	return bs->block + idx;
}

char* block_stack_get_temp(block_stack_t *bs, size_t idx) {
	while (idx >= bs->n) {
		if (_block_stack_grow(bs)) {
			fprintf(stderr, "_block_stack_grow failed\n");
			return NULL;
		}
	}

	return bs->temp[idx];
}
