#ifndef BK_BLOCK_H
#define BK_BLOCK_H

#include <fcntl.h>
#include <stdint.h>

#define MAX_INDIRECTION 4

typedef struct block {
	size_t blksize;
	uint32_t idx_blksize;
	size_t indirection;
	size_t len[MAX_INDIRECTION + 1];
	size_t idx[MAX_INDIRECTION + 1];
	size_t limit[MAX_INDIRECTION + 1];
	unsigned char *data[MAX_INDIRECTION + 1]; /* indirection buffer (locked) */
	unsigned char *temp0; /* user buffer, size bytes (locked) */
	unsigned char *temp1; /* compression buffer, LZ4_compressBound(size) bytes (locked) */
	unsigned char *temp2; /* encryption buffer, size bytes */
	uint64_t raw_bytes;
	uint64_t allocated_bytes;
} block_t;

#include "index.h"

int block_init(block_t *block, size_t block_size);
void block_free(block_t *block);
int block_append(block_t *block, index_t *index, const unsigned char *data, size_t size);
int block_flush(block_t *block, index_t *index, unsigned char* ref);

int block_ref_length(const unsigned char *ref);

int block_setup(block_t *block, const unsigned char *ref, size_t ref_len);
ssize_t block_read(block_t *block, index_t *index, unsigned char *dst, size_t size);
int block_skip(block_t *block, index_t *index, off_t ofs);

int blksize_check(size_t blksize);
int block_ref_check(const unsigned char *ref, size_t ref_len);

#endif
