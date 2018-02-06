#ifndef BK_BLOCK_H
#define BK_BLOCK_H

#include <openssl/evp.h>

#include <fcntl.h>
#include <stdint.h>

#define MAX_INDIRECTION 4

typedef struct block_thread_state {
	char* pack; // packSize bytes, in locked memory
	char* crypt; // blksize
	size_t packSize;  // compress_bound(blksize)
	int compression;
	EVP_CIPHER_CTX *cipher_context;
} block_thread_state_t;

typedef struct block {
	size_t blksize;
	uint32_t idx_blksize;
	size_t indirection;
	size_t len[MAX_INDIRECTION + 1];
	size_t idx[MAX_INDIRECTION + 1];
	size_t limit[MAX_INDIRECTION + 1];
	char *data[MAX_INDIRECTION + 1]; /* decrypted data & indirection buffer (locked) */
	uint64_t raw_bytes;
	uint64_t allocated_bytes;
} block_t;

#include "index.h"

int block_init(block_t *block, size_t block_size);
void block_free(block_t *block);
int block_append(block_thread_state_t *block_thread_state, block_t *block, index_t *index, const char *data, size_t size);
int block_flush(block_thread_state_t *block_thread_state, block_t *block, index_t *index, char* ref, int force_indirection);

size_t block_ref_length(const char *ref);

int block_setup(block_t *block, const char *ref, size_t ref_len);
ssize_t block_read(block_thread_state_t *block_thread_state, block_t *block, index_t *index, char *dst, size_t size);
int block_skip(block_thread_state_t *block_thread_state, block_t *block, index_t *index, off_t ofs);
int block_stats(block_thread_state_t *block_thread_state, block_t *block, index_t *index, ondiskidx_t *rootidx, uint64_t *allocated_bytes);

int blksize_check(size_t blksize);
int block_ref_check(const char *ref, size_t ref_len);

#endif
