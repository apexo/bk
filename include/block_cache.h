#ifndef BK_BLOCK_CACHE_H
#define BK_BLOCK_CACHE_H

#include "inode_cache.h"
#include "index.h"
#include "block.h"

#define BLOCK_CACHE_SIZE 4

typedef struct block_cache {
	size_t next;
	uint64_t ino[BLOCK_CACHE_SIZE];
	off_t off[BLOCK_CACHE_SIZE];
	block_t block[BLOCK_CACHE_SIZE];
} block_cache_t;

int block_cache_init(block_cache_t *cache, size_t block_size);
block_t *block_cache_get(block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off, size_t *cache_index);
void block_cache_put(block_cache_t *cache, size_t index, uint64_t ino, off_t off);
void block_cache_free(block_cache_t *cache);

#endif
