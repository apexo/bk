#ifndef BK_BLOCK_CACHE_H
#define BK_BLOCK_CACHE_H

#include "types.h"

int block_cache_init(block_cache_t *cache, size_t block_size);
block_t *block_cache_get(block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off, size_t *cache_index);
void block_cache_put(block_cache_t *cache, size_t index, uint64_t ino, off_t off);
void block_cache_free(block_cache_t *cache);

#endif
