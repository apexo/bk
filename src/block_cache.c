#include <stdio.h>
#include <assert.h>

#include "block_cache.h"

int block_cache_init(block_cache_t *cache, size_t block_size) {
	cache->next = 0;
	for (size_t i = 0; i < BLOCK_CACHE_SIZE; i++) {
		cache->ino[i] = 0;
		cache->off[i] = 0;
		if (block_init(cache->block + i, block_size)) {
			fprintf(stderr, "block_cache_init failed\n");
			return -1;
		}
	}
	return 0;
}

block_t *block_cache_get(block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off, size_t *cache_index) {
	for (size_t i = 0; i < BLOCK_CACHE_SIZE; i++) {
		if (cache->ino[i] == ino && cache->off[i] == off) {
			*cache_index = i;
			cache->ino[i] = 0;
			cache->off[i] = 0;
			return cache->block + i;
		}
	}

	const inode_t *inode = inode_cache_lookup(inode_cache, ino);
	if (!inode) {
		fprintf(stderr, "inode_cache_lookup failed\n");
		return NULL;
	}

	size_t idx = cache->next;
	block_t *block = cache->block + idx;

	if (block_setup(block, inode->ref, inode->ref_len)) {
		cache->ino[idx] = 0;
		fprintf(stderr, "block_setup failed\n");
		return NULL;
	}

	if (off > 0) {
		int res = block_skip(block, index, off);
		if (res <= 0) {
			cache->ino[idx] = 0;
			fprintf(stderr, "block_skip failed\n");
			return NULL;
		}
	}

	*cache_index = idx;
	cache->ino[idx] = 0;
	cache->off[idx] = 0;
	cache->next = (idx + 1) % BLOCK_CACHE_SIZE;

	return block;
}

void block_cache_put(block_cache_t *cache, size_t cache_index, uint64_t ino, off_t off) {
	assert(0 <= cache_index && cache_index < BLOCK_CACHE_SIZE);
	cache->ino[cache_index] = ino;
	cache->off[cache_index] = off;
}

void block_cache_free(block_cache_t *cache) {
	for (size_t i = 0; i < BLOCK_CACHE_SIZE; i++) {
		block_free(cache->block + i);
	}
}

