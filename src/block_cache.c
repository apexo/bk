#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "block_cache.h"

int block_cache_init(block_cache_t *cache, size_t blksize) {
	memset(cache, 0, sizeof(block_cache_t));
	cache->blksize = blksize;

#ifdef MULTITHREADED
	if (pthread_mutex_init(&cache->mutex, NULL)) {
		perror("pthread_mutex_init failed");
		return -1;
	}

	if (sem_init(&cache->sem, 0, BLOCK_CACHE_MAX_THREADS)) {
		perror("sem_init failed");
		if (pthread_mutex_destroy(&cache->mutex)) {
			perror("pthread_mutex_destroy failed");
		}
		return -1;
	}
#endif

	return 0;
}

static block_t *_block_cache_get(block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off, int *flag) {
	for (size_t i = 0; i < cache->cached; i++) {
		if (cache->ino[i] == ino && cache->off[i] == off) {
			block_t *result = cache->block[i];
			if (i < cache->cached - 1) {
				size_t j = cache->cached - 1;
				cache->block[i] = cache->block[j];
				cache->ino[i] = cache->ino[j];
				cache->off[i] = cache->off[j];
				cache->block[j] = NULL;
				cache->ino[j] = 0;
				cache->off[j] = 0;
			} else {
				cache->block[i] = NULL;
				cache->ino[i] = 0;
				cache->off[i] = 0;
			}
			cache->cached--;
			*flag = 1;
			return result;
		}
	}

	if (cache->free) {
		size_t i = BLOCK_CACHE_SIZE - (cache->free--);
		block_t *result = cache->block[i];
		cache->block[i] = NULL;
		*flag = 0;
		return result;
	}

	if (cache->allocated < BLOCK_CACHE_SIZE) {
		block_t *new_block = malloc(sizeof(block_t));
		if (block_init(new_block, cache->blksize)) {
			fprintf(stderr, "block_init failed\n");
			free(new_block);
		} else {
			cache->allocated++;
			*flag = 0;
			return new_block;
		}
	}

	if (cache->cached) {
		size_t i = --cache->cached;
		block_t *result = cache->block[i];
		cache->block[i] = NULL;
		cache->ino[i] = 0;
		cache->off[i] = 0;
		*flag = 0;
		return result;
	}

	assert(0); // you're probably leaking blocks
	return NULL;
}

static void _block_cache_put(block_cache_t *cache, block_t *block, uint64_t ino, off_t off) {
	assert(cache->free + cache->cached < cache->allocated);

	if (ino) {
		size_t i = cache->cached++;
		cache->block[i] = block;
		cache->ino[i] = ino;
		cache->off[i] = off;
	} else {
		size_t i = BLOCK_CACHE_SIZE - (++cache->free);
		cache->block[i] = block;
	}
}

block_t *block_cache_get(block_thread_state_t *block_thread_state, block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off) {
	block_t *block = NULL;
#ifdef MULTITHREADED
	if (sem_wait(&cache->sem)) {
		perror("sem_wait failed");
		return NULL;
	}
	if (pthread_mutex_lock(&cache->mutex)) {
		perror("pthread_mutex_lock failed");
		goto post;
	}
#endif
	int match = 0;
	block = _block_cache_get(cache, inode_cache, index, ino, off, &match);

#ifdef MULTITHREADED
	if (pthread_mutex_unlock(&cache->mutex)) {
		perror("pthread_mutex_unlock failed");
		goto post;
	}
#endif

	if (!block) {
		fprintf(stderr, "_block_cache_get failed\n");
		goto post;
	}

	if (match) {
		return block;
	}

	const inode_t *inode = inode_cache_lookup(inode_cache, ino);
	if (!inode) {
		fprintf(stderr, "inode_cache_lookup failed\n");
		goto post;
	}

	if (block_setup(block, inode->ref, inode->ref_len)) {
		fprintf(stderr, "block_setup failed\n");
		goto post;
	}

	if (off > 0 && block_skip(block_thread_state, block, index, off) <= 0) {
		fprintf(stderr, "block_skip failed\n");
		goto post;
	}

	return block;

post:
#ifdef MULTITHREADED
	if (block) {
		_block_cache_put(cache, block, 0, 0);
	}
	if (sem_post(&cache->sem)) {
		perror("sem_post failed");
	}
#endif
	return NULL;
}

void block_cache_put(block_cache_t *cache, block_t *block, uint64_t ino, off_t off) {
	assert(block);

#ifdef MULTITHREADED
	if (pthread_mutex_lock(&cache->mutex)) {
		perror("(in block_cache_put) pthread_mutex_lock failed");
	}
#endif

	_block_cache_put(cache, block, ino, off);

#ifdef MULTITHREADED
	if (pthread_mutex_unlock(&cache->mutex)) {
		perror("(in block_cache_put) pthread_mutex_unlock failed");
	}
#endif

#ifdef MULTITHREADED
	if (sem_post(&cache->sem)) {
		perror("(in block_cache_get) sem_post failed");
	}
#endif
}

void block_cache_free(block_cache_t *cache) {
	assert(cache->free + cache->cached == cache->allocated);
	for (size_t i = 0; i < cache->cached; i++) {
		block_free(cache->block[i]);
		free(cache->block[i]);
	}
	cache->cached = 0;

	for (size_t i = BLOCK_CACHE_SIZE - cache->free; i < BLOCK_CACHE_SIZE; i++) {
		block_free(cache->block[i]);
		free(cache->block[i]);
	}
	cache->free = 0;

#ifdef MULTITHREADED
	if (pthread_mutex_destroy(&cache->mutex)) {
		perror("(in block_cache_free) pthread_mutex_destroy failed");
	}
	if (sem_destroy(&cache->sem)) {
		perror("(in block_cache_free) sem_destroy failed");
	}
#endif
}
