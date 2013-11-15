#ifndef BK_BLOCK_CACHE_H
#define BK_BLOCK_CACHE_H

#ifdef MULTITHREADED
#include <pthread.h>
#include <semaphore.h>
#endif

#include "inode_cache.h"
#include "index.h"
#include "block.h"

#define BLOCK_CACHE_SIZE 20
#define BLOCK_CACHE_MAX_THREADS 10

typedef struct block_cache {
	#ifdef MULTITHREADED
	pthread_mutex_t mutex;
	sem_t sem;
	#endif
	size_t allocated;
	size_t free;
	size_t cached;
	size_t blksize;

	uint64_t ino[BLOCK_CACHE_SIZE];
	off_t off[BLOCK_CACHE_SIZE];
	block_t *block[BLOCK_CACHE_SIZE];
} block_cache_t;

int block_cache_init(block_cache_t *cache, size_t blksize);
block_t *block_cache_get(block_thread_state_t *block_thread_state, block_cache_t *cache, inode_cache_t *inode_cache, index_t *index, uint64_t ino, off_t off);
void block_cache_put(block_cache_t *cache, block_t *block, uint64_t ino, off_t off);
void block_cache_free(block_cache_t *cache);

#endif
