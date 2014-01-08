#ifndef BK_MEMPOOL_H
#define BK_MEMPOOL_H

#ifdef MULTITHREADED
#include <pthread.h>
#endif

typedef struct mempool_area {
	void *addr;
	size_t length;
	size_t index;
} mempool_area_t;

typedef struct mempool {
	size_t num_areas;
	mempool_area_t *areas;
	size_t align_mask;
	size_t page_size;
	int prot;
	int flags;
#ifdef MULTITHREADED
	pthread_mutex_t mutex;
#endif
} mempool_t;

int mempool_init(mempool_t *mp, size_t align, int locked);
void *mempool_alloc(mempool_t *mp, size_t size);
void mempool_free(mempool_t *mp);

#endif
