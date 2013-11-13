#ifndef BK_MEMPOOL_H
#define BK_MEMPOOL_H

typedef struct mempool_area {
	void *addr;
	size_t length;
	size_t index;
} mempool_area_t;

typedef struct mempool {
	size_t num_areas;
	mempool_area_t *areas;
	size_t align_mask;
	long page_size;
	int prot;
	int flags;
} mempool_t;

int mempool_init(mempool_t *mp, size_t align, int locked);
void *mempool_alloc(mempool_t *mp, size_t size);
void mempool_free(mempool_t *mp);

#endif
