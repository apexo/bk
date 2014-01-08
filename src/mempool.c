#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include "mempool.h"
#include "mixed_limits.h"

static int _mempool_grow(mempool_t *mp, size_t length) {
	mempool_area_t *areas = realloc(mp->areas, (mp->num_areas + 1) * sizeof(mempool_area_t));
	if (!areas) {
		perror("out of memory");
		return -1;
	}

	mempool_area_t *area = areas + mp->num_areas;
	memset(area, 0, sizeof(mempool_area_t));
	mp->areas = areas;

	void *addr = mmap(NULL, length, mp->prot, mp->flags, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap failed");
		return -1;
	}

	area->addr = addr;
	area->length = length;
	area->index = 0;
	mp->num_areas++;
	return 0;
}

int mempool_init(mempool_t *mp, size_t align, int locked) {
	memset(mp, 0, sizeof(mempool_t));

	mp->prot = PROT_READ | PROT_WRITE;
	mp->flags = MAP_ANONYMOUS | MAP_PRIVATE;
	if (locked) {
		mp->flags |= MAP_LOCKED;
	}

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("error querying pagesize");
		return -1;
	}
	if (page_size == 0 || page_size > LONG_SIZE_MAX) {
		perror("illegal pagesize");
		return -1;
	}
	mp->page_size = page_size;

	if (align < 1 || align > mp->page_size || (align & (align - 1))) {
		fprintf(stderr, "invalid alignment\n");
		return -1;
	}
	mp->align_mask = align - 1;

#ifdef MULTITHREADED
	if (pthread_mutex_init(&mp->mutex, NULL)) {
		fprintf(stderr, "pthread_mutex_init failed\n");
		return -1;
	}
#endif

	if (_mempool_grow(mp, mp->page_size)) {
		fprintf(stderr, "_mempool_grow failed\n");
		goto err;
	}

	return 0;

err:
#ifdef MULTITHREADED
	if (pthread_mutex_destroy(&mp->mutex)) {
		fprintf(stderr, "pthread_mutex_destroy failed\n");
	}
#endif
	return -1;
}

void *mempool_alloc(mempool_t *mp, size_t size) {
	void* result = NULL;

#ifdef MULTITHREADED
	if (pthread_mutex_lock(&mp->mutex)) {
		fprintf(stderr, "pthread_mutex_lock failed\n");
		return NULL;
	}
#endif

	mempool_area_t *area = mp->areas + mp->num_areas - 1;
	if (size > area->length || area->index > area->length - size) {
		size_t length;
		if (mp->num_areas == 1) {
			length = mp->page_size;
		} else {
			length = mp->areas[mp->num_areas - 2].length + area->length;
		}
		if (size > length) {
			if (size > SIZE_MAX - mp->page_size + 1) {
				fprintf(stderr, "requested size too large\n");
				goto out;
			}
			length = size + (-size) % mp->page_size;
		}
		if (_mempool_grow(mp, length)) {
			fprintf(stderr, "_mempool_grow failed\n");
			goto out;
		}
		area = mp->areas + mp->num_areas - 1;
		assert(size <= area->length && area->index == 0);
	}

	result = area->addr + area->index;
	area->index += size;
	const size_t padding = (-size) & mp->align_mask;
	if (padding < area->length - area->index) {
		area->index += padding;
	} else {
		area->index = area->length;
	}

out:
#ifdef MULTITHREADED
	if (pthread_mutex_unlock(&mp->mutex)) {
		fprintf(stderr, "(in mempool_alloc) pthread_mutex_unlock failed\n");
	}
#endif
	return result;
}

void mempool_free(mempool_t *mp) {
	for (size_t i = 0; i < mp->num_areas; i++) {
		mempool_area_t *area = mp->areas + i;
		if (mp->prot & MAP_LOCKED) {
			memset(area->addr, 0, area->length);
		}
		if (munmap(area->addr, area->length)) {
			fprintf(stderr, "(in mempool_free) munmap failed\n");
		}
	}
	free(mp->areas);

#ifdef MULTITHREADED
	if (pthread_mutex_destroy(&mp->mutex)) {
		fprintf(stderr, "(in mempool_free) pthread_mutex_destroy failed\n");
	}
#endif
}
