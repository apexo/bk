#define _BSD_SOURCE
#define _LARGEFILE64_SOURCE
#define __STDC_LIMIT_MACROS

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

int _index_fib_grow(index_t *index, size_t limit);

int index_init(index_t *index, const unsigned char *salt, size_t salt_len) {
	memset(index, 0, sizeof(index_t));
	index->next_ino = 2; // in FUSE, 0 is invalid and 1 is reserved for the root
	if (_index_fib_grow(index, 1)) {
		return -1;
	}
	if (_index_fib_grow(index, 1)) {
		return -1;
	}
	SHA256_Init(&index->encryption_key_context);
	SHA256_Update(&index->encryption_key_context, salt, salt_len);
	SHA256_Init(&index->storage_key_context);
	return 0;
}

int index_free(index_t *index) {
	for (size_t i = 0; i < index->num_references; i++) {
		const size_t num_pages = (index->references[i].limit + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE;

		if (munmap(index->references[i].pages, num_pages * PAGE_SIZE)) {
			perror("error unmapping index");
			return -1;
		}
	}

	index->references = (index_range_t*)realloc(index->references, 0);
	index->ref_data_fd = (int*)realloc(index->ref_data_fd, 0);
	index->num_references = 0;

	for (size_t i = 0; i < index->num_fibidx; i++) {
		free((void*)index->fibidx[i].pages);
	}

	index->fibidx = (index_range_t*)realloc(index->fibidx, 0);
	index->data_fd = 0;
	index->num_fibidx = 0;

	return 0;
}

int index_add_reference(index_t *index, int index_fd, int data_fd) {
	const size_t nr = index->num_references;
	const off64_t idx_size = lseek64(index_fd, 0, SEEK_END);
	if (idx_size == (off64_t)-1) {
		perror("error seeking to end of index");
		return -1;
	}

	if (idx_size < PAGE_SIZE) {
		perror("invalid index: must contain at least one page");
		return -1;
	}

	if (idx_size > SIZE_MAX) {
		perror("index too large (exceeds SIZE_MAX)");
		return -1;
	}

	int *ref_data_fd = (int*)realloc(index->ref_data_fd, (nr + 1) * sizeof(int));
	if (!ref_data_fd) {
		perror("out of memory adding index reference");
	}
	index->ref_data_fd = ref_data_fd;

	index_range_t *references = (index_range_t*)realloc(index->references, (nr + 1) * sizeof(index_range_t));
	if (!references) {
		perror("out of memory adding index reference");
	}
	index->references = references;

	void *data = mmap(NULL, (size_t)idx_size, PROT_READ, MAP_PRIVATE, index_fd, 0);
	if (data == MAP_FAILED) {
		perror("failed to mmap index");
		return -1;
	}

	ref_data_fd[nr] = data_fd;

	index_page_t* pages = (index_page_t*)data;
	const size_t num_full_pages = (idx_size - PAGE_SIZE) / PAGE_SIZE;
	const index_page_t* last_page = pages + num_full_pages;
	const size_t num_entries = num_full_pages * ENTRIES_PER_PAGE + last_page->header.num_entries;
	
	references[nr].pages = pages;
	references[nr].num_entries = num_entries;
	references[nr].limit = num_entries;
	index->num_references++;

	return 0;
}

int _index_fib_grow(index_t *index, size_t limit) {
	const size_t nf = index->num_fibidx;
	index_range_t *fibidx = (index_range_t*)realloc(index->fibidx, (nf + 1) * sizeof(index_range_t));
	if (!fibidx) {
		perror("out of memory");
		return -1;
	}
	index->fibidx = fibidx;

	if (limit > SIZE_MAX - ENTRIES_PER_PAGE + 1) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	const size_t num_pages = (limit + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE;
	if (num_pages > SIZE_MAX / PAGE_SIZE) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	fibidx[nf].num_entries = 0;
	fibidx[nf].limit = limit;
	fibidx[nf].pages = (index_page_t*)malloc(num_pages * PAGE_SIZE);
	if (!fibidx[nf].pages) {
		perror("out of memory");
		return -1;
	}
	memset(fibidx[nf].pages, 0, num_pages * PAGE_SIZE);
	index->num_fibidx++;

	return 0;
}

void _index_range_merge(index_range_t *dst, index_range_t *src1, index_range_t *src2) {
	index_page_t *ps1 = src1->pages, *ps2 = src2->pages, *pd = dst->pages;
	size_t n1 = src1->num_entries, n2 = src2->num_entries, ips1 = 0, ips2 = 0, ipd = 0;

	while (n1 && n2) {
		if (memcmp(ps1->key[ips1], ps2->key[ips2], BLOCK_KEY_SIZE) < 0) {
			memcpy(pd->key[ipd], ps1->key[ips1], BLOCK_KEY_SIZE);
			pd->file_offset[ipd] = ps1->file_offset[ips1];
			pd->block_size[ipd] = ps1->block_size[ips1];
			pd->compressed_block_size[ipd] = ps1->compressed_block_size[ips1];

			n1--;
			if (++ips1 == ENTRIES_PER_PAGE) {
				ips1 = 0;
				ps1++;
			}
		} else {
			memcpy(pd->key[ipd], ps2->key[ips2], BLOCK_KEY_SIZE);
			pd->file_offset[ipd] = ps2->file_offset[ips2];
			pd->block_size[ipd] = ps2->block_size[ips2];
			pd->compressed_block_size[ipd] = ps2->compressed_block_size[ips2];

			n2--;
			if (++ips2 == ENTRIES_PER_PAGE) {
				ips2 = 0;
				ps2++;
			}
		}

		if (++ipd == ENTRIES_PER_PAGE) {
			ipd = 0;
			pd++;
		}
	}

	while (n1) {
		memcpy(pd->key[ipd], ps1->key[ips1], BLOCK_KEY_SIZE);
		pd->file_offset[ipd] = ps1->file_offset[ips1];
		pd->block_size[ipd] = ps1->block_size[ips1];
		pd->compressed_block_size[ipd] = ps1->compressed_block_size[ips1];

		n1--;
		if (++ips1 == ENTRIES_PER_PAGE) {
			ips1 = 0;
			ps1++;
		}

		if (++ipd == ENTRIES_PER_PAGE) {
			ipd = 0;
			pd++;
		}
	}

	while (n2) {
		memcpy(pd->key[ipd], ps2->key[ips2], BLOCK_KEY_SIZE);
		pd->file_offset[ipd] = ps2->file_offset[ips2];
		pd->block_size[ipd] = ps2->block_size[ips2];
		pd->compressed_block_size[ipd] = ps2->compressed_block_size[ips2];

		n2--;
		if (++ips2 == ENTRIES_PER_PAGE) {
			ips2 = 0;
			ps2++;
		}

		if (++ipd == ENTRIES_PER_PAGE) {
			ipd = 0;
			pd++;
		}
	}

	dst->num_entries = src1->num_entries + src2->num_entries;
	src1->num_entries = 0;
	src2->num_entries = 0;

	/*
	for (size_t j = 1; j < dst->num_entries; j++) {
		const size_t i = j - 1;
		if (memcmp(
			dst->pages[i / ENTRIES_PER_PAGE].key[i % ENTRIES_PER_PAGE],
			dst->pages[j / ENTRIES_PER_PAGE].key[j % ENTRIES_PER_PAGE],
			BLOCK_KEY_SIZE) >= 0) {
			assert(0);
		}
	}
	*/
}

int index_add_block(index_t *index, block_key_t block_key, file_offset_t file_offset, block_size_t block_size, block_size_t compressed_block_size) {
	assert(compressed_block_size && compressed_block_size <= block_size);

	size_t nf = index->num_fibidx;
	index_range_t *fibidx = index->fibidx;

	size_t idx = fibidx[1].num_entries ? 0 : 1;
	index_page_t *page = fibidx[idx].pages;

	memcpy(page->key[0], block_key, BLOCK_KEY_SIZE);
	page->file_offset[0] = htobe64(file_offset);
	page->block_size[0] = htobe32(block_size);
	page->compressed_block_size[0] = htobe32(compressed_block_size);
	fibidx[idx].num_entries = 1;

	while (idx + 1 < nf && fibidx[idx].num_entries && fibidx[idx + 1].num_entries) {
		if (idx + 2 == nf) {
			if (_index_fib_grow(index, fibidx[idx].limit + fibidx[idx + 1].limit)) {
				fprintf(stderr, "_index_fib_grow failed\n");
				return -1;
			}
			fibidx = index->fibidx;
			nf = index->num_fibidx;
		}

		assert(fibidx[idx].num_entries == fibidx[idx].limit);
		assert(fibidx[idx+1].num_entries == fibidx[idx+1].limit);
		assert(!fibidx[idx+2].num_entries);
		assert(fibidx[idx+2].limit == fibidx[idx].limit + fibidx[idx+1].limit);

		// printf("(auto) merging %d and %d -> %d\n", idx, idx+1, idx+2);
		_index_range_merge(fibidx+(idx+2), fibidx+(idx+1), fibidx+idx);
		idx += 2;
	}

	return 0;
}

typedef uint32_t lookup_key_t;
#define LOOKUP_KEY(v) be32toh(*(uint32_t*)(v))
#define LOOKUP_KEY_MIN 0
#define LOOKUP_KEY_MAX UINT32_MAX

int _index_range_lookup(index_range_t *range, block_key_t key, size_t *ret_pagenum, size_t *ret_pageidx) {
	const index_page_t *pages = range->pages;
	const lookup_key_t nk = LOOKUP_KEY(key);
	lookup_key_t nl = LOOKUP_KEY_MIN, nr = LOOKUP_KEY_MAX;
	size_t leftIdx = 0, rightIdx = range->num_entries, n = rightIdx;

	while (n) {
		assert(nl <= nk);
		assert(nk <= nr);
		assert(nl < nr);

		const size_t idx = (n - 1) * (uint64_t)(nk - nl) / (nr - nl) + leftIdx;

		//fprintf(stderr, "lookup %8x - %8x - %8x / %d - %d - %d [%d]\n", nl, nk, nr, leftIdx, idx, rightIdx, n);

		assert(leftIdx <= idx);
		assert(idx < rightIdx);

		const size_t pagenum = idx / ENTRIES_PER_PAGE;
		const size_t pageidx = idx % ENTRIES_PER_PAGE;
		const unsigned char *key2 = pages[pagenum].key[pageidx];

		const int p = memcmp(key2, key, BLOCK_KEY_SIZE);

		if (p < 0) {
			leftIdx = idx + 1;
			nl = LOOKUP_KEY(key2);
		} else if (p > 0) {
			rightIdx = idx;
			nr = LOOKUP_KEY(key2);
		} else { // p == 0
			*ret_pagenum = pagenum;
			*ret_pageidx = pageidx;
			//fprintf(stderr, "lookup success: %d / %d\n", pagenum, pageidx);
			return 0;
		}

		n = rightIdx - leftIdx;
	}

	//fprintf(stderr, "lookup fail\n");
	return -1;
}

int _index_range_write(index_range_t *index, int fd, size_t block_size) {
	index_page_t *page = index->pages;
	size_t remaining = index->num_entries;

	if (block_size > UINT32_MAX) {
		fprintf(stderr, "block size out of bounds\n");
		return -1;
	}

	while (1) {
		const size_t n = remaining >= ENTRIES_PER_PAGE ? ENTRIES_PER_PAGE : remaining;
		memcpy(page->header.magic, MAGIC, strlen(MAGIC) + 1);
		page->header.num_entries = n;
		page->header.block_size = block_size;
		const ssize_t bytes_written = write(fd, page, PAGE_SIZE);
		if (bytes_written < PAGE_SIZE) {
			perror("error writing index - disk full?");
			return -1;
		}
		remaining -= n;
		if (!remaining) {
			return 0;
		}
		page++;
	}
}

int index_write(index_t *index, int fd, size_t block_size) {
	index_range_t *fibidx = index->fibidx;
	size_t nf = index->num_fibidx;
	size_t the_real_index = 0;
	for (size_t i1 = 0; i1 < nf; i1++) {
		if (fibidx[i1].num_entries) {
			the_real_index = i1;

			for (size_t i2 = i1 + 1; i2 < nf; i2++) {
				if (fibidx[i2].num_entries) {
					if (i2 == nf - 1) {
						if (_index_fib_grow(index, fibidx[i1].num_entries + fibidx[i2].num_entries)) {
							perror("error merging index");
							return -1;
						}

						fibidx = index->fibidx;
						nf = index->num_fibidx;
					}

					assert(!fibidx[i2+1].num_entries);
					assert(fibidx[i2+1].limit >= fibidx[i1].num_entries + fibidx[i2].num_entries);

					_index_range_merge(fibidx+(i2+1), fibidx+i2, fibidx+i1);
					the_real_index = i2 + 1;
					break;
				}
			}

		}
	}

	// assert(fibidx[the_real_index].num_entries);

	fprintf(stderr, "writing out %zd entries from index %zd\n", fibidx[the_real_index].num_entries, the_real_index);
	if (_index_range_write(fibidx + the_real_index, fd, block_size)) {
		perror("error writing index");
		return -1;
	}

	return 0;
}

int index_lookup(index_t *index, block_key_t key, int *data_fd, file_offset_t *file_offset, block_size_t *block_size, block_size_t *compressed_block_size) {
	index_page_t *page;
	size_t pagenum, pageidx;

	for (size_t i = 0; i < index->num_references; i++) {
		if (!_index_range_lookup(index->references + i, key, &pagenum, &pageidx)) {
			*data_fd = index->ref_data_fd[i];
			page = index->references[i].pages + pagenum;
			goto ok;
		}
	}

	for (size_t i = 0; i < index->num_fibidx; i++) {
		if (!_index_range_lookup(index->fibidx + i, key, &pagenum, &pageidx)) {
			*data_fd = index->data_fd;
			page = index->fibidx[i].pages + pagenum;
			goto ok;
		}
	}

	return -1;

	ok:
	*file_offset = be64toh(page->file_offset[pageidx]);
	*block_size = be32toh(page->block_size[pageidx]);
	*compressed_block_size = be32toh(page->compressed_block_size[pageidx]);
	return 0;
}

void index_alloc_ino(index_t *index, uint64_t *ino) {
	*ino = index->next_ino++;
}
