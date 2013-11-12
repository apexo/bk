#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "types.h"
#include "block.h"
#include "index.h"

static int _index_workidx_grow(index_t *index, size_t limit);

int index_init(index_t *index, int readonly, const unsigned char *salt, size_t salt_len) {
	assert(sizeof(index_header_t) == PAGE_SIZE);
	assert(sizeof(index_page_t) == PAGE_SIZE);

	memset(index, 0, sizeof(index_t));

	SHA256_Init(&index->storage_key_context);

	if (readonly) {
		return 0;
	}

	index->next_ino = 2; // in FUSE, 0 is invalid and 1 is reserved for the root
	if (_index_workidx_grow(index, 1)) {
		return -1;
	}
	if (_index_workidx_grow(index, 1)) {
		return -1;
	}
	SHA256_Init(&index->encryption_key_context);
	SHA256_Update(&index->encryption_key_context, salt, salt_len);

	memcpy(index->header.magic, MAGIC, strlen(MAGIC) + 1);
	index->header.version = be32toh(VERSION);
	return 0;
}

int index_set_blksize(index_t *index, block_size_t blksize) {
	if (blksize_check(blksize)) {
		fprintf(stderr, "illegal blksize\n");
		return -1;
	}
	index->blksize = blksize;
	index->header.blksize = be32toh(blksize);
	return 0;
}


static int _index_ondiskidx_alloc(ondiskidx_t *ondiskidx, size_t num_entries) {
	memset(ondiskidx, 0, sizeof(ondiskidx_t));

	if (num_entries > SIZE_MAX - 7) {
		fprintf(stderr, "index too big\n");
		return -1;
	}
	size_t bitmap_size = (num_entries + 7) / 8;
	uint8_t *bitmap = malloc(bitmap_size);
	if (!bitmap) {
		perror("out of memory");
		return -1;
	}
	memset(bitmap, 0, bitmap_size);
	ondiskidx->used = bitmap;
	return 0;
}

int index_ondiskidx_add(index_t *index, int index_fd, int data_fd) {
	ondiskidx_t* ondiskidx = realloc(index->ondiskidx, sizeof(ondiskidx_t)*(index->num_ondiskidx+1));
	if (!ondiskidx) {
		perror("out of memory");
		return -1;
	}
	index->ondiskidx = ondiskidx;
	ondiskidx += index->num_ondiskidx;

	const off64_t idx_size = lseek64(index_fd, 0, SEEK_END);
	if (idx_size == (off64_t)-1) {
		perror("lseek64 failed");
		return -1;
	}

	if (idx_size < PAGE_SIZE) {
		perror("invalid index: must contain at least one page");
		return -1;
	}

	if (idx_size > SIZE_MAX) {
		fprintf(stderr, "index too large\n");
		return -1;
	}

	void *data = mmap(NULL, (size_t)idx_size, PROT_READ, MAP_PRIVATE, index_fd, 0);
	if (data == MAP_FAILED) {
		perror("failed to mmap index");
		return -1;
	}

	const index_header_t *header = (index_header_t*)data;

	if (memcmp(header->magic, MAGIC, strlen(MAGIC)+1)) {
		fprintf(stderr, "invalid index magic\n");
		goto err;
	}

	if (be32toh(header->version) != VERSION) {
		fprintf(stderr, "unsupported index version\n");
		goto err;
	}

	const size_t num_idx_pages = (idx_size - PAGE_SIZE) / PAGE_SIZE;
	const size_t num_entries = be64toh(header->num_entries);
	const size_t max_entries = num_idx_pages * ENTRIES_PER_PAGE;
	const size_t min_entries = max_entries ? max_entries - ENTRIES_PER_PAGE + 1 : 0;

	if (num_entries < min_entries || num_entries > max_entries) {
		fprintf(stderr, "illegal num_entries: %zd; expected %zd-%zd (based on the index size)\n", num_entries, min_entries, max_entries);
		goto err;
	}

	const block_size_t blksize = be32toh(header->blksize);

	if (blksize_check(blksize)) {
		fprintf(stderr, "blksize_check failed (%d)\n", blksize);
		goto err;
	}

	if (_index_ondiskidx_alloc(ondiskidx, num_entries)) {
		fprintf(stderr, "_index_ondiskidx_alloc failed\n");
		goto err;
	}

	ondiskidx->range.num_entries = num_entries;
	ondiskidx->range.limit = num_entries;
	ondiskidx->range.pages = (index_page_t*)(data + PAGE_SIZE);
	ondiskidx->size = idx_size;
	ondiskidx->header = header;
	ondiskidx->data_fd = data_fd;
	ondiskidx->blksize = blksize;

	index->num_ondiskidx++;
	return 0;

err:
	if (munmap(data, idx_size)) {
		perror("munmap failed");
	}
	return -1;
}

int index_free(index_t *index) {
	for (size_t i = 0; i < index->num_ondiskidx; i++) {
		if (munmap((void*)index->ondiskidx[i].header, index->ondiskidx[i].size)) {
			perror("(in index_free) error unmapping index");
		}

		free(index->ondiskidx[i].used);

		if (index->ondiskidx[i].data_fd) {
			if (close(index->ondiskidx[i].data_fd)) {
				perror("(in index_free) close failed");
			}
		}
	}

	if (index->ondiskidx) {
		free(index->ondiskidx);
		index->ondiskidx = NULL;
	}
	index->num_ondiskidx = 0;

	for (size_t i = 0; i < index->num_workidx; i++) {
		free((void*)index->workidx[i].pages);
	}

	if (index->workidx) {
		free(index->workidx);
		index->workidx = NULL;
	}
	index->num_workidx = 0;

	if (index->data_fd) {
		if (close(index->data_fd)) {
			perror("(in index_free) close failed");
		}
		index->data_fd = 0;
	}

	return 0;
}

static int _index_workidx_grow(index_t *index, size_t limit) {
	const size_t nf = index->num_workidx;
	index_range_t *workidx = (index_range_t*)realloc(index->workidx, (nf + 1) * sizeof(index_range_t));
	if (!workidx) {
		perror("out of memory");
		return -1;
	}
	index->workidx = workidx;

	if (limit > SIZE_MAX - ENTRIES_PER_PAGE + 1) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	const size_t num_pages = (limit + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE;
	if (num_pages > SIZE_MAX / PAGE_SIZE) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	workidx[nf].num_entries = 0;
	workidx[nf].limit = limit;
	workidx[nf].pages = (index_page_t*)malloc(num_pages * PAGE_SIZE);
	if (!workidx[nf].pages) {
		perror("out of memory");
		return -1;
	}
	memset(workidx[nf].pages, 0, num_pages * PAGE_SIZE);
	index->num_workidx++;

	return 0;
}

static void _index_range_merge(index_range_t *dst, index_range_t *src1, index_range_t *src2) {
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

	size_t nf = index->num_workidx;
	index_range_t *workidx = index->workidx;

	size_t idx = workidx[1].num_entries ? 0 : 1;
	index_page_t *page = workidx[idx].pages;

	memcpy(page->key[0], block_key, BLOCK_KEY_SIZE);
	page->file_offset[0] = htobe64(file_offset);
	page->block_size[0] = htobe32(block_size);
	page->compressed_block_size[0] = htobe32(compressed_block_size);
	workidx[idx].num_entries = 1;

	while (idx + 1 < nf && workidx[idx].num_entries && workidx[idx + 1].num_entries) {
		if (idx + 2 == nf) {
			if (_index_workidx_grow(index, workidx[idx].limit + workidx[idx + 1].limit)) {
				fprintf(stderr, "_index_workidx_grow failed\n");
				return -1;
			}
			workidx = index->workidx;
			nf = index->num_workidx;
		}

		assert(workidx[idx].num_entries == workidx[idx].limit);
		assert(workidx[idx+1].num_entries == workidx[idx+1].limit);
		assert(!workidx[idx+2].num_entries);
		assert(workidx[idx+2].limit == workidx[idx].limit + workidx[idx+1].limit);

		// printf("(auto) merging %d and %d -> %d\n", idx, idx+1, idx+2);
		_index_range_merge(workidx+(idx+2), workidx+(idx+1), workidx+idx);
		idx += 2;
	}

	return 0;
}

typedef uint32_t lookup_key_t;
#define LOOKUP_KEY(v) be32toh(*(uint32_t*)(v))
#define LOOKUP_KEY_MIN 0
#define LOOKUP_KEY_MAX UINT32_MAX

static int _index_range_lookup(index_range_t *range, block_key_t key, size_t *ret_pagenum, size_t *ret_pageidx) {
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

#define CHUNK_SIZE (4096*1024)

static void _index_hash(index_t *index, index_range_t *range, size_t num_pages) {
	SHA256_CTX ctx;
	memcpy(&ctx, &(index->storage_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, &index->header, PAGE_SIZE);
	size_t idx_size = num_pages * PAGE_SIZE;
	const char *data = (char*)range->pages;
	while (idx_size) {
		const size_t chunk = idx_size > CHUNK_SIZE ? CHUNK_SIZE : idx_size;
		SHA256_Update(&ctx, data, chunk);
		data += chunk;
		idx_size -= chunk;
	}
	SHA256_Final(index->header.index_hash, &ctx);
}

static int _index_write_header(int fd, index_t *index, index_range_t *range) {
	size_t hdr_size = PAGE_SIZE;
	char *hdr = (char*)&index->header;

	while (hdr_size) {
		const ssize_t bytes_written = write(fd, hdr, hdr_size);
		if (bytes_written < 0) {
			perror("write failed");
			return -1;
		}
		if (!bytes_written) {
			fprintf(stderr, "error writing index - disk full?\n");
			return -1;
		}
		assert(bytes_written <= hdr_size);
		hdr_size -= bytes_written;
		hdr += bytes_written;
	}
	return 0;
}

static int _index_write_data(int fd, index_t *index, index_range_t *range, size_t num_pages) {
	size_t idx_size = num_pages * PAGE_SIZE;
	char *data = (char*)range->pages;

	while (idx_size) {
		const size_t chunk = idx_size > CHUNK_SIZE ? CHUNK_SIZE : idx_size;
		const ssize_t bytes_written = write(fd, data, chunk);
		if (bytes_written < 0) {
			perror("write failed");
			return -1;
		}
		if (!bytes_written) {
			fprintf(stderr, "error writing index - disk full?\n");
			return -1;
		}
		assert(bytes_written <= chunk);
		idx_size -= bytes_written;
		data += bytes_written;
	}
	return 0;
}

static int _index_range_write(index_t *index, index_range_t *range, int fd) {
	if (index->blksize > UINT32_MAX) {
		fprintf(stderr, "block size out of bounds\n");
		return -1;
	}

	index->header.num_entries = be64toh(range->num_entries);
	// TODO: add external references

	if (range->num_entries > SIZE_MAX - ENTRIES_PER_PAGE + 1) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	size_t num_pages = (range->num_entries + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE;

	if (num_pages > SIZE_MAX / PAGE_SIZE) {
		fprintf(stderr, "index too big\n");
		return -1;
	}

	_index_hash(index, range, num_pages);

	if (_index_write_header(fd, index, range)) {
		fprintf(stderr, "_index_write_header failed\n");
		return -1;
	}

	if (_index_write_data(fd, index, range, num_pages)) {
		fprintf(stderr, "_index_write_data failed\n");
		return -1;
	}

	return 0;
}

int index_write(index_t *index, int fd) {
	assert(!blksize_check(index->blksize));

	index_range_t *workidx = index->workidx;
	size_t nf = index->num_workidx;
	size_t the_real_index = 0;
	for (size_t i1 = 0; i1 < nf; i1++) {
		if (workidx[i1].num_entries) {
			the_real_index = i1;

			for (size_t i2 = i1 + 1; i2 < nf; i2++) {
				if (workidx[i2].num_entries) {
					if (i2 == nf - 1) {
						if (_index_workidx_grow(index, workidx[i1].num_entries + workidx[i2].num_entries)) {
							perror("error merging index");
							return -1;
						}

						workidx = index->workidx;
						nf = index->num_workidx;
					}

					assert(!workidx[i2+1].num_entries);
					assert(workidx[i2+1].limit >= workidx[i1].num_entries + workidx[i2].num_entries);

					_index_range_merge(workidx+(i2+1), workidx+i2, workidx+i1);
					the_real_index = i2 + 1;
					break;
				}
			}

		}
	}

	// assert(workidx[the_real_index].num_entries);

	fprintf(stderr, "writing out %zd entries from index %zd\n", workidx[the_real_index].num_entries, the_real_index);
	if (_index_range_write(index, workidx + the_real_index, fd)) {
		perror("error writing index");
		return -1;
	}

	return 0;
}

int index_lookup(index_t *index, block_key_t key, file_offset_t *file_offset, block_size_t *block_size, block_size_t *compressed_block_size, ondiskidx_t **ondiskidx) {
	index_page_t *page;
	size_t pagenum, pageidx;

	for (size_t i = 0; i < index->num_ondiskidx; i++) {
		if (!_index_range_lookup(&(index->ondiskidx + i)->range, key, &pagenum, &pageidx)) {
			*ondiskidx = index->ondiskidx + i;
			page = index->ondiskidx[i].range.pages + pagenum;
			goto ok;
		}
	}

	for (size_t i = 0; i < index->num_workidx; i++) {
		if (!_index_range_lookup(index->workidx + i, key, &pagenum, &pageidx)) {
			*ondiskidx = NULL;
			page = index->workidx[i].pages + pagenum;
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

uint64_t index_alloc_ino(index_t *index) {
	return index->next_ino++;
}
