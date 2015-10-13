#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include "dir_index.h"

#define RANDOM_BYTES 32

static int _dir_index_grow(dir_index_range_t *range, size_t limit) {
	if (limit > SIZE_MAX / sizeof(block_key_t)) {
		fprintf(stderr, "directory too large\n");
		return -1;
	}
	range->key = malloc(sizeof(block_key_t) * limit);
	if (!range->key) {
		perror("out of memory");
		return -1;
	}
	range->ino = malloc(sizeof(uint64_t) * limit);
	if (!range->ino) {
		perror("out of memory");
		free(range->key);
		range->key = NULL;
		return -1;
	}
	return 0;
}

static int _dir_index_seed(dir_index_t *dir_index, mempool_t *mempool) {
	size_t remaining = RANDOM_BYTES, idx = 0;
	ssize_t n;
	while (remaining && (n = read(dir_index->fd_urandom, dir_index->random + idx, remaining))) {
		if (n < 0) {
			perror("read failed");
			return -1;
		}
		assert((size_t)n <= remaining);
		remaining -= n;
		idx += n;
	}
	if (remaining) {
		fprintf(stderr, "could not read enough random bytes\n");
		return -1;
	}

	assert(!dir_index->filename_hash_context);
	dir_index->filename_hash_context = mempool_alloc(mempool, sizeof(SHA256_CTX));
	if (!dir_index->filename_hash_context) {
		fprintf(stderr, "mempool_alloc failed\n");
		return -1;
	}

	SHA256_Init(dir_index->filename_hash_context);
	SHA256_Update(dir_index->filename_hash_context, dir_index->random, RANDOM_BYTES);
	memset(dir_index->random, 0, RANDOM_BYTES);
	return 0;
}

int dir_index_init(dir_index_t *dir_index, mempool_t *mempool) {
	memset(dir_index, 0, sizeof(dir_index_t));
	dir_index->fd_urandom = open("/dev/urandom", O_RDONLY);
	if (dir_index->fd_urandom < 0) {
		perror("open failed");
		fprintf(stderr, "error opening /dev/urandom\n");
		return -1;
	}
	for (size_t i = 0; i < 2; i++) {
		if (_dir_index_grow(dir_index->range + i, 1)) {
			fprintf(stderr, "_dir_index_grow failed\n");
			goto err;
		}
		dir_index->limit[i] = 1;
	}
	dir_index->num_ranges = 2;
	dir_index->temp = mempool_alloc(mempool, sizeof(SHA256_CTX));
	dir_index->random = mempool_alloc(mempool, RANDOM_BYTES);
	if (!dir_index->temp || !dir_index->random) {
		fprintf(stderr, "mempool_alloc failed\n");
		goto err;
	}
	if (_dir_index_seed(dir_index, mempool)) {
		fprintf(stderr, "_dir_index_seed failed\n");
		goto err;
	}
	return 0;

err:
	dir_index_free(dir_index);
	return -1;
}

/*
 * caller must assure that  capacity ("limit") is large enough for (or probably equal to) src1->num_entries + src2->num-entries
 */
static void _dir_index_range_merge(dir_index_range_t *dst, dir_index_range_t *src1, dir_index_range_t *src2) {
	const size_t n1 = src1->num_entries, n2 = src2->num_entries;
	size_t is1 = 0, is2 = 0, id = 0;

	while (is1 < n1 && is2 < n2) {
		if (memcmp(src1->key[is1], src2->key[is2], BLOCK_KEY_SIZE) < 0) {
			memcpy(dst->key[id], src1->key[is1], BLOCK_KEY_SIZE);
			dst->ino[id++] = src1->ino[is1++];
		} else {
			memcpy(dst->key[id], src2->key[is2], BLOCK_KEY_SIZE);
			dst->ino[id++] = src2->ino[is2++];
		}
	}

	while (is1 < n1) {
		memcpy(dst->key[id], src1->key[is1], BLOCK_KEY_SIZE);
		dst->ino[id++] = src1->ino[is1++];
	}

	while (is2 < n2) {
		memcpy(dst->key[id], src2->key[is2], BLOCK_KEY_SIZE);
		dst->ino[id++] = src2->ino[is2++];
	}

	dst->num_entries = src1->num_entries + src2->num_entries;
	src1->num_entries = 0;
	src2->num_entries = 0;
}

int dir_index_add(dir_index_t *dir_index, const char *name, size_t name_len, uint64_t ino) {
	memcpy(dir_index->temp, dir_index->filename_hash_context, sizeof(SHA256_CTX));
	SHA256_Update(dir_index->temp, name, name_len);

	dir_index_range_t *range = dir_index->range;

	size_t idx = range[1].num_entries ? 0 : 1;
	SHA256_Final((unsigned char*)range[idx].key[0], dir_index->temp);
	range[idx].ino[0] = ino;
	range[idx].num_entries = 1;

	while (idx + 1 < dir_index->num_ranges && range[idx].num_entries && range[idx + 1].num_entries) {
		if (idx + 2 == DIR_RANGES) {
			fprintf(stderr, "directory too large\n");
			return -1;
		}
		if (!dir_index->limit[idx+2]) {
			assert(dir_index->limit[idx+1] <= SIZE_MAX - dir_index->limit[idx]);
			dir_index->limit[idx+2] = dir_index->limit[idx+1] + dir_index->limit[idx];
			if (_dir_index_grow(range+idx+2, dir_index->limit[idx+2])) {
				fprintf(stderr, "_dir_index_grow failed\n");
				return -1;
			}
		}

		assert(range[idx].num_entries == dir_index->limit[idx]);
		assert(range[idx+1].num_entries == dir_index->limit[idx+1]);
		assert(!range[idx+2].num_entries);
		assert(dir_index->limit[idx+2] == dir_index->limit[idx] + dir_index->limit[idx+1]);

		_dir_index_range_merge(range+idx+2, range+idx+1, range+idx);

		if (idx + 2 == dir_index->num_ranges) {
			dir_index->num_ranges++;
		}

		idx += 2;
	}

	return 0;
}

dir_index_range_t *dir_index_merge(dir_index_t* dir_index, mempool_t *mempool) {
	dir_index_range_t *result = calloc(1, sizeof(dir_index_range_t));
	if (!result) {
		perror("out of memory");
		return NULL;
	}

	dir_index_range_t *range = dir_index->range;

	size_t i1 = 0;
	while (i1 < dir_index->num_ranges - 1) {
		if (range[i1].num_entries) {
			size_t i2 = i1 + 1;
			while (i2 < dir_index->num_ranges && !range[i2].num_entries) {
				i2++;
			}
			if (i2 >= dir_index->num_ranges) {
				break;
			} else if (i2 == dir_index->num_ranges - 1) {
				// last possible merge: merge directly into result buffer
				if (_dir_index_grow(result, range[i1].num_entries + range[i2].num_entries)) {
					fprintf(stderr, "_dir_index_grow failed\n");
					free(result);
					return NULL;
				}
				_dir_index_range_merge(result, range+i2, range+i1);
				goto seed;
			} else {  // i2 < dir_index->num_range - 1
				// intermediate merge, there's more to come
				_dir_index_range_merge(range+i2+1, range+i2, range+i1);
				i1 = i2+1;
			}
		} else {
			i1++;
		}
	}

	// when we reach here: there's only one populated range (num_ranges - 1) or it's all empty
	assert(i1 == dir_index->num_ranges-1);
	if (!range[i1].num_entries) {
		// TODO: empty directory: this could probably be optimized a bit
		goto seed;
	}

	result->num_entries = range[i1].num_entries;

	if (i1 < 2) {
		// the first two ranges must always be there
		if (_dir_index_grow(result, range[i1].num_entries)) {
			free(result);
			return NULL;
		}
		memcpy(result->key, range[i1].key, sizeof(block_key_t)*range[i1].num_entries);
		memcpy(result->ino, range[i1].ino, sizeof(uint64_t)*range[i1].num_entries);
	} else {
		// we can steal the others
		result->key = range[i1].key;
		result->ino = range[i1].ino;
		range[i1].key = NULL;
		range[i1].ino = NULL;
		dir_index->limit[i1] = 0;
	}

	range[i1].num_entries = 0;

seed:
	dir_index->num_ranges = 2;

	result->filename_hash_context = dir_index->filename_hash_context;
	dir_index->filename_hash_context = NULL;
	if (_dir_index_seed(dir_index, mempool)) {
		fprintf(stderr, "_dir_index_seed failed\n");
		dir_index_range_free(result);
		return NULL;
	}
	return result;
}

void dir_index_free(dir_index_t *dir_index) {
	for (size_t i = 0; i < DIR_RANGES; i++) {
		if (dir_index->range[i].key) {
			free(dir_index->range[i].key);
		}
		if (dir_index->range[i].ino) {
			free(dir_index->range[i].ino);
		}
	}
}

typedef uint32_t lookup_key_t;
#define LOOKUP_KEY(v) be32toh(*(uint32_t*)(v))
#define LOOKUP_KEY_MIN 0
#define LOOKUP_KEY_MAX UINT32_MAX

uint64_t dir_index_range_lookup(dir_index_range_t* range, lookup_temp_t *temp, const char *name, size_t name_len) {
	memcpy(&temp->ctx, range->filename_hash_context, sizeof(SHA256_CTX));
	SHA256_Update(&temp->ctx, name, name_len);
	block_key_t key;
	SHA256_Final((unsigned char*)key, &temp->ctx);
	const char *key_t = key;

	const lookup_key_t nk = LOOKUP_KEY(key_t);
	lookup_key_t nl = LOOKUP_KEY_MIN, nr = LOOKUP_KEY_MAX;
	size_t leftIdx = 0, rightIdx = range->num_entries, n = rightIdx;

	while (n) {
		assert(nl <= nk);
		assert(nk <= nr);
		assert(nl < nr);

		const size_t idx = (n - 1) * (uint64_t)(nk - nl) / (nr - nl) + leftIdx;

		assert(leftIdx <= idx);
		assert(idx < rightIdx);

		const char *key2 = range->key[idx];

		const int p = memcmp(key2, key, BLOCK_KEY_SIZE);

		if (p < 0) {
			leftIdx = idx + 1;
			nl = LOOKUP_KEY(key2);
		} else if (p > 0) {
			rightIdx = idx;
			nr = LOOKUP_KEY(key2);
		} else { // p == 0
			return range->ino[idx];
		}

		n = rightIdx - leftIdx;
	}

	return 0;
}

void dir_index_range_free(dir_index_range_t* range) {
	free(range->key);
	free(range->ino);
	free(range);
}
