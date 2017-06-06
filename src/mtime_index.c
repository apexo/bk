#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/mman.h>

#include "util.h"
#include "mtime_index.h"
#include "mixed_limits.h"

static void _mtime_hash(mtime_index_t *mi, block_key_t key, const char *path, size_t path_len, uint64_t size, uint64_t mtime) {
	SHA256_CTX ctx;
	memcpy(&ctx, &mi->key_hash_context, sizeof(SHA256_CTX));

	uint64_t be_size = be64toh(size);
	SHA256_Update(&ctx, &be_size, sizeof(be_size));

	uint64_t be_mtime = be64toh(mtime);
	SHA256_Update(&ctx, &be_mtime, sizeof(be_mtime));

	SHA256_Update(&ctx, path, path_len);

	SHA256_Final((unsigned char*)key, &ctx);
}

static int _mtime_crypt(EVP_CIPHER_CTX *ctx, const char *src, size_t n, char *dst, block_key_t encryption_key, int enc, char *iv) {
	const EVP_CIPHER *cipher = EVP_aes_256_ctr();
	if (!cipher) {
		fprintf(stderr, "EVP_aes_256_ctr failed\n");
		return -1;
	}

	if (!EVP_CipherInit_ex(ctx, cipher, NULL, (unsigned char*)encryption_key, (unsigned char*)iv, enc)) {
		fprintf(stderr, "error %scrypting ref; EVP_CipherInit_ex failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_reset(ctx);
		return -1;
	}

	int len;
	if (!EVP_CipherUpdate(ctx, (unsigned char*)dst, &len, (const unsigned char*)src, n)) {
		fprintf(stderr, "error %scrypting ref; EVP_CipherUpdate failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_reset(ctx);
		return -1;
	}

	int f_len;
	if (!EVP_CipherFinal_ex(ctx, (unsigned char*)(dst+len), &f_len)) {
		fprintf(stderr, "error %scrypting ref; EVP_CipherFinal_ex failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_reset(ctx);
		return -1;
	}

	assert(len + f_len == (int)n);

	EVP_CIPHER_CTX_reset(ctx);
	return 0;
}

static ssize_t _mtime_num_pages(size_t limit) {
	if (limit > SSIZE_MAX - MTIME_ENTRIES_PER_PAGE + 1) {
		fprintf(stderr, "mtime index too big\n");
		return -1;
	}

	const ssize_t num_pages = (limit + MTIME_ENTRIES_PER_PAGE - 1) / MTIME_ENTRIES_PER_PAGE;
	if (num_pages > SSIZE_MAX / PAGE_SIZE) {
		fprintf(stderr, "mtime index too big\n");
		return -1;
	}

	return num_pages;
}

static int _mtime_index_alloc_pages(mtime_index_range_t *range, size_t limit) {
	const ssize_t num_pages = _mtime_num_pages(limit);
	if (num_pages < 0) {
		return -1;
	}

	range->num_entries = 0;
	range->limit = limit;
	range->pages = (mtime_index_page_t*)calloc(num_pages, PAGE_SIZE);
	if (!range->pages) {
		perror("out of memory");
		return -1;
	}

	return 0;
}

static int _mtime_index_grow(mtime_index_t *mi, size_t limit) {
	mtime_index_range_t *range = realloc(mi->range, sizeof(mtime_index_range_t)*(mi->num_ranges+1));
	if (!range) {
		perror("out of memory");
		return -1;
	}
	memset(range+mi->num_ranges, 0, sizeof(mtime_index_range_t));

	if (_mtime_index_alloc_pages(range+mi->num_ranges, limit)) {
		fprintf(stderr, "_mtime_index_alloc_pages failed\n");
		return -1;
	}

	mi->range = range;
	mi->num_ranges++;
	return 0;
}

int mtime_index_init(mtime_index_t *mi, const char *salt, size_t salt_len) {
	assert(sizeof(mtime_index_page_t) == PAGE_SIZE);

	memset(mi, 0, sizeof(mtime_index_t));

	SHA256_Init(&mi->key_hash_context);
	SHA256_Update(&mi->key_hash_context, salt, salt_len);
	SHA256_Final((unsigned char*)mi->value_encryption_key, &mi->key_hash_context);

	SHA256_Init(&mi->key_hash_context);
	SHA256_Update(&mi->key_hash_context, salt, salt_len);

	memcpy(mi->header.magic, MTIME_MAGIC, strlen(MTIME_MAGIC) + 1);
	mi->header.version = be32toh(MTIME_VERSION);

	if (_mtime_index_grow(mi, 1) || _mtime_index_grow(mi, 1)) {
		fprintf(stderr, "_mtime_index_grow failed\n");
		mtime_index_free(mi);
		return -1;
	}

	if (!(mi->cipher_context = EVP_CIPHER_CTX_new())) {
		mtime_index_free(mi);
		return -1;
	}

	return 0;
}

/*
 * caller must assure that dst->capacity ("limit") is large enough for (or probably equal to) src1->num_entries + src2->num-entries
 */
static void _mtime_index_range_merge(mtime_index_range_t *dst, mtime_index_range_t *src1, mtime_index_range_t *src2) {
	const size_t n1 = src1->num_entries, n2 = src2->num_entries;
	size_t is1 = 0, is2 = 0, id = 0;

	while (is1 < n1 && is2 < n2) {
		mtime_index_page_t *pd = dst->pages + (id / MTIME_ENTRIES_PER_PAGE);
		mtime_index_page_t *ps1 = src1->pages + (is1 / MTIME_ENTRIES_PER_PAGE);
		mtime_index_page_t *ps2 = src2->pages + (is2 / MTIME_ENTRIES_PER_PAGE);

		if (memcmp(ps1->key[is1 % MTIME_ENTRIES_PER_PAGE], ps2->key[is2 % MTIME_ENTRIES_PER_PAGE], BLOCK_KEY_SIZE) < 0) {
			memcpy(pd->key[id % MTIME_ENTRIES_PER_PAGE], ps1->key[is1 % MTIME_ENTRIES_PER_PAGE], BLOCK_KEY_SIZE);
			memcpy(pd->ref[id % MTIME_ENTRIES_PER_PAGE], ps1->ref[is1 % MTIME_ENTRIES_PER_PAGE], MAX_REF_SIZE);
			pd->ref_len[id % MTIME_ENTRIES_PER_PAGE] = ps1->ref_len[is1 % MTIME_ENTRIES_PER_PAGE];
			id++; is1++;
		} else {
			memcpy(pd->key[id % MTIME_ENTRIES_PER_PAGE], ps2->key[is2 % MTIME_ENTRIES_PER_PAGE], BLOCK_KEY_SIZE);
			memcpy(pd->ref[id % MTIME_ENTRIES_PER_PAGE], ps2->ref[is2 % MTIME_ENTRIES_PER_PAGE], MAX_REF_SIZE);
			pd->ref_len[id % MTIME_ENTRIES_PER_PAGE] = ps2->ref_len[is2 % MTIME_ENTRIES_PER_PAGE];
			id++; is2++;
		}
	}

	while (is1 < n1) {
		mtime_index_page_t *pd = dst->pages + (id / MTIME_ENTRIES_PER_PAGE);
		mtime_index_page_t *ps1 = src1->pages + (is1 / MTIME_ENTRIES_PER_PAGE);

		memcpy(pd->key[id % MTIME_ENTRIES_PER_PAGE], ps1->key[is1 % MTIME_ENTRIES_PER_PAGE], BLOCK_KEY_SIZE);
		memcpy(pd->ref[id % MTIME_ENTRIES_PER_PAGE], ps1->ref[is1 % MTIME_ENTRIES_PER_PAGE], MAX_REF_SIZE);
		pd->ref_len[id % MTIME_ENTRIES_PER_PAGE] = ps1->ref_len[is1 % MTIME_ENTRIES_PER_PAGE];
		id++; is1++;
	}

	while (is2 < n2) {
		mtime_index_page_t *pd = dst->pages + (id / MTIME_ENTRIES_PER_PAGE);
		mtime_index_page_t *ps2 = src2->pages + (is2 / MTIME_ENTRIES_PER_PAGE);

		memcpy(pd->key[id % MTIME_ENTRIES_PER_PAGE], ps2->key[is2 % MTIME_ENTRIES_PER_PAGE], BLOCK_KEY_SIZE);
		memcpy(pd->ref[id % MTIME_ENTRIES_PER_PAGE], ps2->ref[is2 % MTIME_ENTRIES_PER_PAGE], MAX_REF_SIZE);
		pd->ref_len[id % MTIME_ENTRIES_PER_PAGE] = ps2->ref_len[is2 % MTIME_ENTRIES_PER_PAGE];
		id++; is2++;
	}

	dst->num_entries = src1->num_entries + src2->num_entries;
	src1->num_entries = 0;
	src2->num_entries = 0;
}

int mtime_index_add(mtime_index_t *mi, const char *path, size_t path_len, uint64_t size, uint64_t mtime, ref_t ref, int ref_len) {
	mtime_index_range_t *range = mi->range;

	ref_t temp;
	memcpy(temp, ref, ref_len);
	memset(temp + ref_len, 0, MAX_REF_SIZE - ref_len);

	size_t idx = range[1].num_entries ? 0 : 1;
	_mtime_hash(mi, range[idx].pages[0].key[0], path, path_len, size, mtime);
	if (_mtime_crypt(mi->cipher_context, temp, MAX_REF_SIZE, range[idx].pages[0].ref[0], mi->value_encryption_key, 1, range[idx].pages[0].key[0])) {
		fprintf(stderr, "_mtime_crypt failed\n");
		return -1;
	}
	range[idx].pages[0].ref_len[0] = ref_len;
	range[idx].num_entries = 1;

	while (idx + 1 < mi->num_ranges && range[idx].num_entries && range[idx + 1].num_entries) {
		if (idx+2 == mi->num_ranges) {
			assert(range[idx+1].limit <= SIZE_MAX - range[idx].limit);
			size_t limit = range[idx+1].limit + range[idx].limit;
			if (_mtime_index_grow(mi, limit)) {
				fprintf(stderr, "_mtime_index_grow failed\n");
				return -1;
			}
		}

		range = mi->range;

		assert(range[idx].num_entries == range[idx].limit);
		assert(range[idx+1].num_entries == range[idx+1].limit);
		assert(!range[idx+2].num_entries);
		assert(range[idx+2].limit == range[idx].limit + range[idx+1].limit);

		_mtime_index_range_merge(range+idx+2, range+idx+1, range+idx);

		idx += 2;
	}

	return 0;
}

static int _mtime_index_range_write(mtime_index_t *mi, index_t *index, mtime_index_range_t *range, int fd) {
	index->header.num_entries = be64toh(range->num_entries);

	const ssize_t num_pages = _mtime_num_pages(range->num_entries);
	if (num_pages < 0) {
		return -1;
	}

	memcpy(mi->header.index_hash, index->header.index_hash, BLOCK_KEY_SIZE);
	mi->header.num_entries = be64toh(range->num_entries);
	// TODO: _mtime_index_hash(mi, range, num_pages) -> mtime_index_hash

	if (write_all(fd, (char*)&mi->header, PAGE_SIZE)) {
		fprintf(stderr, "write_all failed\n");
		return -1;
	}

	if (write_all(fd, (char*)range->pages, PAGE_SIZE * num_pages)) {
		fprintf(stderr, "write_all failed\n");
		return -1;
	}

	return 0;
}

int mtime_index_write(mtime_index_t *mi, index_t *index, int fd) {
	mtime_index_range_t *range = mi->range;

	size_t i1 = 0;
	while (i1 < mi->num_ranges - 1) {
		if (!range[i1].num_entries) {
			i1++;
			continue;
		}
		size_t i2 = i1 + 1;
		while (i2 < mi->num_ranges && !range[i2].num_entries) {
			i2++;
		}
		if (i2 == mi->num_ranges) {
			break;
		}
		if ((i2 == mi->num_ranges - 1) && _mtime_index_grow(mi, range[i1].num_entries + range[i2].num_entries)) {
			fprintf(stderr, "_mtime_index_grow failed\n");
			return -1;
		}
		range = mi->range;
		_mtime_index_range_merge(range+i2+1, range+i2, range+i1);
		i1 = i2+1;
	}

	if (_mtime_index_range_write(mi, index, range + i1, fd)) {
		perror("error writing mtime index");
		return -1;
	}

	return 0;
}

typedef uint32_t lookup_key_t;
#define LOOKUP_KEY(v) be32toh(*(uint32_t*)(v))
#define LOOKUP_KEY_MIN 0
#define LOOKUP_KEY_MAX UINT32_MAX

static int _mtime_index_range_lookup(mtime_index_range_t* range, block_key_t key, ref_t ref) {
	const lookup_key_t nk = LOOKUP_KEY(key);
	lookup_key_t nl = LOOKUP_KEY_MIN, nr = LOOKUP_KEY_MAX;
	size_t leftIdx = 0, rightIdx = range->num_entries, n = rightIdx;

	while (n) {
		assert(nl <= nk);
		assert(nk <= nr);
		assert(nl < nr);

		const size_t idx = (n - 1) * (uint64_t)(nk - nl) / (nr - nl) + leftIdx;

		assert(leftIdx <= idx);
		assert(idx < rightIdx);

		mtime_index_page_t *page = range->pages + (idx / MTIME_ENTRIES_PER_PAGE);
		size_t pageidx = idx % MTIME_ENTRIES_PER_PAGE;
		const char *key2 = page->key[pageidx];

		const int p = memcmp(key2, key, BLOCK_KEY_SIZE);

		if (p < 0) {
			leftIdx = idx + 1;
			nl = LOOKUP_KEY(key2);
		} else if (p > 0) {
			rightIdx = idx;
			nr = LOOKUP_KEY(key2);
		} else { // p == 0
			memcpy(ref, page->ref[pageidx], MAX_REF_SIZE);
			return page->ref_len[pageidx];
		}

		n = rightIdx - leftIdx;
	}

	return 0;
}

int mtime_index_lookup(mtime_index_t* mi, const char *path, size_t path_len, uint64_t size, uint64_t mtime, ref_t ref) {
	block_key_t key;
	_mtime_hash(mi, key, path, path_len, size, mtime);
	int n;
	ref_t temp_ref;

	for (size_t i = 0; i < mi->num_ondisk; i++) {
		if ((n = _mtime_index_range_lookup(&mi->ondisk[i].range, key, temp_ref))) {
			mi->ondisk[i].used = 1;
			goto decrypt;
		}
	}

	for (size_t i = 0; i < mi->num_ranges; i++) {
		if ((n = _mtime_index_range_lookup(mi->range + i, key, temp_ref))) {
			goto decrypt;
		}
	}

	return 0;

decrypt:
	if (_mtime_crypt(mi->cipher_context, temp_ref, MAX_REF_SIZE, ref, mi->value_encryption_key, 0, key)) {
		fprintf(stderr, "(in mtime_index_lookup) _mtime_crypt failed\n");
		return 0;
	}

	return n;
}

int mtime_index_ondisk_add(mtime_index_t *mi, int fd) {
	mtime_index_ondisk_t* ondisk = realloc(mi->ondisk, sizeof(mtime_index_ondisk_t)*(mi->num_ondisk+1));
	if (!ondisk) {
		perror("out of memory");
		return -1;
	}
	mi->ondisk = ondisk;
	ondisk += mi->num_ondisk;

	// TODO: determine what happens, when sysconf(_SC_PAGESIZE) != PAGE_SIZE
	const off_t idx_size = lseek(fd, 0, SEEK_END);
	if (idx_size == (off_t)-1) {
		perror("lseek failed");
		return -1;
	}

	if (idx_size < PAGE_SIZE) {
		perror("invalid mtime index: must contain at least one page");
		return -1;
	}

	if (idx_size > OFFSET_SIZE_MAX) {
		fprintf(stderr, "mtime index too large\n");
		return -1;
	}

	char *data = mmap(NULL, (size_t)idx_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		perror("failed to mmap mtime index");
		return -1;
	}

	const mtime_index_header_t *header = (mtime_index_header_t*)data;

	if (memcmp(header->magic, MTIME_MAGIC, strlen(MTIME_MAGIC)+1)) {
		fprintf(stderr, "invalid mtime index magic\n");
		goto err;
	}

	if (be32toh(header->version) != MTIME_VERSION) {
		fprintf(stderr, "unsupported mtime index version\n");
		goto err;
	}

	const size_t num_idx_pages = (idx_size - PAGE_SIZE) / PAGE_SIZE;
	const size_t num_entries = be64toh(header->num_entries);
	const size_t max_entries = num_idx_pages * MTIME_ENTRIES_PER_PAGE;
	const size_t min_entries = max_entries ? max_entries - MTIME_ENTRIES_PER_PAGE + 1 : 0;

	if (num_entries < min_entries || num_entries > max_entries) {
		fprintf(stderr, "illegal num_entries: %zu; expected %zu-%zu (based on the mtime index size)\n", num_entries, min_entries, max_entries);
		goto err;
	}

	ondisk->range.num_entries = num_entries;
	ondisk->range.limit = num_entries;
	ondisk->range.pages = (mtime_index_page_t*)(data + PAGE_SIZE);
	ondisk->size = idx_size;
	ondisk->header = header;

	mi->num_ondisk++;
	return 0;

err:
	if (munmap(data, idx_size)) {
		perror("munmap failed");
	}
	return -1;

}


void mtime_index_free(mtime_index_t *mi) {
	if (mi->cipher_context) {
		EVP_CIPHER_CTX_free(mi->cipher_context);
	}
	for (size_t i = 0; i < mi->num_ranges; i++) {
		free(mi->range[i].pages);
	}
	if (mi->range) {
		free(mi->range);
	}
	for (size_t i = 0; i < mi->num_ondisk; i++) {
		if (munmap((void*)mi->ondisk[i].header, mi->ondisk[i].size)) {
			perror("munmap failed");
		}
	}
	if (mi->ondisk) {
		free(mi->ondisk);
	}
}
