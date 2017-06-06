#ifndef BK_MTIME_INDEX_H
#define BK_MTIME_INDEX_H

/*
 * mtime index, maps (absolute) file path, size, and mtime to a ref
 *
 * this can be used for fast deduplication based on a single stat() call but
 * may be less accurate than content-based deduplication
 */

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "types.h"
#include "index.h"

#define MTIME_ENTRY_SIZE (sizeof(block_key_t) + sizeof(ref_t) + 1)
#define MTIME_ENTRIES_PER_PAGE (PAGE_SIZE / MTIME_ENTRY_SIZE)
#define MTIME_PAGE_FILL_BYTES (PAGE_SIZE - MTIME_ENTRIES_PER_PAGE * MTIME_ENTRY_SIZE)

#define MTIME_MAGIC "BK.MIDX"
#define MTIME_VERSION 1

typedef char ref_t[MAX_REF_SIZE];

typedef struct mtime_index_header {
	char magic[8];

	// all numbers are in network byte order (big endian)
	uint32_t version;
	char reserved1[4];
	uint64_t num_entries;
	char reserved2[8];

	block_key_t index_hash;
	char reserved3[4000];
	block_key_t mtime_index_hash;
} mtime_index_header_t;

typedef struct mtime_index_page {
	block_key_t key[MTIME_ENTRIES_PER_PAGE];
	ref_t ref[MTIME_ENTRIES_PER_PAGE];
	uint8_t ref_len[MTIME_ENTRIES_PER_PAGE];

	char fill[MTIME_PAGE_FILL_BYTES];
} mtime_index_page_t;

typedef struct mtime_index_range {
	size_t num_entries;
	size_t limit;
	mtime_index_page_t *pages;
} mtime_index_range_t;

typedef struct mtime_index_ondisk {
	mtime_index_range_t range;
	size_t size;
	const mtime_index_header_t *header;
	int used;
} mtime_index_ondisk_t;

typedef struct mtime_index {
	size_t num_ranges;
	mtime_index_range_t *range;

	size_t num_ondisk;
	mtime_index_ondisk_t *ondisk;

	block_key_t value_encryption_key;
	SHA256_CTX key_hash_context;
	EVP_CIPHER_CTX *cipher_context;

	mtime_index_header_t header;
} mtime_index_t;

int mtime_index_init(mtime_index_t *mtime_index, const char *salt, size_t salt_len);
int mtime_index_add(mtime_index_t *mtime_index, const char *path, size_t path_len, uint64_t size, uint64_t mtime, ref_t ref, int ref_len);
int mtime_index_write(mtime_index_t *mtime_index, index_t *index, int fd);
int mtime_index_ondisk_add(mtime_index_t *mtime_index, int fd);
int mtime_index_lookup(mtime_index_t* mtime_index, const char *path, size_t path_len, uint64_t size, uint64_t mtime, ref_t ref);
void mtime_index_free(mtime_index_t *mtime_index);

#endif
