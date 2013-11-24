#ifndef BK_DIR_INDEX_H
#define BK_DIR_INDEX_H

/*
 * directory index for fast filename lookup
 */

#include <openssl/sha.h>

#include "types.h"
#include "mempool.h"

/*
 * the (immutable) directory index; contains a sorted list of keys (which are salted
 * hashes of filenames, mapping to their inos
 *
 * read-only access by multiple threads (via dir_index_range_lookup) is okay, as long as
 * each thread has it's own lookup_temp_t
 */
typedef struct dir_index_range {
	// contains sensitive data, allocated from locked memory pool
	SHA256_CTX *filename_hash_context;

	size_t num_entries;
	block_key_t *key;
	uint64_t *ino;

	uint64_t first_ino;
} dir_index_range_t;

#define DIR_RANGES 64
#define LOOKUP_FAIL 0

/*
 * while the directory index is being populated, it is being kept in this data
 * structure; it may be reused for creating multiple indices
 */
typedef struct dir_index {
	size_t limit[DIR_RANGES];
	dir_index_range_t range[DIR_RANGES];
	int num_ranges;
	int fd_urandom;

	// contains sensitive data, allocated from locked memory pool
	SHA256_CTX *filename_hash_context;

	// contains sensitive data, allocated from locked memory pool
	SHA256_CTX *temp;

	// contains sensitive data, allocated from locked memory pool
	char *random;
} dir_index_t;

// contains sensitive data, should be allocated from locked memory pool
typedef struct lookup_temp {
	SHA256_CTX ctx;
} lookup_temp_t;

int dir_index_init(dir_index_t *dir_index, mempool_t *mempool);
int dir_index_add(dir_index_t *dir_index, const char *name, size_t name_len, uint64_t ino);
dir_index_range_t *dir_index_merge(dir_index_t* dir_index, mempool_t *mempool);
void dir_index_free(dir_index_t *dir_index);

uint64_t dir_index_range_lookup(dir_index_range_t* range, lookup_temp_t *temp, const char *name, size_t name_len);
void dir_index_range_free(dir_index_range_t* range);

#endif
