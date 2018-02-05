#ifndef BK_INDEX_H
#define BK_INDEX_H

#include <openssl/sha.h>

#ifdef MULTITHREADED
#include <pthread.h>
#endif

#include "types.h"

#define ENTRY_SIZE (sizeof(block_key_t) + sizeof(file_offset_t) + sizeof(block_size_t) + sizeof(block_size_t))
#define ENTRIES_PER_PAGE (PAGE_SIZE / ENTRY_SIZE)
#define PAGE_FILL_BYTES (PAGE_SIZE - ENTRIES_PER_PAGE * ENTRY_SIZE)
#define MAX_REFERENCED_INDICES 124

#define MAGIC "BK.IDX\0"
#define IDX_RESERVED "\0\0\0\0\0\0\0"
#define VERSION 1

typedef struct index_header {
	char magic[8];

	// all numbers are in network byte order (big endian)
	uint32_t version;
	uint32_t blksize;
	uint64_t num_entries;
	char reserved[8];

	uint64_t total_blocks;
	uint64_t total_bytes;
	uint64_t dedup_blocks;
	uint64_t dedup_bytes;
	uint64_t dedup_compressed_bytes;
	uint64_t internal_blocks;
	uint64_t internal_bytes;
	uint64_t internal_compressed_bytes;

	block_key_t referenced_indices[MAX_REFERENCED_INDICES];
	block_key_t index_hash;
} index_header_t;

typedef struct index_page {
	block_key_t key[ENTRIES_PER_PAGE];

	/* these 3 fields are in network byte order (big endian) */
	file_offset_t file_offset[ENTRIES_PER_PAGE];
	block_size_t block_size[ENTRIES_PER_PAGE];
	block_size_t compressed_block_size[ENTRIES_PER_PAGE];

	char fill[PAGE_FILL_BYTES];
} index_page_t;

typedef struct index_range {
	size_t num_entries;
	size_t limit;
	index_page_t *pages;
} index_range_t;

typedef struct ondiskidx {
	index_range_t range;
	size_t size;
	const index_header_t *header;
	int data_fd;
	block_size_t blksize;

	// bitmap, 1 bit per entry; starts at 0 and is set to 1 once referenced;
	// mostly for statistical purposes (and to determine which indices are actually referenced)
	uint8_t *used;

#ifdef MULTITHREADED
	pthread_mutex_t mutex;
#endif
} ondiskidx_t;

typedef struct index {
	block_size_t blksize;
	int data_fd;
	size_t num_workidx;
	index_range_t *workidx;

	size_t num_ondiskidx;
	ondiskidx_t *ondiskidx;

	SHA256_CTX encryption_key_context;
	SHA256_CTX storage_key_context;

	index_header_t header;

#ifdef MULTITHREADED
	pthread_mutex_t mutex;
#endif
} index_t;

int index_init(index_t *index, int readonly, const char *salt, size_t salt_len);
int index_set_blksize(index_t *index, block_size_t blksize);
int index_free(index_t *index);
int index_ondiskidx_add(index_t *index, int index_fd, int data_fd);
int index_add_block(index_t *index, block_key_t block_key, file_offset_t file_offset, block_size_t block_size, block_size_t compressed_block_size);
int index_write(index_t *index, int fd);
int index_lookup(index_t *index, block_key_t key, file_offset_t *file_offset, block_size_t *block_size, block_size_t *compressed_block_size, ondiskidx_t **ondiskidx);

#endif
