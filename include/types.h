#ifndef BK_TYPES_H
#define BK_TYPES_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/sha.h>

#define PAGE_SIZE 4096
#define MIN_BLOCK_SIZE 4096
#define INLINE_THRESHOLD 160
#define BLOCK_KEY_SIZE 32
#define MAX_INDIRECTION 4
#define MAX_REF_SIZE (2 + INLINE_THRESHOLD)


typedef unsigned char block_key_t[BLOCK_KEY_SIZE];
typedef uint64_t file_offset_t;
typedef uint32_t block_size_t;

#define ENTRY_SIZE (sizeof(block_key_t) + sizeof(file_offset_t) + sizeof(block_size_t) + sizeof(block_size_t))
#define ENTRIES_PER_PAGE (PAGE_SIZE / ENTRY_SIZE)
#define PAGE_FILL_BYTES (PAGE_SIZE - ENTRIES_PER_PAGE * ENTRY_SIZE)

#define MAX_REFERENCED_INDICES 124

#define MAGIC "BK.IDX\0"
#define VERSION 1

typedef struct index_header {
	unsigned char magic[8];

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

	unsigned char fill[PAGE_FILL_BYTES];
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
	// mostly for statistical purposes
	uint8_t *used;
} ondiskidx_t;

typedef struct dentry {
	uint64_t ino;     /* inode number (synthetic) */
	uint64_t rdev;    /* device ID (if special file) */
	uint64_t size;    /* total size, in bytes */
	uint64_t blocks;  /* number of 512B blocks allocated */
	uint64_t atime;   /* time of last access */
	uint64_t mtime;   /* time of last modification */
	uint64_t ctime;   /* time of last status change */
	uint32_t mode;    /* protection */
	uint32_t uid;     /* user ID of owner */
	uint32_t gid;     /* group ID of owner */
	uint16_t namelen;
	uint8_t usernamelen;
	uint8_t groupnamelen;
} dentry_t;

typedef struct inode  {
	uint64_t parent_ino;

	/* all dentry_t fields, except: ino (implicit), namelen, usernamelen, grouplen (not used) */
	uint64_t rdev;    /* device ID (if special file) */
	uint64_t size;    /* total size, in bytes */
	uint64_t blocks;  /* number of 512B blocks allocated */
	uint64_t atime;   /* time of last access */
	uint64_t mtime;   /* time of last modification */
	uint64_t ctime;   /* time of last status change */
	uint32_t mode;    /* protection */
	uint32_t uid;     /* user ID of owner */
	uint32_t gid;     /* group ID of owner */
	//uint32_t blksize; /* blocksize for filesystem I/O */

	uint8_t ref_len;
	unsigned char ref[];
} inode_t;

#define INODE_TABLES 79

typedef struct inode_cache {
	size_t size[INODE_TABLES];
	inode_t **table[INODE_TABLES];
} inode_cache_t;

typedef struct index {
	block_size_t blksize;
	int data_fd;
	size_t num_workidx;
	index_range_t *workidx;

	size_t num_ondiskidx;
	ondiskidx_t *ondiskidx;

	SHA256_CTX encryption_key_context;
	SHA256_CTX storage_key_context;
	uint64_t next_ino;

	index_header_t header;
} index_t;

typedef struct block {
	size_t blksize;
	uint32_t idx_blksize;
	size_t indirection;
	size_t len[MAX_INDIRECTION + 1];
	size_t idx[MAX_INDIRECTION + 1];
	size_t limit[MAX_INDIRECTION + 1];
	unsigned char *data[MAX_INDIRECTION + 1]; /* indirection buffer (locked) */
	unsigned char *temp0; /* user buffer, size bytes (locked) */
	unsigned char *temp1; /* compression buffer, LZ4_compressBound(size) bytes (locked) */
	unsigned char *temp2; /* encryption buffer, size bytes */
	uint64_t raw_bytes;
	uint64_t allocated_bytes;
} block_t;

typedef struct block_stack {
	size_t blksize;
	size_t n;
	size_t limit;
	block_t *block;
} block_stack_t;

#define BLOCK_CACHE_SIZE 4

typedef struct block_cache {
	size_t next;
	uint64_t ino[BLOCK_CACHE_SIZE];
	off_t off[BLOCK_CACHE_SIZE];
	block_t block[BLOCK_CACHE_SIZE];
} block_cache_t;

typedef struct filter_rule {
	size_t count;
	char **path;
	int include;
} filter_rule_t;

typedef struct filter_match {
	size_t capacity;
	size_t count;
	filter_rule_t **rules;
	size_t *idx;
	int include;
} filter_match_t;

typedef struct filter {
	size_t rule_count;
	filter_rule_t **rules;

	size_t max_depth;
	size_t depth;
	filter_match_t *match;

	int flags;
} filter_t;

typedef struct args {
	int verbose;
	int list_only;
	int xdev;
	int dev;
	filter_t filter;

	size_t path_capacity;
	size_t path_length;
	char *path;
} args_t;

#endif
