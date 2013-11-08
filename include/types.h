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


//typedef struct { unsigned char key[BLOCK_KEY_SIZE]; } keyx_t;
typedef unsigned char block_key_t[BLOCK_KEY_SIZE];
typedef uint64_t file_offset_t;
typedef uint32_t block_size_t;

#define ENTRY_SIZE (sizeof(block_key_t) + sizeof(file_offset_t) + sizeof(block_size_t) + sizeof(block_size_t))
#define PAGE_ENTRIES_SIZE (PAGE_SIZE - sizeof(index_page_header_t))
#define ENTRIES_PER_PAGE (PAGE_ENTRIES_SIZE / ENTRY_SIZE)
#define PAGE_FILL_BYTES (PAGE_ENTRIES_SIZE - ENTRIES_PER_PAGE * ENTRY_SIZE)

#define MAGIC "BK.IDX"

typedef struct index_page_header {
	unsigned char magic[7];
	unsigned char num_entries;
	uint32_t block_size;
} index_page_header_t;

typedef struct index_page {
	index_page_header_t header;
	unsigned char fill[PAGE_FILL_BYTES];

	block_key_t key[ENTRIES_PER_PAGE];

	/* these 3 fields are in network byte order (big endian) */
	file_offset_t file_offset[ENTRIES_PER_PAGE];
	block_size_t block_size[ENTRIES_PER_PAGE];
	block_size_t compressed_block_size[ENTRIES_PER_PAGE];
} index_page_t;

typedef struct index_range {
	size_t num_entries;
	size_t limit;
	index_page_t *pages;
} index_range_t;

typedef struct dentry {
	uint64_t ino;     /* inode number (synthetic) */
	uint32_t mode;    /* protection */
	uint32_t uid;     /* user ID of owner */
	uint32_t gid;     /* group ID of owner */
	uint64_t rdev;    /* device ID (if special file) */
	uint64_t size;    /* total size, in bytes */
	uint32_t blksize; /* blocksize for filesystem I/O */
	uint64_t blocks;  /* number of 512B blocks allocated */
	uint64_t atime;   /* time of last access */
	uint64_t mtime;   /* time of last modification */
	uint64_t ctime;   /* time of last status change */
	uint16_t namelen;
	uint8_t usernamelen;
	uint8_t groupnamelen;
} dentry_t;

typedef struct index {
	int *ref_data_fd;
	int data_fd;
	size_t num_references;
	size_t num_fibidx;
	index_range_t *references;
	index_range_t *fibidx;
	SHA256_CTX encryption_key_context;
	SHA256_CTX storage_key_context;
	uint64_t next_ino;
} index_t;

typedef struct block {
	size_t size;
	size_t indirection;
	size_t len[MAX_INDIRECTION + 1];
	size_t idx[MAX_INDIRECTION + 1];
	unsigned char *data[MAX_INDIRECTION + 1];
	unsigned char *temp0; /* read buffer, size bytes */
	unsigned char *temp1; /* compression buffer, LZ4_compressBound(size) bytes */
	unsigned char *temp2; /* encryption buffer, size bytes */
	uint64_t raw_bytes;
	uint64_t allocated_bytes;
} block_t;

typedef struct block_stack {
	size_t block_size;
	size_t n;
	size_t limit;
	block_t *block;
} block_stack_t;

#endif
