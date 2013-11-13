#ifndef BK_TYPES_H
#define BK_TYPES_H

#include <stdint.h>

#define PAGE_SIZE 4096
#define MIN_BLOCK_SIZE 4096
#define INLINE_THRESHOLD 160
#define BLOCK_KEY_SIZE 32
#define MAX_REF_SIZE (2 + INLINE_THRESHOLD)

typedef unsigned char block_key_t[BLOCK_KEY_SIZE];
typedef uint64_t file_offset_t;
typedef uint32_t block_size_t;

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

#include "filter.h"

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
