#ifndef BK_INODE_CACHE_H
#define BK_INODE_CACHE_H

#include <stdint.h>

#include "dir.h"

#define INODE_TABLES 79

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

typedef struct inode_cache {
	size_t size[INODE_TABLES];
	inode_t **table[INODE_TABLES];
} inode_cache_t;

int inode_cache_init(inode_cache_t *cache, const unsigned char *ref, int ref_len);
const inode_t *inode_cache_lookup(inode_cache_t *cache, uint64_t ino);
const inode_t* inode_cache_add(inode_cache_t *cache, uint64_t parent_ino, const dentry_t *dentry, const unsigned char *ref, int ref_len);
void inode_cache_free(inode_cache_t *cache);

#endif
