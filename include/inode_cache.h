#ifndef BK_INODE_CACHE_H
#define BK_INODE_CACHE_H

#include <stdint.h>

#ifdef MULTITHREADED
#include <pthread.h>
#endif

#include "dir.h"
#include "mempool.h"
#include "dir_index.h"

#define INODE_TABLES 79

typedef struct inode  {
	uint64_t parent_ino;
	char* name;

	dir_index_range_t *
		#ifdef MULTITHREADED
		volatile
		#endif
		dir_index;

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

	uint8_t ref_len;
	char ref[];
} inode_t;

typedef struct inode_cache {
	size_t size[INODE_TABLES];
	inode_t **table[INODE_TABLES];
	mempool_t *mempool;
	uint64_t next_ino;
#ifdef MULTITHREADED
	pthread_mutex_t mutex;
#endif
} inode_cache_t;

int inode_cache_init(inode_cache_t *cache, mempool_t *mempool, const char *ref, int ref_len);
inode_t *inode_cache_lookup(inode_cache_t *cache, uint64_t ino);
inode_t* inode_cache_add(inode_cache_t *cache, uint64_t parent_ino, const dentry_t *dentry, const char *ref, int ref_len, uint64_t *ino);
void inode_cache_free(inode_cache_t *cache);

#endif
