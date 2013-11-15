#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>

#include "inode_cache.h"

#define INODE_ENTRIES_MIN 512

static inode_t *_inode_alloc(mempool_t *mempool, const char *ref, int ref_len) {
	inode_t *inode = mempool_alloc(mempool, sizeof(inode_t) + ref_len);
	if (!inode) {
		perror("out of memory");
		return NULL;
	}

	memset(inode, 0, sizeof(inode_t));
	inode->ref_len = ref_len;
	memcpy(&inode->ref, ref, ref_len);
	return inode;
}

int inode_cache_init(inode_cache_t *cache, mempool_t *mempool, const char *ref, int ref_len) {
	memset(cache, 0, sizeof(inode_cache_t));

#ifdef MULTITHREADED
	if (pthread_mutex_init(&cache->mutex, NULL)) {
		fprintf(stderr, "pthread_mutex_init failed\n");
		return -1;
	}
#endif

	cache->mempool = mempool;

	for (size_t i = 0; i < 2; i++) {
		if (!(cache->table[i] = malloc(INODE_ENTRIES_MIN * sizeof(inode_t*)))) {
			perror("out of memory");
			goto err;
		}
		memset(cache->table[i], 0, INODE_ENTRIES_MIN * sizeof(inode_t*));
	}

	inode_t *root = _inode_alloc(mempool, ref, ref_len);
	if (!root) {
		fprintf(stderr, "_inode_alloc failed\n");
		goto err;
	}

	cache->size[0] = INODE_ENTRIES_MIN;
	cache->size[1] = INODE_ENTRIES_MIN;

	root->parent_ino = 1;
	root->mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
	cache->table[0][1] = root;

	return 0;

err:
#ifdef MULTITHREADED
	if (pthread_mutex_destroy(&cache->mutex)) {
		fprintf(stderr, "pthread_mutex_destroy failed\n");
	}
#endif
	for (size_t i = 0; i < 2; i++) {
		if (cache->table[i]) {
			free(cache->table[i]);
			cache->table[i] = NULL;
		}
	}

	return -1;
}

inode_t* inode_cache_lookup(inode_cache_t *cache, uint64_t ino) {
	size_t table_idx = 0;
	while (cache->size[table_idx] && ino >= cache->size[table_idx]) {
		ino -= cache->size[table_idx++];
		assert(table_idx < INODE_TABLES);
	}
	if (!cache->size[table_idx]) {
		return NULL;
	}
	return cache->table[table_idx][ino];
}

const inode_t* inode_cache_add(inode_cache_t *cache, uint64_t parent_ino, const dentry_t *dentry, const char *ref, int ref_len) {
	inode_t *inode = NULL;
	size_t table_idx = 0;
	uint64_t ino = be64toh(dentry->ino);

#ifdef MULTITHREADED
	if (pthread_mutex_lock(&cache->mutex)) {
		fprintf(stderr, "pthread_mutex_lock failed\n");
		return NULL;
	}
#endif

	while (1) {
		assert(table_idx < INODE_TABLES);
		if (!cache->size[table_idx]) {
			assert(table_idx >= 2);
			const size_t n = cache->size[table_idx - 2] + cache->size[table_idx - 1];
			if (n > (SIZE_MAX / sizeof(inode_t*))) {
				fprintf(stderr, "inode cache too large\n");
				goto out;
			}
			cache->table[table_idx] = malloc(n * sizeof(inode_t*));
			if (!cache->table[table_idx]) {
				perror("out of memory");
				goto out;
			}
			memset(cache->table[table_idx], 0, n * sizeof(inode_t*));
			cache->size[table_idx] = n;
		}
		if (ino < cache->size[table_idx]) {
			break;
		}
		ino -= cache->size[table_idx++];
	}

	if (cache->table[table_idx][ino]) {
		inode = cache->table[table_idx][ino];
		goto out;
	}

	inode = _inode_alloc(cache->mempool, ref, ref_len);
	if (!inode) {
		fprintf(stderr, "_inode_alloc failed\n");
		goto out;
	}

	inode->parent_ino = parent_ino;
	inode->rdev = be64toh(dentry->rdev);
	inode->size = be64toh(dentry->size);
	inode->blocks = be64toh(dentry->blocks);
	inode->atime = be64toh(dentry->atime);
	inode->mtime = be64toh(dentry->mtime);
	inode->ctime = be64toh(dentry->ctime);
	inode->mode = be32toh(dentry->mode);
	inode->uid = be32toh(dentry->uid); // TODO: translate (with username) to local uid
	inode->gid = be32toh(dentry->gid); // TODO: translate (with groupname) to local gid

	cache->table[table_idx][ino] = inode;

out:
#ifdef MULTITHREADED
	if (pthread_mutex_unlock(&cache->mutex)) {
		fprintf(stderr, "(in inode_cache_add) pthread_mutex_unlock failed\n");
	}
#endif

	return inode;
}

void inode_cache_free(inode_cache_t *cache) {
	for (size_t i = 0; i < INODE_TABLES; i++) {
		if (cache->table[i]) {
			for (size_t j = 0; j < cache->size[i]; j++) {
				if (cache->table[i][j] && cache->table[i][j]->dir_index) {
					dir_index_range_free(cache->table[i][j]->dir_index);
				}
			}
			free(cache->table[i]);
		}
	}

	if (pthread_mutex_destroy(&cache->mutex)) {
		fprintf(stderr, "(in inode_cache_free) pthread_mutex_destroy failed\n");
	}
}
