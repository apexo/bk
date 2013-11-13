#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>

#include "inode_cache.h"

#define INODE_ENTRIES_MIN 512

int inode_cache_init(inode_cache_t *cache, const unsigned char *ref, int ref_len) {
	memset(cache, 0, sizeof(inode_cache_t));

	inode_t *root = malloc(sizeof(inode_t) + ref_len);
	if (!root) {
		perror("out of memory");
		return -1;
	}

	cache->table[0] = malloc(INODE_ENTRIES_MIN * sizeof(inode_t*));
	if (!cache->table[0]) {
		perror("out of memory");
		free(root);
		return -1;
	}
	memset(cache->table[0], 0, INODE_ENTRIES_MIN * sizeof(inode_t*));

	cache->table[1] = malloc(INODE_ENTRIES_MIN * sizeof(inode_t*));
	if (!cache->table[1]) {
		perror("out of memory");
		free(root);
		free(cache->table[0]);
		cache->table[0] = NULL;
		return -1;
	}
	memset(cache->table[1], 0, INODE_ENTRIES_MIN * sizeof(inode_t*));

	cache->size[0] = INODE_ENTRIES_MIN;
	cache->size[1] = INODE_ENTRIES_MIN;

	memset(root, 0, sizeof(inode_t));
	root->parent_ino = 1;
	root->mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
	root->ref_len = ref_len;
	memcpy(&(root->ref), ref, ref_len);

	cache->table[0][1] = root;

	return 0;
}

const inode_t* inode_cache_lookup(inode_cache_t *cache, uint64_t ino) {
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

const inode_t* inode_cache_add(inode_cache_t *cache, uint64_t parent_ino, const dentry_t *dentry, const unsigned char *ref, int ref_len) {
	size_t table_idx = 0;
	uint64_t ino = be64toh(dentry->ino);
	while (1) {
		assert(table_idx < INODE_TABLES);
		if (!cache->size[table_idx]) {
			assert(table_idx >= 2);
			const size_t n = cache->size[table_idx - 2] + cache->size[table_idx - 1];
			if (n > (SIZE_MAX / sizeof(inode_t*))) {
				fprintf(stderr, "inode cache too large\n");
				return NULL;
			}
			cache->table[table_idx] = malloc(n * sizeof(inode_t*));
			if (!cache->table[table_idx]) {
				perror("out of memory");
				return NULL;
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
		return cache->table[table_idx][ino];
	}

	inode_t *inode = malloc(sizeof(inode_t) + ref_len);
	if (!inode) {
		perror("out of memory");
		return NULL;
	}

	memset(inode, 0, sizeof(inode_t));
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
	inode->ref_len = ref_len;
	memcpy(&(inode->ref), ref, ref_len);
	cache->table[table_idx][ino] = inode;

	return inode;
}

void inode_cache_free(inode_cache_t *cache) {
	for (size_t i = 0; i < INODE_TABLES; i++) {
		if (cache->table[i]) {
			for (size_t j = 0; j < cache->size[i]; j++) {
				if (cache->table[i][j]) {
					free(cache->table[i][j]);
				}
			}
			free(cache->table[i]);
		}
	}
}
