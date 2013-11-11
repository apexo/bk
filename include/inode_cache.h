#ifndef BK_INODE_CACHE_H
#define BK_INODE_CACHE_H

#include "types.h"

int inode_cache_init(inode_cache_t *cache, const unsigned char *ref, int ref_len);
const inode_t *inode_cache_lookup(inode_cache_t *cache, uint64_t ino);
const inode_t* inode_cache_add(inode_cache_t *cache, uint64_t parent_ino, const dentry_t *dentry, const unsigned char *ref, int ref_len);
void inode_cache_free(inode_cache_t *cache);

#endif
