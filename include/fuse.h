#ifndef BK_FUSE_H
#define BK_FUSE_H

#include "index.h"
#include "inode_cache.h"

int fuse_main(index_t *index, inode_cache_t *_inode_cache, size_t blksize, int argc, char *argv[]);

#endif
