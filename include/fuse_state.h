#ifndef BK_FUSE_STATE_H
#define BK_FUSE_STATE_H

#define FUSE_USE_VERSION 35
#include <fuse3/fuse_lowlevel.h>

#ifdef MULTITHREADED
#include <pthread.h>
#endif

#include "block.h"
#include "block_cache.h"
#include "inode_cache.h"
#include "index.h"
#include "dir_index.h"
#include "mempool.h"


typedef struct fuse_thread_state {
	dir_thread_state_t dir_thread_state;
	block_thread_state_t block_thread_state;

	// size of the locked mmap region for block_thread_state.pack, dir_thread_state_t.dentry, and this fuse_thread_state_t
	size_t locked_size;

	// read, readdir, readlink
	// we don't really know the block size fuse is going to request from us a-priori, so we allocate this separately
	char *reply_buffer; // in locked memory
	size_t reply_buffer_size;

	// lookup
	lookup_temp_t d;
	struct fuse_entry_param e;
} fuse_thread_state_t;

typedef struct fuse_global_state {
	// read-only, no locking required
	index_t *index;

	// inode_cache_add is internally synchronized, inode_cache_lookup probably doesn't need to be
	inode_cache_t *inode_cache;

	// internally synchronized
	block_cache_t *block_cache;

	// read-only, no locking required
	ondiskidx_t *ondiskidx;

	// locking required
	dir_index_t *dir_index;
	#ifdef MULTITHREADED
	pthread_mutex_t dir_index_mutex;
	#endif

	// internally synchronized
	mempool_t *mempool;

	long page_size;
	int stats;

	#ifdef MULTITHREADED
	pthread_key_t state_key;
	#else
	fuse_thread_state_t *single_thread_state;
	#endif
} fuse_global_state_t;


int fuse_global_state_setup(fuse_global_state_t *global_state);
fuse_thread_state_t *fuse_thread_state_get(fuse_global_state_t *global_state);
char *fuse_thread_state_get_reply_buffer(fuse_global_state_t *global_state, fuse_thread_state_t *fuse_thread_state, size_t size);
void fuse_global_state_free(fuse_global_state_t *global_state);

#endif
