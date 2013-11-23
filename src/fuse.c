#define FUSE_USE_VERSION 30
#include <fuse/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/statvfs.h>
#include <endian.h>

#include "types.h"
#include "block_cache.h"
#include "block.h"
#include "dir.h"
#include "dir_index.h"
#include "fuse_state.h"

static void stat_from_inode(ondiskidx_t *ondiskidx, struct stat *stbuf, const inode_t *inode) {
	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = inode->mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = inode->uid;
	stbuf->st_gid = inode->gid;
	stbuf->st_rdev = inode->rdev;
	stbuf->st_size = inode->size;
	stbuf->st_blksize = ondiskidx ? ondiskidx->blksize : MIN_BLOCK_SIZE;
	stbuf->st_blocks = inode->blocks;
	stbuf->st_atime = inode->atime;
	stbuf->st_mtime = inode->mtime;
	stbuf->st_ctime = inode->ctime;
}

static void bk_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);

	const inode_t *inode = inode_cache_lookup(fuse_global_state->inode_cache, ino);
	if (!inode) {
		fuse_reply_err(req, EIO);
		return;
	}

	struct stat stbuf;
	stat_from_inode(fuse_global_state->ondiskidx, &stbuf, inode);
	stbuf.st_ino = ino;
	fuse_reply_attr(req, &stbuf, 86400.0);
}

static int _populate_dir_index_locked(fuse_global_state_t *fuse_global_state, fuse_thread_state_t *fuse_thread_state, fuse_ino_t parent, inode_t *parent_inode) {
	block_t *block = block_cache_get(
		&fuse_thread_state->block_thread_state,
		fuse_global_state->block_cache, 
		fuse_global_state->inode_cache,
		fuse_global_state->index,
		parent, 0);

	if (!block) {
		fprintf(stderr, "block_cache_get failed\n");
		return -1;
	}

	int rc = -1;
	size_t ref_len, dnamelen;
	const char *ref, *dname, *username, *groupname;
	const dentry_t *dentry;
	inode_t *last_sibling = NULL;

	ssize_t n;
	while ((n = dir_entry_read(&fuse_thread_state->block_thread_state, &fuse_thread_state->dir_thread_state, block, fuse_global_state->index, &dentry,
		&ref, &ref_len,
		&dname, &dnamelen,
		&username, &groupname)) > 0) {

		uint64_t ino;

		inode_t *inode = inode_cache_add(fuse_global_state->inode_cache, parent, dentry, ref, ref_len, &ino);
		if (!inode) {
			fprintf(stderr, "inode_cache_add failed\n");
			goto out;
		}

		char *name = mempool_alloc(fuse_global_state->inode_cache->mempool, dnamelen + 1);
		if (!name) {
			fprintf(stderr, "mempool_alloc failed\n");
			goto out;
		}
		memcpy(name, dname, dnamelen);
		inode->name = name;

		if (last_sibling) {
			last_sibling->next_sibling_ino = ino;
		} else {
			parent_inode->first_child_ino = ino;
		}
		last_sibling = inode;

		if (dir_index_add(fuse_global_state->dir_index, (const char*)dname, dnamelen, ino)) {
			fprintf(stderr, "dir_index_add failed\n");
			goto out;
		}
	}

	if (n < 0) {
		fprintf(stderr, "dir_entry_read failed\n");
		goto out;
	}

	parent_inode->dir_index = dir_index_merge(fuse_global_state->dir_index, fuse_global_state->mempool);
	if (!parent_inode->dir_index) {
		fprintf(stderr, "dir_index_merge failed\n");
		goto out;
	}

	rc = 0;
out:
	block_cache_put(fuse_global_state->block_cache, block, 0, 0);
	return rc;
}

static int _populate_dir_index(fuse_global_state_t *fuse_global_state, fuse_thread_state_t *fuse_thread_state, fuse_ino_t parent, inode_t *parent_inode) {
	if (!parent_inode->dir_index) {
		#ifdef MULTITHREADED
		if (pthread_mutex_lock(&fuse_global_state->dir_index_mutex)) {
			perror("pthread_mutex_lock failed");
			return -1;
		}
		if (!parent_inode->dir_index) {
		#endif
			if (_populate_dir_index_locked(fuse_global_state, fuse_thread_state, parent, parent_inode)) {
				fprintf(stderr, "_populate_dir_index_locked failed\n");
				return -1;
			}
		#ifdef MULTITHREADED
		}
		if (pthread_mutex_unlock(&fuse_global_state->dir_index_mutex)) {
			perror("(in bk_ll_lookup) pthread_mutex_unlock failed");
			return -1;
		}
		#endif
	}

	return 0;

}

static void bk_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);
	fuse_thread_state_t *fuse_thread_state = fuse_thread_state_get(fuse_global_state);

	inode_t *parent_inode = inode_cache_lookup(fuse_global_state->inode_cache, parent);
	if (!parent_inode) {
		fprintf(stderr, "(in bk_ll_lookup) inode_cache_lookup failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (_populate_dir_index(fuse_global_state, fuse_thread_state, parent, parent_inode)) {
		fprintf(stderr, "(in bk_ll_lookup) _populate_dir_index failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	const uint64_t ino = dir_index_range_lookup(parent_inode->dir_index, &fuse_thread_state->d, name, strlen(name));
	if (!ino) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	const inode_t *inode = inode_cache_lookup(fuse_global_state->inode_cache, ino);
	if (!inode) {
		fprintf(stderr, "(in bk_ll_lookup) inode_cache_lookup failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	struct fuse_entry_param *e = &fuse_thread_state->e;
	e->generation = 1;
	e->ino = ino;
	stat_from_inode(fuse_global_state->ondiskidx, &e->attr, inode);
	e->attr.st_ino = ino;
	e->attr_timeout = 86400.0;
	e->entry_timeout = 86400.0;
	fuse_reply_entry(req, e);
	memset(e, 0, sizeof(struct fuse_entry_param));
}

/*
 * off mapping:
 * 0: start, "."
 * 1: ".."
 * 2: end of directory
 * 2 + x: = more entries, x = ino of next child (since ino > 0, this is always > 2)
 */
static void bk_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);
	fuse_thread_state_t *fuse_thread_state = fuse_thread_state_get(fuse_global_state);

	char *reply = fuse_thread_state_get_reply_buffer(fuse_global_state, fuse_thread_state, size);

	if (!reply) {
		fprintf(stderr, "(in bk_ll_readdir) fuse_thread_state_get_reply_buffer failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (off == 2) {
		// end of directory
		fuse_reply_buf(req, reply, 0);
		return;
	}

	size_t idx = 0;
	inode_t *self;

	if (off < 2) {
		self = inode_cache_lookup(fuse_global_state->inode_cache, ino);
		if (!self) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_lookup (%zd) failed\n", ino);
			fuse_reply_err(req, EIO);
			return;
		}
	} else {
		self = NULL;
	}

	if (off == 0) {
		struct stat stbuf;
		stat_from_inode(fuse_global_state->ondiskidx, &stbuf, self);
		stbuf.st_ino = ino;
		size_t n = fuse_add_direntry(req, reply + idx, size - idx, ".", &stbuf, ++off);
		if (n > size - idx) {
			goto full;
		}
		idx += n;
	}

	if (off == 1) {
		const inode_t *parent = self->parent_ino == ino ? self : inode_cache_lookup(fuse_global_state->inode_cache, self->parent_ino);
		if (!parent) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_lookup (%zd) failed\n", self->parent_ino);
			fuse_reply_err(req, EIO);
			return;
		}
		struct stat stbuf;
		stat_from_inode(fuse_global_state->ondiskidx, &stbuf, parent);
		stbuf.st_ino = self->parent_ino;
		size_t n = fuse_add_direntry(req, reply + idx, size - idx, "..", &stbuf, ++off);
		if (n > size - idx) {
			goto full;
		}
		idx += n;
	}

	assert(off >= 2);

	uint64_t child_ino = off - 2;

	if (!child_ino) {
		if (_populate_dir_index(fuse_global_state, fuse_thread_state, ino, self)) {
			fprintf(stderr, "(in bk_ll_readdir) _populate_dir_index failed\n");
			fuse_reply_err(req, EIO);
			return;
		}

		child_ino = self->first_child_ino;
	}

	while (child_ino) {
		const inode_t *child = inode_cache_lookup(fuse_global_state->inode_cache, child_ino);
		if (!child) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_lookup (%zd) failed\n", child_ino);
			fuse_reply_err(req, EIO);
			return;
		}

		struct stat stbuf;
		stat_from_inode(fuse_global_state->ondiskidx, &stbuf, child);
		stbuf.st_ino = child_ino;

		size_t n = fuse_add_direntry(req, reply + idx, size - idx, child->name, &stbuf, 2 + child->next_sibling_ino);
		if (n > size - idx) {
			goto full;
		}
		idx += n;
		child_ino = child->next_sibling_ino;
	}

	fuse_reply_buf(req, reply, idx);
	return;

full:
	if (idx) {
		fuse_reply_buf(req, reply, idx);
	} else {
		fuse_reply_err(req, ERANGE);
	}
	return;
}

static void bk_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);

	const inode_t *inode = inode_cache_lookup(fuse_global_state->inode_cache, ino);
	if (!inode) {
		fprintf(stderr, "(in bk_ll_open) inode_cache_lookup failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (S_ISDIR(inode->mode)) {
		fuse_reply_err(req, EISDIR);
	} else if (S_ISREG(inode->mode)) {
		fuse_reply_open(req, fi);
	} else {
		fuse_reply_err(req, EIO);
	}
}

static void bk_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);
	fuse_thread_state_t *fuse_thread_state = fuse_thread_state_get(fuse_global_state);

	char *reply = fuse_thread_state_get_reply_buffer(fuse_global_state, fuse_thread_state, size);

	if (!reply) {
		fprintf(stderr, "(in bk_ll_read) fuse_thread_state_get_reply_buffer failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	block_t *block = block_cache_get(
		&fuse_thread_state->block_thread_state,
		fuse_global_state->block_cache,
		fuse_global_state->inode_cache,
		fuse_global_state->index,
		ino, off);


	if (!block) {
		fprintf(stderr, "(in bk_ll_read) block_cache_get failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	size_t total = 0;
	ssize_t n;

	while (total < size && (n = block_read(
		&fuse_thread_state->block_thread_state,
		block,
		fuse_global_state->index,
		reply + total, size - total))) {
		if (n < 0) {
			fprintf(stderr, "(in bk_ll_read) block_read failed\n");
			block_cache_put(fuse_global_state->block_cache, block, 0, 0);
			fuse_reply_err(req, EIO);
			return;
		}

		total += n;
	}

	block_cache_put(fuse_global_state->block_cache, block, ino, off + total);
	fuse_reply_buf(req, reply, total);
}

static void bk_ll_readlink(fuse_req_t req, fuse_ino_t ino) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);
	fuse_thread_state_t *fuse_thread_state = fuse_thread_state_get(fuse_global_state);

	block_t *block = block_cache_get(
		&fuse_thread_state->block_thread_state,
		fuse_global_state->block_cache,
		fuse_global_state->inode_cache,
		fuse_global_state->index,
		ino, 0);

	if (!block) {
		fprintf(stderr, "(in bk_ll_readlink) block_cache_get failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	char* buf = fuse_thread_state->reply_buffer;
	size_t size = fuse_thread_state->reply_buffer_size;

	const ssize_t n = block_read(
		&fuse_thread_state->block_thread_state,
		block,
		fuse_global_state->index,
		buf, size);

	block_cache_put(fuse_global_state->block_cache, block, 0, 0);

	if (n < 0) {
		fprintf(stderr, "(in bk_ll_readlink) block_read failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (n >= size) {
		fprintf(stderr, "(in bk_ll_readlink) link too long\n");
		fuse_reply_err(req, ENAMETOOLONG);
		return;
	}

	buf[n] = 0;
	fuse_reply_readlink(req, buf);
}

static void bk_ll_statfs(fuse_req_t req, fuse_ino_t ino) {
	fuse_global_state_t *fuse_global_state = fuse_req_userdata(req);
	ondiskidx_t *ondiskidx = fuse_global_state->ondiskidx;

	struct statvfs stbuf;
	memset(&stbuf, 0, sizeof(struct statvfs));
	if (ondiskidx) {
		stbuf.f_bsize = ondiskidx->blksize;
		stbuf.f_frsize = ondiskidx->blksize;
		// very crude
		stbuf.f_blocks = be64toh(ondiskidx->header->dedup_compressed_bytes) / ondiskidx->blksize;
	} else {
		stbuf.f_bsize = MIN_BLOCK_SIZE;
		stbuf.f_frsize = MIN_BLOCK_SIZE;
	}
	fuse_reply_statfs(req, &stbuf);
}

static struct fuse_lowlevel_ops bk_ll_oper = {
	.lookup	= bk_ll_lookup,
	.getattr = bk_ll_getattr,
	.readdir = bk_ll_readdir,
	.open = bk_ll_open,
	.read = bk_ll_read,
	.readlink = bk_ll_readlink,
	.statfs = bk_ll_statfs,
};

int fuse_main(index_t *index, inode_cache_t *inode_cache, ondiskidx_t *ondiskidx, int argc, char *argv[]) {
	fuse_global_state_t fuse_global_state;
	memset(&fuse_global_state, 0, sizeof(fuse_global_state_t));

	fuse_global_state.index = index;
	fuse_global_state.ondiskidx = ondiskidx;
	fuse_global_state.mempool = inode_cache->mempool;
	fuse_global_state.inode_cache = inode_cache;

	if (fuse_global_state_setup(&fuse_global_state)) {
		fprintf(stderr, "fuse_thread_state_setup failed\n");
		return 1;
	}

	block_cache_t block_cache;
	if (block_cache_init(&block_cache, ondiskidx ? ondiskidx->blksize : MIN_BLOCK_SIZE)) {
		fprintf(stderr, "block_cache_init failed\n");
		return 1;
	}

	dir_index_t dir_index;
	if (dir_index_init(&dir_index, fuse_global_state.mempool)) {
		fprintf(stderr, "dir_index_init failed\n");
		block_cache_free(&block_cache);
		return 1;
	}

	fuse_global_state.block_cache = &block_cache;
	fuse_global_state.dir_index = &dir_index;


	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;
	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 && (ch = fuse_mount(mountpoint, &args)) != NULL) {
		struct fuse_session *se = fuse_lowlevel_new(&args, &bk_ll_oper, sizeof(bk_ll_oper), &fuse_global_state);
		if (se != NULL) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
#ifdef MULTITHREADED
				err = fuse_session_loop_mt(se);
#else
				err = fuse_session_loop(se);
#endif
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
	fuse_opt_free_args(&args);
	if (mountpoint) {
		free(mountpoint);
	}

	fuse_global_state_free(&fuse_global_state);
	dir_index_free(&dir_index);
	block_cache_free(&block_cache);

	return err ? 1 : 0;
}
