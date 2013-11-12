#define FUSE_USE_VERSION 30
#include <fuse/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "types.h"
#include "inode_cache.h"
#include "block_cache.h"
#include "block.h"
#include "dir.h"

inode_cache_t inode_cache;
block_cache_t block_cache;
index_t *block_index;

static void stat_from_inode(struct stat *stbuf, const inode_t *inode) {
	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = inode->mode;
	stbuf->st_nlink = 1;
	stbuf->st_uid = inode->uid;
	stbuf->st_gid = inode->gid;
	stbuf->st_rdev = inode->rdev;
	stbuf->st_size = inode->size;
	stbuf->st_blksize = 65536; //inode->blksize; TODO: determine proper blksize from index
	stbuf->st_blocks = inode->blocks;
	stbuf->st_atime = inode->atime;
	stbuf->st_mtime = inode->mtime;
	stbuf->st_ctime = inode->ctime;
}

static void bk_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	const inode_t *inode = inode_cache_lookup(&inode_cache, ino);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	struct stat stbuf;
	stat_from_inode(&stbuf, inode);
	stbuf.st_ino = ino;
	fuse_reply_attr(req, &stbuf, 86400.0);
}

static void bk_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	size_t cache_index;
	block_t *block = block_cache_get(&block_cache, &inode_cache, block_index, parent, 0, &cache_index);
	if (!block) {
		fprintf(stderr, "(in bk_ll_lookup) block_cache_get failed\n");
		fuse_reply_err(req, ENODEV);
		return;
	}

	off_t off = 0;
	size_t ref_len, dnamelen, usernamelen, groupnamelen, namelen = strlen(name);
	const unsigned char *ref, *dname, *username, *groupname;
	const dentry_t *dentry;
	struct fuse_entry_param e;
	e.generation = 0;

	ssize_t n;
	while ((n = dir_entry_read(block, block_index, &dentry,
		&ref, &ref_len,
		&dname, &dnamelen,
		&username, &usernamelen,
		&groupname, &groupnamelen)) > 0) {
		off += n;

		if (namelen == dnamelen && !memcmp(name, dname, namelen)) {
			e.ino = be64toh(dentry->ino);
			const inode_t *inode = inode_cache_add(&inode_cache, parent, dentry, ref, ref_len);
			if (!inode) {
				fprintf(stderr, "(in bk_ll_lookup) inode_cache_add failed\n");
				fuse_reply_err(req, ENODEV);
				return;
			}

			e.generation = 1;
			stat_from_inode(&e.attr, inode);
			e.attr.st_ino = e.ino;
			e.attr_timeout = 86400.0;
			e.entry_timeout = 86400.0;
			break;
		}
	}

	if (n < 0) {
		fprintf(stderr, "(in bk_ll_lookup) dir_entry_read failed\n");
		fprintf(stderr, "ino: %zd, name: %s\n", parent, name);
		fuse_reply_err(req, ENODEV);
		return;
	}

	block_cache_put(&block_cache, cache_index, parent, off);

	if (!e.generation) {
		fuse_reply_err(req, ENOENT);
	} else {
		fuse_reply_entry(req, &e);
	}
}

static void bk_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
	char *name = NULL;
	//fprintf(stderr, "readdir %zd @ %zd / %zd\n", ino, off, size);

	char *reply = malloc(size);
	if (!reply) {
		perror("(in bk_ll_readdir) out of memory");
		fuse_reply_err(req, ENOMEM);
		return;
	}

	size_t idx = 0;
	const inode_t *self;

	if (off < 2) {
		self = inode_cache_lookup(&inode_cache, ino);
		if (!self) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_lookup (%zd) failed\n", ino);
			fuse_reply_err(req, ENODEV);
			goto cleanup;
		}
	} else {
		self = NULL;
	}

	if (off == 0) {
		struct stat stbuf;
		stat_from_inode(&stbuf, self);
		stbuf.st_ino = ino;
		size_t n = fuse_add_direntry(req, reply + idx, size - idx, ".", &stbuf, off+1);
		if (n > size - idx) {
			goto full;
		}
		off++;
		idx += n;
	}

	if (off == 1) {
		const inode_t *parent = self->parent_ino == ino ? self : inode_cache_lookup(&inode_cache, self->parent_ino);
		if (!parent) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_lookup (%zd) failed\n", self->parent_ino);
			fuse_reply_err(req, ENODEV);
			goto cleanup;
		}
		struct stat stbuf;
		stat_from_inode(&stbuf, parent);
		stbuf.st_ino = self->parent_ino;
		size_t n = fuse_add_direntry(req, reply + idx, size - idx, "..", &stbuf, off+1);
		if (n > size - idx) {
			goto full;
		}
		off++;
		idx += n;
	}

	assert(off >= 2);

	size_t cache_index;
	block_t *block = block_cache_get(&block_cache, &inode_cache, block_index, ino, off-2, &cache_index);

	if (!block) {
		fprintf(stderr, "(in bk_ll_readdir) block_cache_get failed\n");
		fuse_reply_err(req, ENODEV);
		goto cleanup;
	}

	size_t ref_len, dnamelen, usernamelen, groupnamelen, namelen = 256;
	const unsigned char *ref, *dname, *username, *groupname;
	const dentry_t *dentry;
	name = malloc(namelen);

	if (!name) {
		perror("(in bk_ll_readdir) out of memory");
		fuse_reply_err(req, ENOMEM);
		goto cleanup;
	}

	ssize_t n;

	while ((n = dir_entry_read(block, block_index, &dentry,
		&ref, &ref_len,
		&dname, &dnamelen,
		&username, &usernamelen,
		&groupname, &groupnamelen)) > 0) {

		if (dnamelen + 1 > namelen) {
			namelen = dnamelen + 1;
			char *name2 = realloc(name, namelen);
			if (!name2) {
				perror("(in bk_ll_readdir) out of memory");
				fuse_reply_err(req, ENOMEM);
				goto cleanup;
			}
			name = name2;
		}

		const inode_t *inode = inode_cache_add(&inode_cache, ino, dentry, ref, ref_len);
		if (!inode) {
			fprintf(stderr, "(in bk_ll_readdir) inode_cache_add failed\n");
			fuse_reply_err(req, ENODEV);
			goto cleanup;
		}

		memcpy(name, dname, dnamelen);
		name[dnamelen] = 0;

		struct stat stbuf;
		stat_from_inode(&stbuf, inode);
		stbuf.st_ino = be64toh(dentry->ino);
		size_t m = fuse_add_direntry(req, reply + idx, size - idx, name, &stbuf, off + n);
		if (m > size - idx) {
			if (block->idx[0] >= n) {
				// easy: "unread" dentry and put block back in cache
				block->idx[0] -= n;
				block_cache_put(&block_cache, cache_index, ino, off - 2);
			} // otherwise: dentry was probably split on block boundary
			goto full;
		}
		idx += m;
		off += n;
	}

	if (n < 0) {
		fprintf(stderr, "(in bk_ll_readdir) dir_entry_read failed\n");
		fuse_reply_err(req, ENODEV);
		goto cleanup;
	}

	//fprintf(stderr, "readdir -> %zd / %zd\n", idx, off);

	block_cache_put(&block_cache, cache_index, ino, off - 2);
	fuse_reply_buf(req, reply, idx);
	goto cleanup;

full:
	if (idx) {
		fuse_reply_buf(req, reply, idx);
	} else {
		fuse_reply_err(req, ENOSPC);
	}

cleanup:
	if (name) {
		free(name);
	}
	free(reply);
	return;
}

static void bk_ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	const inode_t *inode = inode_cache_lookup(&inode_cache, ino);
	if (!inode) {
		fprintf(stderr, "(in bk_ll_open) inode_cache_lookup failed\n");
		fuse_reply_err(req, ENOENT);
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
	size_t cache_index;
	block_t *block = block_cache_get(&block_cache, &inode_cache, block_index, ino, off, &cache_index);

	if (!block) {
		fprintf(stderr, "(in bk_ll_read) block_cache_get failed\n");
		fuse_reply_err(req, ENODEV);
		return;
	}

	const ssize_t n = block_read(block, block_index, block->temp0, size);

	if (n < 0) {
		fprintf(stderr, "(in bk_ll_read) block_read failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (n) {
		block_cache_put(&block_cache, cache_index, ino, off + n);
		fuse_reply_buf(req, (char*)block->temp0, n);
	} else {
		fuse_reply_buf(req, NULL, 0);
	}
}

static void bk_ll_readlink(fuse_req_t req, fuse_ino_t ino) {
	size_t cache_index;
	block_t *block = block_cache_get(&block_cache, &inode_cache, block_index, ino, 0, &cache_index);

	if (!block) {
		fprintf(stderr, "(in bk_ll_readlink) block_cache_get failed\n");
		fuse_reply_err(req, ENODEV);
		return;
	}

	const ssize_t n = block_read(block, block_index, block->temp0, block->blksize);

	if (n < 0) {
		fprintf(stderr, "(in bk_ll_readlink) block_read failed\n");
		fuse_reply_err(req, EIO);
		return;
	}

	if (n >= block->blksize) {
		fprintf(stderr, "(in bk_ll_readlink) link too long\n");
		fuse_reply_err(req, ENAMETOOLONG);
		return;
	}

	block->temp0[n] = 0;

	fuse_reply_readlink(req, (char*)block->temp0);
}


static struct fuse_lowlevel_ops bk_ll_oper = {
	.lookup	= bk_ll_lookup,
	.getattr = bk_ll_getattr,
	.readdir = bk_ll_readdir,
	.open = bk_ll_open,
	.read = bk_ll_read,
	.readlink = bk_ll_readlink,
};

int fuse_main(index_t *index, const unsigned char *ref, int ref_len, size_t blksize, int argc, char *argv[]) {
	if (inode_cache_init(&inode_cache, ref, ref_len)) {
		fprintf(stderr, "inode_cache_init failed\n");
		return 1;
	}
	if (block_cache_init(&block_cache, blksize)) {
		fprintf(stderr, "block_cache_init failed\n");
		inode_cache_free(&inode_cache);
		return 1;
	}

	block_index = index;

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;
	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 && (ch = fuse_mount(mountpoint, &args)) != NULL) {
		struct fuse_session *se = fuse_lowlevel_new(&args, &bk_ll_oper, sizeof(bk_ll_oper), NULL);
		if (se != NULL) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
				err = fuse_session_loop(se);
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
	fuse_opt_free_args(&args);

	block_cache_free(&block_cache);
	inode_cache_free(&inode_cache);

	return err ? 1 : 0;
}
