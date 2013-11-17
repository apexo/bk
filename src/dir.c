#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <lz4.h>

#include "dir.h"

#define RECURSION_LIMIT 100

int dir_write_state_init(dir_write_state_t *dws, args_t *args, index_t *index, mtime_index_t *mtime_index, size_t blksize) {
	memset(dws, 0, sizeof(dir_write_state_t));

	if (!(dws->block = malloc(blksize))) {
		goto oom;
	}

	if (!(dws->path = malloc(PATH_MAX))) {
		perror("out of memory");
		goto oom;
	}

	if (!(dws->block_thread_state.pack = malloc(LZ4_compressBound(blksize)))) {
		perror("out of memory");
		goto oom;
	}

	if (!(dws->block_thread_state.crypt = malloc(blksize))) {
		perror("out of memory");
		goto oom;
	}

	if (block_stack_init(&dws->block_stack, blksize, RECURSION_LIMIT)) {
		fprintf(stderr, "block_stack_init failed\n");
		goto err;
	}

	dws->args = args;
	dws->index = index;
	dws->mtime_index = mtime_index;
	dws->blksize = blksize;
	dws->path_capacity = PATH_MAX;

	return 0;

oom:
	perror("out of memory");
err:
	if (dws->block_thread_state.crypt) {
		free(dws->block_thread_state.crypt);
	}
	if (dws->block_thread_state.pack) {
		free(dws->block_thread_state.pack);
	}
	if (dws->path) {
		free(dws->path);
	}
	if (dws->block) {
		free(dws->block);
	}
	return -1;
}

void dir_write_state_free(dir_write_state_t *dws) {
	block_stack_free(&dws->block_stack);
	free(dws->block_thread_state.crypt);
	free(dws->block_thread_state.pack);
	free(dws->path);
	free(dws->block);
}

static int _dir_entry_write(dir_write_state_t *dws, size_t depth, block_t *block, int dirfd, char *name);

static int _dir_write_file(dir_write_state_t *dws, size_t depth, block_t *block, int fd) {
	ssize_t n;
	char* temp = block_stack_get_temp(&dws->block_stack, depth);

	while ((n = read(fd, temp, dws->blksize)) > 0) {
		if (block_append(&dws->block_thread_state, block, dws->index, temp, n)) {
			fprintf(stderr, "block_append failed\n");
			return -1;
		}
	}

	if (n < 0) {
		perror("read failed");
		return -1;
	}

	return 0;
}

int _dir_write_symlink(dir_write_state_t *dws, size_t depth, block_t *block, int fd) {
	char* temp = block_stack_get_temp(&dws->block_stack, depth);
	int n = readlinkat(fd, "", temp, dws->blksize);
	if (n < 0) {
		perror("readlinkat failed");
		return -1;
	}

	if (block_append(&dws->block_thread_state, block, dws->index, temp, n)) {
		fprintf(stderr, "block_append failed\n");
		return -1;
	}

	return 0;
}

int _dir_write_dir(dir_write_state_t *dws, size_t depth, block_t *block, int fd) {
	char* temp = block_stack_get_temp(&dws->block_stack, depth);
	off_t basep = 0;
	ssize_t n = getdirentries(fd, temp, dws->blksize, &basep);
	while (n > 0) {
		struct dirent *dent = (struct dirent*)temp;
		for (size_t pos = 0; pos < n; pos += dent->d_reclen, dent = (struct dirent*)(temp + pos)) {
			if (_dir_entry_write(dws, depth, block, fd, dent->d_name)) {
				fprintf(stderr, "_dir_entry_write failed\n");
				return -1;
			}
		}
		n = getdirentries(fd, temp, dws->blksize, &basep);
	}
	if (n < 0) {
		perror("getdirentries failed");
		return -1;
	}
	return 0;
}

int _dir_entry_write(dir_write_state_t *dws, size_t depth, block_t *block, int dirfd, char *name) {
	if (*name && *name == '.' && (!*(name+1) || (*(name+1) == '.' && !*(name+2)))) {
		return 0;
	}

	args_t *args = dws->args;
	int fd = 0, fd2 = 0, rc = -1;
	size_t org_path_length = dws->path_length, org_depth = args->filter.depth;

	fd = openat(dirfd, name, O_NOFOLLOW | O_RDONLY | O_NOATIME | O_PATH);
	if (fd < 0) {
		if (errno == ENOENT) {
			rc = 0;
			goto cleanup;
		}
		perror("openat failed");
		fprintf(stderr, "openat %d/%s failed\n", dirfd, name);
		goto cleanup;
	}

	struct stat buf;
	if (fstatat(fd, "", &buf, AT_NO_AUTOMOUNT | AT_EMPTY_PATH)) {
		perror("fstatat failed");
		fprintf(stderr, "fstatat %d/%s failed\n", dirfd, name);
		goto cleanup;
	}

	char ref[MAX_REF_SIZE];
	block_t *block_next = block_stack_get(&dws->block_stack, depth + 1);
	if (!block_next) {
		fprintf(stderr, "block_stack_get failed\n");
		goto cleanup;
	}

	block_next->raw_bytes = 0;
	block_next->allocated_bytes = 0;

	int include = S_ISDIR(buf.st_mode) ? filter_enter_directory(&args->filter, name) : filter_test_leaf(&args->filter, name);
	if (include < 0) {
		fprintf(stderr, "%s failed\n", S_ISDIR(buf.st_mode) ? "filter_enter_directory" : "filter_test_leaf");
		goto cleanup;
	}

	if (args->verbose || dws->mtime_index) {
		const size_t d = dws->path_length ? 1 : 0;
		const size_t namelen = strlen(name), req = dws->path_length + namelen + 1 + d;
		if (req > dws->path_capacity) {
			char *path = realloc(dws->path, req);
			if (!path) {
				perror("out of memory");
				goto cleanup;
			}
			dws->path = path;
			dws->path_capacity = req;
		}
		if (d) {
			dws->path[dws->path_length] = '/';
		}
		memcpy(dws->path + dws->path_length + d, name, namelen + 1);
		dws->path_length += namelen + d;
	}
	if (args->verbose) {
		const char *suffix1 = S_ISDIR(buf.st_mode) ? "/" : "";
		const char *suffix2 = include ? "" : " (excluded)";
		fprintf(stdout, "%s%s%s\n", dws->path, suffix1, suffix2);
	}

	if (!include) {
		rc = 0;
		goto cleanup;
	}

	if (args->list_only && !S_ISDIR(buf.st_mode)) {
		rc = 0;
		goto cleanup;
	}

	int ref_len = 0;

	if (S_ISREG(buf.st_mode)) {
		if (dws->mtime_index) {
			ref_len = mtime_index_lookup(dws->mtime_index, dws->path, dws->path_length, buf.st_size, buf.st_mtime, ref);
			if (ref_len > 0) {
				block_next->raw_bytes = buf.st_size;
				dws->index->header.total_bytes += buf.st_size;
				fprintf(stderr, "DEBUG: mtime match on %s\n", dws->path);
				goto terrific;
			}
		}

		fd2 = openat(dirfd, name, O_NOFOLLOW | O_RDONLY | O_NOATIME);
		if (fd2 < 0) {
			if (errno == ENOENT) {
				rc = 0;
				goto cleanup;
			}
			perror("openat failed");
			fprintf(stderr, "openat %d/%s failed [2]\n", dirfd, name);
			goto cleanup;
		}
		if (_dir_write_file(dws, depth + 1, block_next, fd2)) {
			fprintf(stderr, "_dir_write_file failed: %s\n", name);
			goto cleanup;
		}
		if (block_next->raw_bytes != buf.st_size) {
			fprintf(stderr, "file size changed: %zd -> %zd: %s\n", buf.st_size, block_next->raw_bytes, name);
		}
	} else if (S_ISDIR(buf.st_mode)) {
		fd2 = openat(dirfd, name, O_NOFOLLOW | O_RDONLY | O_NOATIME | O_DIRECTORY);
		if (fd2 < 0) {
			if (errno == ENOENT) {
				rc = 0;
				goto cleanup;
			}
			perror("openat failed");
			fprintf(stderr, "openat %d/%s failed [2]\n", dirfd, name);
			goto cleanup;
		}
		if (_dir_write_dir(dws, depth + 1, block_next, fd2)) {
			fprintf(stderr, "_dir_write_dir failed: %s\n", name);
			goto cleanup;
		}
	} else if (S_ISCHR(buf.st_mode)) {
	} else if (S_ISBLK(buf.st_mode)) {
	} else if (S_ISFIFO(buf.st_mode)) {
	} else if(S_ISLNK(buf.st_mode)) {
		if (_dir_write_symlink(dws, depth + 1, block_next, fd)) {
			fprintf(stderr, "_dir_write_symlink failed: %s\n", name);
			goto cleanup;
		}
	} else if (S_ISSOCK(buf.st_mode)) {
	} else {
		fprintf(stderr, "unknown file type: %s\n", name);
		goto cleanup;
	}

	if (args->list_only) {
		rc = 0;
		goto cleanup;
	}

	ref_len = block_flush(&dws->block_thread_state, block_next, dws->index, ref);
	if (ref_len < 0) {
		fprintf(stderr, "block_flush failed\n");
		goto cleanup;
	}

	if (dws->mtime_index && S_ISREG(buf.st_mode)) {
		if (mtime_index_add(dws->mtime_index, dws->path, dws->path_length, block_next->raw_bytes, buf.st_mtime, ref, ref_len)) {
			fprintf(stderr, "mtime_index_add failed\n");
			goto cleanup;
		}
	}
terrific:

	assert(ref_len >= 2);

	dentry_t d;
	memset(&d, 0, sizeof(d));

	struct group *grp = getgrgid(buf.st_gid);
	if (grp && (!grp->gr_name || strlen(grp->gr_name) > UINT8_MAX)) {
		grp = NULL;
	}

	struct passwd *pwd = getpwuid(buf.st_uid);
	if (pwd && (!pwd->pw_name || strlen(pwd->pw_name) > UINT8_MAX)) {
		pwd = NULL;
	}

	d.ino = htobe64(index_alloc_ino(dws->index));
	d.mode = htobe32(buf.st_mode);
	d.uid = htobe32(buf.st_uid);
	d.gid = htobe32(buf.st_gid);
	d.rdev = htobe64(buf.st_rdev);
	d.size = htobe64(block_next->raw_bytes);
	d.blocks = htobe64((block_next->allocated_bytes + 511) / 512);
	d.atime = htobe64(buf.st_atime);
	d.mtime = htobe64(buf.st_mtime);
	d.ctime = htobe64(buf.st_ctime);
	d.namelen = htobe16(strlen(name));
	d.usernamelen = pwd ? strlen(pwd->pw_name) : 0;
	d.groupnamelen = grp ? strlen(grp->gr_name) : 0;

	if (block_append(&dws->block_thread_state, block, dws->index, (char*)&d, sizeof(dentry_t))) {
		fprintf(stderr, "block_append failed\n");
		goto cleanup;
	}

	if (block_append(&dws->block_thread_state, block, dws->index, ref, ref_len)) {
		fprintf(stderr, "block_append failed\n");
		goto cleanup;
	}

	if (block_append(&dws->block_thread_state, block, dws->index, name, strlen(name))) {
		fprintf(stderr, "block_append failed\n");
		goto cleanup;
	}

	if (d.usernamelen && block_append(&dws->block_thread_state, block, dws->index, pwd->pw_name, d.usernamelen)) {
		fprintf(stderr, "block_append failed\n");
		goto cleanup;
	}

	if (d.groupnamelen && block_append(&dws->block_thread_state, block, dws->index, grp->gr_name, d.groupnamelen)) {
		fprintf(stderr, "block_append failed\n");
		goto cleanup;
	}

	rc = 0;

cleanup:
	if (fd2 > 0 && close(fd2)) {
		perror("close failed");
	}
	if (fd > 0 && close(fd)) {
		perror("close failed");
	}
	dws->path_length = org_path_length;
	args->filter.depth = org_depth;
	return rc;

}

int dir_write(dir_write_state_t *dws, size_t depth, int fd, char *ref) {
	block_t *block = block_stack_get(&dws->block_stack, depth);
	if (!block) {
		fprintf(stderr, "block_stack_get failed\n");
		return -1;
	}

	block->raw_bytes = 0;
	block->allocated_bytes = 0;

	if (_dir_write_dir(dws, depth, block, fd)) {
		fprintf(stderr, "_dir_write_dir failed\n");
		return -1;
	}

	int ref_len = block_flush(&dws->block_thread_state, block, dws->index, ref);
	if (ref_len < 0) {
		fprintf(stderr, "block_flush failed\n");
		return -1;
	}

	return ref_len;
}

#if 0
int _dir_read_dir(block_stack_t *bs, size_t depth, block_t *block, index_t *index, const char *ref, int ref_len);

int _dir_dentry_process(block_stack_t *bs, size_t depth, block_t *block, index_t *index,
	const dentry_t *dentry,
	const char *ref, int ref_len,
	const char *name, int name_len,
	const char *username, int username_len,
	const char *groupname, int groupname_len) {
	uint32_t mode = be32toh(dentry->mode);

	if (S_ISDIR(mode)) {
		fprintf(stdout, "%*.s%.*s", (int)(depth-1)*2, "", (int)name_len, name);
		fprintf(stdout, "/\n");
		if (_dir_read_dir(bs, depth, block, index, ref, ref_len)) {
			fprintf(stderr, "_dir_read_dir failed\n");
			fprintf(stderr, "%d\n", ref_len);
			return -1;
		}
		return 0;
	}

	if (S_ISREG(mode)) {
		return 0;
	}

	return 0;
}
#endif

ssize_t dir_entry_read(
	block_thread_state_t *block_thread_state,
	dir_thread_state_t *dir_thread_state,
	block_t *block, index_t *index,
	const dentry_t **dentry,
	const char **ref, size_t *ref_len,
	const char **name, size_t *namelen,
	const char **username, const char **groupname) {

	char *temp = dir_thread_state->dentry;
	dentry_t *dent = (dentry_t*)temp;
	char *dref = temp + sizeof(dentry_t);

	ssize_t n = 0;
	size_t req = sizeof(dentry_t) + 1;
	do {
		ssize_t m = block_read(block_thread_state, block, index, temp + n, req - n);
		if (m < 0) {
			fprintf(stderr, "block_read failed\n");
			return -1;
		}
		if (m == 0) {
			if (n) {
				fprintf(stderr, "unexpected end of directory\n");
				return -1;
			}
			return 0;
		}
		n += m;
		assert(n <= req);
	} while (n < req);

	size_t dnamelen = be16toh(dent->namelen);
	size_t dref_len = block_ref_length(dref);

	req = sizeof(dentry_t) + dref_len + dnamelen + dent->usernamelen + dent->groupnamelen;
	if (req > block->blksize) {
		fprintf(stderr, "dentry size exceeds block size\n");
		return -1;
	}
	do {
		ssize_t m = block_read(block_thread_state, block, index, temp + n, req - n);
		if (m < 0) {
			fprintf(stderr, "block_read failed\n");
			return -1;
		}
		if (m == 0) {
			fprintf(stderr, "unexpected end of directory\n");
			return -1;
		}
		n += m;
		assert(n <= req);
	} while (n <  req);

	*dentry = dent;
	*ref = dref;
	*ref_len = dref_len;
	*name = dref + block_ref_length(dref);
	*namelen = dnamelen;
	*username = *name + dnamelen;
	*groupname = *username + dent->usernamelen;

	return n;
}

#if 0
int _dir_read_dir(dir_thread_state *ts, block_stack_t *bs, size_t depth, block_t *block, index_t *index, const char *ref, int ref_len) {
	if (block_setup(block, ref, ref_len)) {
		fprintf(stderr, "block_setup failed\n");
		return -1;
	}

	block_t *block_next = block_stack_get(bs, depth + 1);

	ssize_t n = block_read(block, index, block->temp0, block->blksize);
	char *ptr = block->temp0;

	if (n < 0) {
		fprintf(stderr, "block_read failed\n");
		return -1;
	}

	if (n == 0) {
		return 0;
	}

	while (1) {
		//fprintf(stderr, "%zd @ %zd\n", n, ptr - block->temp0);
		const dentry_t *dent = (dentry_t*)ptr;
		const char *dref = ptr + sizeof(dentry_t);
		size_t req = sizeof(dentry_t);
		if (n > req) { // need one more byte (than req) to determine ref_len
			req += block_ref_length(dref) + be16toh(dent->namelen) + dent->usernamelen + dent->groupnamelen;
		} else { // 2 bytes is the minium ref_length, this makes sure that n < ref
			req += 2;
		}
		if (n < req) {
			if (req > block->blksize) {
				fprintf(stderr, "dentry size exceeds block size\n");
				return -1;
			}
			if (ptr != block->temp0) {
				//fprintf(stderr, "-> 0\n");
				memmove(block->temp0, ptr, n);
				ptr = block->temp0;
			}

			ssize_t m = block_read(&bs->block_thread_state, block, index, block->temp0 + n, block->blksize - n);
			if (m < 0) {
				fprintf(stderr, "block_read failed\n");
				return -1;
			}

			if (m == 0) {
				if (n) {
					fprintf(stderr, "unexpected end of directory\n");
					return -1;
				}
				return 0;
			}
			n += m;
			//fprintf(stderr, "+ %zd = %zd\n", m, n);
			continue;
		}

		const char* name = dref + block_ref_length(dref);
		const char* username = name + be16toh(dent->namelen);
		const char* groupname = name + dent->usernamelen;

		if (_dir_dentry_process(
			bs, depth+1, block_next, index,
			dent,
			dref, block_ref_length(dref),
			name, be16toh(dent->namelen),
			username, dent->usernamelen,
			groupname, dent->groupnamelen
		)) {
			fprintf(stderr, "_dir_dentry_process failed\n");
			return -1;
		}

		n -= req;
		ptr += req;
	}
	return 0;
}

int dir_read(block_stack_t *bs, size_t depth, index_t *index, char *ref, int ref_len) {
	block_t *block = block_stack_get(bs, depth);
	if (!block) {
		fprintf(stderr, "block_stack_get failed\n");
		return -1;
	}

	if (_dir_read_dir(bs, depth, block, index, ref, ref_len)) {
		fprintf(stderr, "_dir_read_dir failed\n");
		return -1;
	}

	return 0;
}

void dir_test() {
	index_t index;
	block_stack_t bs;
	block_stack_init(&bs, 65536, 100);
	args_t args;
	memset(&args, 0, sizeof(args_t));

	int fd = open("testdir", O_NOFOLLOW | O_RDONLY);
	if (fd < 0) {
		perror("open failed");
		return;
	}

	int n = dir_write(&bs, 0, &index, &args, fd, NULL);
	if (n < 0) {
		fprintf(stderr, "dir_write failed\n");
		return;
	}
}
#endif
