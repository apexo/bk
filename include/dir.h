#ifndef BK_DIR_H
#define BK_DIR_H

#include <limits.h>

// args_t
#include "types.h"

#include "index.h"
#include "mtime_index.h"
#include "block_stack.h"

#define USERNAMELEN_MAX 255
#define GROUPNAMELEN_MAX 255
#define DENTRY_MAX_SIZE (sizeof(dentry_t) + MAX_REF_SIZE + PATH_MAX + USERNAMELEN_MAX + GROUPNAMELEN_MAX)

typedef struct dentry {
	uint64_t ino_unused;     /* inode number (synthetic) */
	uint64_t rdev;    /* device ID (if special file) */
	uint64_t size;    /* total size, in bytes */
	uint64_t blocks;  /* number of 512B blocks allocated */
	uint64_t atime;   /* time of last access */
	uint64_t mtime;   /* time of last modification */
	uint64_t ctime;   /* time of last status change */
	uint32_t mode;    /* protection */
	uint32_t uid;     /* user ID of owner */
	uint32_t gid;     /* group ID of owner */
	uint16_t namelen;
	uint8_t usernamelen;
	uint8_t groupnamelen;
} dentry_t;

typedef struct dir_thread_state {
        char* dentry; // DENTRY_MAX_SIZE, in locked memory
} dir_thread_state_t;

typedef struct dir_write_thread_state {
	block_stack_t block_stack;
	block_thread_state_t block_thread_state;

	args_t *args;
	index_t *index;
	mtime_index_t *mtime_index;

	size_t blksize;
	char* block; // blksize

	size_t path_length;
	size_t path_capacity; // initialized at PATH_MAX
	char *path; // path_capacity
} dir_write_state_t;

int dir_write_state_init(dir_write_state_t *dir_write_state, args_t *args, index_t *index, mtime_index_t *mtime_index, size_t blksize);
int dir_write(dir_write_state_t *dir_write_state, size_t depth, int fd, char *ref);
void dir_write_state_free(dir_write_state_t *dir_write_state);

//int dir_read(block_stack_t *bs, size_t depth, index_t *index, char *ref, int ref_len);

ssize_t dir_entry_read(block_thread_state_t *block_thread_state, dir_thread_state_t *dir_thread_state, block_t *block, index_t *index,
	const dentry_t **dentry,
	const char **ref, size_t *ref_len,
	const char **name, size_t *namelen,
	const char **username, const char **groupname);

#endif
