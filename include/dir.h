#ifndef BK_DIR_H
#define BK_DIR_H

// args_t
#include "types.h"

#include "index.h"
#include "block_stack.h"

typedef struct dentry {
	uint64_t ino;     /* inode number (synthetic) */
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


int dir_write(block_stack_t *bs, size_t depth, index_t *index, args_t *args, int fd, unsigned char *ref);
void dir_test();
int dir_read(block_stack_t *bs, size_t depth, index_t *index, unsigned char *ref, int ref_len);

ssize_t dir_entry_read(block_t *block, index_t *index,
	const dentry_t **dentry,
	const unsigned char **ref, size_t *ref_len,
	const unsigned char **name, size_t *namelen,
	const unsigned char **username, const unsigned char **groupname);

#endif
