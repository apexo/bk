#ifndef BK_DIR_H
#define BK_DIR_H

#include "types.h"
#include "index.h"
#include "block_stack.h"

int dir_write(block_stack_t *bs, size_t depth, index_t *index, args_t *args, int fd, unsigned char *ref);
void dir_test();
int dir_read(block_stack_t *bs, size_t depth, index_t *index, unsigned char *ref, int ref_len);

ssize_t dir_entry_read(block_t *block, index_t *index,
	const dentry_t **dentry,
	const unsigned char **ref, size_t *ref_len,
	const unsigned char **name, size_t *namelen,
	const unsigned char **username, const unsigned char **groupname);

#endif
