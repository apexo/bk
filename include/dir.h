#ifndef BK_DIR_H
#define BK_DIR_H

#include "types.h"

int dir_write(block_stack_t *bs, size_t depth, index_t *index, int fd, unsigned char *ref);
void dir_test();
int dir_read(block_stack_t *bs, size_t depth, index_t *index, unsigned char *ref, int ref_len);

#endif
