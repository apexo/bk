#ifndef BK_BLOCK_H
#define BK_BLOCK_H

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <fcntl.h>

#include "types.h"

int block_init(block_t *block, size_t block_size);
void block_free(block_t *block);
int block_append(block_t *block, index_t *index, const unsigned char *data, size_t size);
int block_flush(block_t *block, index_t *index, unsigned char* ref);

int block_ref_length(const unsigned char *ref);

int block_setup(block_t *block, const unsigned char *ref, size_t ref_len);
int block_read(block_t *block, index_t *index, unsigned char *dst, size_t size);
int block_skip(block_t *block, index_t *index, size_t block_size, off64_t ofs);

#endif
