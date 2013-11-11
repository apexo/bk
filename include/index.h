#ifndef BK_INDEX_H
#define BK_INDEX_H

#include "types.h"

int index_init(index_t *index, const unsigned char *salt, size_t salt_len);
int index_free(index_t *index);
int index_add_ondiskidx(index_t *index, int index_fd, int data_fd);
int index_add_block(index_t *index, block_key_t block_key, file_offset_t file_offset, block_size_t block_size, block_size_t compressed_block_size);
int index_write(index_t *index, int fd, size_t block_size);
int index_lookup(index_t *index, block_key_t key, int *data_fd, file_offset_t *file_offset, block_size_t *block_size, block_size_t *compressed_block_size, uint32_t *blksize);
uint64_t index_alloc_ino(index_t *index);

#endif
