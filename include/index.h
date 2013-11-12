#ifndef BK_INDEX_H
#define BK_INDEX_H

#include "types.h"

int index_init(index_t *index, int readonly, const unsigned char *salt, size_t salt_len);
int index_set_blksize(index_t *index, block_size_t blksize);
int index_free(index_t *index);
int index_ondiskidx_add(index_t *index, int index_fd, int data_fd);
int index_add_block(index_t *index, block_key_t block_key, file_offset_t file_offset, block_size_t block_size, block_size_t compressed_block_size);
int index_write(index_t *index, int fd);
int index_lookup(index_t *index, block_key_t key, file_offset_t *file_offset, block_size_t *block_size, block_size_t *compressed_block_size, ondiskidx_t **ondiskidx);
uint64_t index_alloc_ino(index_t *index);

#endif
