#ifndef BK_UTIL_H
#define BK_UTIL_H

#include "types.h"
#include "mtime_index.h"
#include "index.h"

int add_ondiskidx_by_name(index_t *index, mtime_index_t *mtime_index, char *name, int idx_only, int ignore_midx);
int open_outputs(index_t *index, char *name, int force, int *idx_fd, int *midx_fd);
int close_outputs(index_t *index, int idx_fd, int midx_fd, char *name, int fatal_error);
int parse_hex_reference(const char *hexref, char *ref);
void hex_format(char *dst, const char *value, size_t bytes);
int write_all(int fd, char* data, size_t size);

#endif
