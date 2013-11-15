#ifndef BK_UTIL_H
#define BK_UTIL_H

#include "types.h"

int add_ondiskidx_by_name(index_t *index, char *name, int idx_only);
int open_outputs(index_t *index, char *name, int force);
int close_outputs(index_t *index, int idx_fd, char *name, int fatal_error);
int parse_hex_reference(const char *hexref, char *ref);
void hex_format(char *dst, const char *value, size_t bytes);

#endif
