#ifndef BK_FILTER_H
#define BK_FILTER_H

#include "types.h"

int filter_init(filter_t *filter, int flags);
int filter_rule_add(filter_t *filter, int include, const char *pattern);

/*
 * returns -1 on error, 0 when the directory is filtered out, and 1 on success;
 * filter_exit_directory must only be called on success
 */
int filter_enter_directory(filter_t *filter, const char *name);

void filter_exit_directory(filter_t *filter);

/*
 * returns -1 on error, 0 when the leaf is filtered out, and 1 on success
 */
int filter_test_leaf(filter_t *filter, const char *name);

#endif
