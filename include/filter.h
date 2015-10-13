#ifndef BK_FILTER_H
#define BK_FILTER_H

typedef struct filter_rule {
	size_t count;
	char **path;
	int include;
	char *pattern;
	int hit_count;
} filter_rule_t;

typedef struct filter_match {
	size_t capacity;
	size_t count;
	filter_rule_t **rules;
	size_t *idx;
	int include;
	filter_rule_t *this_rule;
} filter_match_t;

typedef struct filter {
	size_t rule_count;
	filter_rule_t **rules;

	size_t max_depth;
	size_t depth;
	filter_match_t *match;

	int flags;
} filter_t;

int filter_init(filter_t *filter, int flags);
int filter_rule_add(filter_t *filter, int include, const char *pattern);
void filter_free(filter_t *filter);

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

void filter_print_stats(filter_t *filter);

#endif
