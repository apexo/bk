#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <assert.h>
#include <string.h>

#include "filter.h"

static int filter_rule_init(filter_rule_t *filter_rule, int include, const char *pattern) {
	memset(filter_rule, 0, sizeof(filter_rule_t));

	char **path = malloc(sizeof(char*));
	if (!path) {
		perror("out of memory");
		return -1;
	}

	char *pos = path[0] = strdup(pattern);
	if (!pos) {
		perror("out of memory");
		free(path);
		return -1;
	}
	size_t path_idx = 1;

	while (1) {
		char *slash = strchrnul(pos, '/');
		if (slash == pos) {
			fprintf(stderr, "illegal pattern: must not contain empty components: %s\n", pattern);
			free(path[0]);
			free(path);
			return -1;
		}
		if ((slash - pos == 2 && !memcmp(pos, "..", 2)) || (slash - pos == 1 && !memcmp(pos, ".", 1))) {
			fprintf(stderr, "illegal pattern: must not contain ./.. components: %s\n", pattern);
			free(path[0]);
			free(path);
			return -1;
		}
		if (slash - pos == 2 && !memcmp(pos, "**", 2) && path_idx > 1 && !memcmp(path[path_idx-2], "**", 2)) {
			fprintf(stderr, "illegal pattern: must contain not more than one consecutive ** component: %s\n", pattern);
			free(path[0]);
			free(path);
			return -1;
		}

		if (!*slash) {
			break;
		}
		
		char **path_new = realloc(path, (path_idx+1)*sizeof(char*));
		if (!path_new) {
			perror("out of memory");
			free(path[0]);
			free(path);
			return -1;
		}
		path = path_new;

		path[path_idx++] = pos = slash + 1;
		*slash = 0;
	}

	filter_rule->count = path_idx;
	filter_rule->path = path;
	filter_rule->include = include;
	return 0;
}

static void filter_rule_free(filter_rule_t *filter_rule) {
	free(filter_rule->path[0]);
	free(filter_rule->path);
}

static int _filter_match_grow(filter_t *filter) {
	filter_match_t *match = realloc(filter->match, sizeof(filter_match_t)*(filter->max_depth + 1));
	if (!match) {
		perror("out of memory");
		return -1;
	}
	filter->match = match;
	memset(match + filter->max_depth, 0, sizeof(filter_match_t));
	filter->max_depth++;

	return 0;
}

int filter_init(filter_t *filter, int flags) {
	memset(filter, 0, sizeof(filter_t));
	if (_filter_match_grow(filter)) {
		fprintf(stderr, "_filter_match_grow failed\n");
		return -1;
	}
	filter->match[0].include = 1;
	filter->depth = 1;
	filter->flags = flags;
	return 0;
}

static int _filter_match_add(filter_match_t *match, filter_rule_t *rule, size_t idx) {
	if (match->count == match->capacity) {
		filter_rule_t **rules = realloc(match->rules, sizeof(filter_rule_t*)*(match->capacity+1));
		if (!rules) {
			perror("out of memory");
			return -1;
		}
		match->rules = rules;

		size_t *idx = realloc(match->idx, sizeof(size_t)*(match->capacity+1));
		if (!idx) {
			perror("out of memory");
			return -1;
		}
		match->idx = idx;

		match->capacity++;
	}
	
	match->rules[match->count] = rule;
	match->idx[match->count++] = idx;
	return 0;
}

int filter_rule_add(filter_t *filter, int include, const char *pattern) {
	filter_rule_t **rules = realloc(filter->rules, sizeof(filter_rule_t*)*(filter->rule_count+1));
	if (!rules) {
		perror("out of memory");
		return -1;
	}
	filter->rules = rules;

	filter_rule_t *rule = malloc(sizeof(filter_rule_t));
	if (!rule) {
		perror("out of memory");
		return -1;
	}
	rules[filter->rule_count] = rule;

	if (filter_rule_init(rule, include, pattern)) {
		fprintf(stderr, "filter_rule_init failed\n");
		free(rule);
		return -1;
	}
	filter->rule_count++;

	if (_filter_match_add(filter->match, rule, 0)) {
		fprintf(stderr, "_filter_match_add failed\n");
		filter_rule_free(rule);
		free(rule);
		return -1;
	}

	return 0;
}

/*
 * returns values:
 * -1: error
 * 0: no match
 * 1: partial match
 * 2: final match
 */
static int _filter_match_segment(filter_t *filter, filter_rule_t *rule, size_t idx, const char *name) {
	const char *pat = rule->path[idx];
	int match = fnmatch(pat, name, filter->flags);
	//fprintf(stderr, "fnmatch(\"%s\", \"%s\", %d) = %d\n", pat, name, filter->flags, match);
	if (match == 0) {
		if (idx + 1 == rule->count) {
			return 2;
		}
		return 1;
	} else if (match != FNM_NOMATCH) {
		fprintf(stderr, "fnmatch failed for pattern %s (code: %d)\n", pat, match);
		return -1;
	} else {
		return 0;
	}
}

int filter_enter_directory(filter_t *filter, const char *name) {
	if (filter->depth == filter->max_depth && _filter_match_grow(filter)) {
		fprintf(stderr, "_filter_match_grow failed\n");
		return -1;
	}

	const filter_match_t *m1 = filter->match + filter->depth - 1;
	filter_match_t *m2 = filter->match + filter->depth;
	m2->count = 0;

	filter_rule_t *matched_rule = NULL;

	size_t exclude_count = 0, include_count = 0;

	for (size_t i = 0; i < m1->count; i++) {
		const char *pat = m1->rules[i]->path[m1->idx[i]];
		if (!strcmp(pat, "**")) {
			if (m1->idx[i] + 1 < m1->rules[i]->count) {
				int match = _filter_match_segment(filter, m1->rules[i], m1->idx[i] + 1, name);
				if (match < 0) {
					fprintf(stderr, "_filter_match_segment failed\n");
					return -1;
				}
				if (match == 1 && _filter_match_add(m2, m1->rules[i], m1->idx[i] + 2)) {
					fprintf(stderr, "_filter_match_add failed\n");
					return -1;
				}
				if (match == 2) {
					matched_rule = m1->rules[i];
					break;
				}
				if (_filter_match_add(m2, m1->rules[i], m1->idx[i])) {
					fprintf(stderr, "_filter_match_add failed\n");
					return -1;
				}
				if (m1->rules[i]->include) {
					include_count++;
				} else {
					exclude_count++;
				}
			} else {
				// trailing **; kinda redundant (except when it's the only path segment)
				matched_rule = m1->rules[i];
				break;
			}
		} else {
			int match = _filter_match_segment(filter, m1->rules[i], m1->idx[i], name);
			if (match < 0) {
				fprintf(stderr, "_filter_match_segment failed\n");
				return -1;
			}
			if (match == 1 && _filter_match_add(m2, m1->rules[i], m1->idx[i] + 1)) {
				fprintf(stderr, "_filter_match_add failed\n");
				return -1;
			}
			if (match == 2) {
				matched_rule = m1->rules[i];
				break;
			}
			if (match == 1) {
				if (m1->rules[i]->include) {
					include_count++;
				} else {
					exclude_count++;
				}
			}
		}
	}

	if (matched_rule) {
		m2->include = matched_rule->include;
	} else {
		m2->include = m1->include;
	}

	if (m2->include) {
		if (!exclude_count) {
			m2->count = 0;
		}
	} else {
		if (!include_count) {
			return 0;
		}
	}
	filter->depth++;
	return 1;
}

void filter_exit_directory(filter_t *filter) {
	assert(filter->depth > 1);
	filter->depth--;
}

int filter_test_leaf(filter_t *filter, const char *name) {
	const filter_match_t *m1 = filter->match + filter->depth - 1;

	for (size_t i = 0; i < m1->count; i++) {
		const char *pat = m1->rules[i]->path[m1->idx[i]];
		if (!strcmp(pat, "**")) {
			if (m1->idx[i] + 1 < m1->rules[i]->count) {
				int match = _filter_match_segment(filter, m1->rules[i], m1->idx[i] + 1, name);
				if (match < 0) {
					fprintf(stderr, "_filter_match_segment failed\n");
					return -1;
				}
				if (match == 2) {
					return m1->rules[i]->include;
				}
			} else {
				return m1->rules[i]->include;
			}
		} else {
			int match = _filter_match_segment(filter, m1->rules[i], m1->idx[i], name);
			if (match < 0) {
				fprintf(stderr, "_filter_match_segment failed\n");
				return -1;
			}
			if (match == 2) {
				return m1->rules[i]->include;
			}
		}
	}

	return m1->include;
}

void filter_free(filter_t *filter) {
	for (size_t i = 0; i < filter->rule_count; i++) {
		filter_rule_free(filter->rules[i]);
		free(filter->rules[i]);
	}
	if (filter->rules) {
		free(filter->rules);
	}
	for (size_t i = 0; i < filter->max_depth; i++) {
		free(filter->match[i].rules);
		free(filter->match[i].idx);
	}
	if (filter->max_depth) {
		free(filter->match);
	}
}
