#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "index.h"

int _normalize_name(char *name) {
	int name_len = strlen(name);

	if (name_len >= 4 && !memcmp(name + name_len - 4, ".idx", 4)) {
		name_len -= 4;
	}

	return name_len;
}

int add_ondiskidx_by_name(index_t *index, char *name, int idx_only) {
	int name_len = _normalize_name(name);
	char *name_temp = malloc(name_len + 6);

	memcpy(name_temp, name, name_len);
	memcpy(name_temp + name_len, ".idx", 5);

	const int ref_idx_fd = open(name_temp, O_RDONLY);
	if (ref_idx_fd < 0) {
		perror("error opening index file");
		fprintf(stderr, "error opening index file %s\n", name_temp);
		free(name_temp);
		return -1;
	}

	int ref_data_fd = 0;	
	
	if (!idx_only) {
		memcpy(name_temp + name_len, ".data", 6);

		ref_data_fd = open(name_temp, O_RDONLY);
		if (ref_data_fd < 0) {
			perror("error opening data file");
			fprintf(stderr, "error opening data file %s\n", name_temp);
			close(ref_idx_fd);
			free(name_temp);
			return -1;
		}
	}

	free(name_temp);

	if (index_add_ondiskidx(index, ref_idx_fd, ref_data_fd)) {
		close(ref_idx_fd);
		close(ref_data_fd);
		fprintf(stderr, "error adding index %s\n", name);
		return -1;
	}

	close(ref_idx_fd);
	return 0;
}

int open_outputs(index_t *index, char *name, int force) {
	int name_len = _normalize_name(name);
	char *name_temp = malloc(name_len + 6);

	memcpy(name_temp, name, name_len);

	const int flags = O_WRONLY | O_CREAT | __O_CLOEXEC | (force ? O_TRUNC : O_EXCL);

	memcpy(name_temp + name_len, ".idx", 5);
	const int idx_fd = open(name_temp, flags, 0666);
	if (idx_fd < 0) {
		perror("error opening index file for writing");
		fprintf(stderr, "error opening index file %s\n", name_temp);
		free(name_temp);
		return -1;
	}

	memcpy(name_temp + name_len, ".data", 6);
	const int data_fd = open(name_temp, flags, 0666);
	if (data_fd < 0) {
		perror("error opening data file for writing");
		fprintf(stderr, "error opening data file %s\n", name_temp);

		memcpy(name_temp + name_len, ".idx", 6);
		if (unlink(name_temp)) {
			perror("error unlinking index file");
			fprintf(stderr, "error unlinking index file %s\n", name_temp);
		}
		if (close(idx_fd)) {
			perror("error closing index file");
		}
		index->data_fd = 0;
		free(name_temp);
		return -1;
	}
	index->data_fd = data_fd;

	return idx_fd;
}

int close_outputs(index_t *index, int idx_fd, char *name, int fatal_error) {
	int name_len = _normalize_name(name);
	int rc = 0;

	if (fatal_error) {
		char *name_temp = malloc(name_len + 6);
		memcpy(name_temp + name_len, ".data", 6);
		if (unlink(name_temp)) {
			perror("error unlinking data file");
			fprintf(stderr, "error unlinking data file %s\n", name_temp);
			rc = -1;
		}

		memcpy(name_temp + name_len, ".idx", 5);
		if (unlink(name_temp)) {
			perror("error unlinking index file");
			fprintf(stderr, "error unlinking index file %s\n", name_temp);
			rc = -1;
		}
		free(name_temp);
	}
	
	if (close(idx_fd)) {
		perror("error closing index file");
		rc = -1;
	}

	if (close(index->data_fd)) {
		perror("error closing data file");
		rc = -1;
	}

	return rc;
}

int _hex_decode_nib(char c) {
	if ('0' <= c && c <= '9') {
		return c - '0';
	} else if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	} else if ('A' <= c && c <= 'F') {
		return c - 'A' + 10;
	} else {
		return -1;
	}
}

int parse_hex_reference(const char *hexref, unsigned char *ref) {
	size_t ref_len = 0;

	while (*hexref) {
		if (!*(hexref + 1)) {
			fprintf(stderr, "illegal reference\n");
			return -1;
		}

		const int n1 = _hex_decode_nib(*hexref);
		const int n2 = _hex_decode_nib(*(hexref + 1));
		if (n1 < 0 || n2 < 0) {
			fprintf(stderr, "illegal reference\n");
			return -1;
		}
		hexref += 2;
		ref[ref_len++] = (n1 << 4) | n2;
	}

	return ref_len;
}
