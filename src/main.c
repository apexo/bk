#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "types.h"
#include "index.h"
#include "block_stack.h"
#include "dir.h"
#include "filter.h"
#include "util.h"
#include "fuse.h"

#define DEFAULT_BLOCK_SIZE 65536

int do_help(int argc, char *argv[]) {
	fprintf(stdout, "Usage: %s [--help] <command> [<args>]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "Where command is one of:\n");
	fprintf(stdout, "   backup   Create backup.\n");
	fprintf(stdout, "   mount    Mount backup.\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "See '%s help <command>' for help on a specific subcommand.\n", argv[0]);
	return 1;
}

int do_help_backup(int argc, char *argv[]) {
	fprintf(stdout, "Usage: %s backup [-v] [-n|--no-act] [--xdev] [-E|--exclude|-I|--include <pattern>...] <path> [<target> [<index>...]]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "   -v                      Verbose output. Print names of files as they are being backed up.\n");
	fprintf(stdout, "   -n,--no-act             Don't write any outputs. Just walk directories and print what would be backed up. Implies -v.\n");
	fprintf(stdout, "   --xdev                  Do not descend into directories on other filesystems.\n");
	fprintf(stdout, "   -E,--exclude <pattern>  Exclude files/directories. E.g.: home/*/.cache, **/.*.swp\n");
	fprintf(stdout, "   -I,--include <pattern>  Include files/directories.\n");
	fprintf(stdout, "   --blksize <n>           Set block size; valid values for n range from 0 (4 KiByte) to 19 (2 GiByte); 4 (64 kiByte) is the default\n");
	return 1;
}

int do_help_mount(int argc, char *argv[]) {
	fprintf(stdout, "Usage: %s mount [-R|--root-ref <reference>] <index>... -- <mountpoint> [fuse-options]\n", argv[0]);
	fprintf(stdout, "\n");
	return 1;
}

int do_backup(int argc, char *argv[], int idx) {
	optind = idx;

	static struct option long_options[] = {
		{"no-act",  no_argument,       0, 0 },
		{"xdev",    no_argument,       0, 0 },
		{"exclude", required_argument, 0, 0 },
		{"include", required_argument, 0, 0 },
		{"blksize", required_argument, 0, 0 },
		{0,         0,                 0, 0 }
	};

	args_t args;
	memset(&args, 0, sizeof(args_t));
	if (filter_init(&args.filter, 0)) {
		fprintf(stderr, "filter_init failed\n");
		return 1;
	}
	index_t index;

	if (index_init(&index, (const unsigned char*)"SALT", 4)) {
		fprintf(stderr, "index_init failed\n");
		return 1;
	}

	size_t blksize = DEFAULT_BLOCK_SIZE;
	char *target = NULL;
	char *path = NULL;

	while (1) {
		int option_index;
		char c = getopt_long(argc, argv, "-vnE:I:", long_options, &option_index);

		if (c == -1)
			break;

		if (c == 'n' || (!c && option_index == 0)) {
			args.list_only = 1;
			args.verbose = 1;
			continue;
		}

		if (!c && option_index == 1) {
			args.xdev = 1;
			continue;
		}

		if (c == 'E' || (!c && option_index == 2)) {
			if (filter_rule_add(&args.filter, 0, optarg)) {
				fprintf(stderr, "filter_rule_add failed\n");
				return 1;
			}
			continue;
		}

		if (c == 'I' || (!c && option_index == 3)) {
			if (filter_rule_add(&args.filter, 1, optarg)) {
				fprintf(stderr, "filter_rule_add failed\n");
				return 1;
			}
			continue;
		}

		if (!c && option_index == 4) {
			char *endptr;
			long int v = strtol(optarg, &endptr, 10);
			if (*endptr || v == LONG_MIN || v == LONG_MAX || v < 0 || v > 19) {
				fprintf(stderr, "illegal blksize, must be 0 <= x <= 19: %s\n", optarg);
				return 1;
			}
			blksize = 4096 << v;
		}

		if (c == 1) {
			if (!path) {
				path = optarg;
			} else if (!target) {
				target = optarg;
			} else {
				if (add_ondiskidx_by_name(&index, optarg, 1)) {
					fprintf(stderr, "add_ondiskidx_by_name failed\n");
					return 1;
				}
			}
		}

		if (c == 'v') {
			args.verbose = 1;
			continue;
		}
	}

	if (!path) {
		fprintf(stderr, "path missing\n");
		return do_help_backup(argc, argv);
	}

	int idx_fd = 0;

	if (!args.list_only) {
		if (!target) {
			fprintf(stderr, "target missing\n");
			return do_help_backup(argc, argv);
		}
		idx_fd = open_outputs(&index, target, 0);
	}

	block_stack_t bs;

	if (block_stack_init(&bs, blksize, 100)) {
		fprintf(stderr, "block_stack_init failed\n");
		return 1;
	}

	int fd = open(path, O_NOFOLLOW | O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		perror("open failed");
		fprintf(stderr, "error opening directory %s\n", path);
		return 1;
	}

	unsigned char ref[MAX_REF_SIZE];
	int ref_len;
	if ((ref_len = dir_write(&bs, 0, &index, &args, fd, ref)) < 0) {
		fprintf(stderr, "dir_write failed\n");
		if (close(fd)) {
			perror("close failed");
		}
		block_stack_free(&bs);
		return 1;
	}

	if (close(fd)) {
		perror("close failed");
	}
	block_stack_free(&bs);

	if (!args.list_only) {
		if (index_write(&index, idx_fd, blksize)) {
			fprintf(stderr, "index_write failed\n");
			if (close_outputs(&index, idx_fd, target, 1)) {
				fprintf(stderr, "close_outputs failed\n");
			}
			return 1;
		}
		if (close_outputs(&index, idx_fd, target, 0)) {
			fprintf(stderr, "close_outputs failed\n");
			return 1;
		}	

		for (int i = 0; i < ref_len; i++) {
			fprintf(stdout, "%02x", ref[i]);
		}
		fprintf(stdout, "\n");
	}
	return 0;
}

int do_mount(int argc, char *argv[], int idx) {
	optind = idx;

	static struct option long_options[] = {
		{"root-ref", required_argument, 0, 0 },
		{0,          0,                 0, 0 }
	};

	int ref_len = 0;
	unsigned char ref[MAX_REF_SIZE];

	index_t index;

	if (index_init(&index, (const unsigned char*)"SALT", 4)) {
		fprintf(stderr, "index_init failed\n");
		return 1;
	}

	char c;
	int option_index;
	while ((c = getopt_long(argc, argv, "-R:", long_options, &option_index)) != -1) {
		if (c == 'R' || (!c && option_index == 0)) {
			if (ref_len) {
				fprintf(stderr, "duplicate root reference\n");
				index_free(&index);
				return do_help_mount(argc, argv);
			}
			ref_len = parse_hex_reference(optarg, ref);
			if (ref_len < 0) {
				fprintf(stderr, "illegal root reference\n");
				index_free(&index);
				return do_help_mount(argc, argv);
			}
			continue;
		}

		if (c == 1) {
			// TODO: check whether this could be a valid mountpoint (i.e.: an existing directory)
			if (add_ondiskidx_by_name(&index, optarg, 0)) {
				fprintf(stderr, "add_ondiskidx_by_name failed\n");
				index_free(&index);
				return 1;
			}
		}
	}

	if (!index.num_ondiskidx) {
		fprintf(stderr, "at least one index required\n");
		index_free(&index);
		return do_help_mount(argc, argv);
	}

	size_t blksize = 0;
	for (size_t i = 0; i < index.num_ondiskidx; i++) {
		if (index.ondiskidx_blksize[i] > blksize) {
			blksize = index.ondiskidx_blksize[i];
		}
	}

	char* arg0_a = argv[0];
	const char* arg0_b = " mount [...] --";
	size_t arglen = strlen(arg0_a) + strlen(arg0_b) + 1;
	for (size_t i = optind; i < argc; i++) {
		arglen += strlen(argv[i]) + 1;
	}
	const int fuse_argc = argc - optind + 1;
	char **fuse_argv = malloc(sizeof(char*) * fuse_argc);
	if (!fuse_argv) {
		perror("out of memory");
		index_free(&index);
		return 1;
	}
	char *fuse_args = malloc(arglen);
	if (!fuse_argc) {
		perror("out of memory");
		index_free(&index);
		free(fuse_argv);
		return 1;
	}
	char *argpos = fuse_args;
	fuse_argv[0] = argpos;
	memcpy(argpos, arg0_a, strlen(arg0_a)); argpos += strlen(arg0_a);
	memcpy(argpos, arg0_b, strlen(arg0_b)); argpos += strlen(arg0_b);
	*argpos = 0; argpos++;
	for (size_t i = optind; i < argc; i++) {
		fuse_argv[i - optind + 1] = argpos;
		memcpy(argpos, argv[i], strlen(argv[i]));
		argpos += strlen(argv[i]);
		*argpos = 0;
		argpos++;
	}
	assert(argpos == fuse_args + arglen);

	int rc = fuse_main(&index, ref, ref_len, blksize, fuse_argc, fuse_argv);
	index_free(&index);
	free(fuse_args);
	free(fuse_argv);
	return rc;
}

int main(int argc, char *argv[]) {
	if (argc <= 1) {
		return do_help(argc, argv);
	}

	if (!strcmp(argv[1], "backup")) {
		return do_backup(argc, argv, 2);
	} else if (!strcmp(argv[1], "mount")) {
		return do_mount(argc, argv, 2);
	} else if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
		if (argc > 2 && !strcmp(argv[2], "backup")) {
			return do_help_backup(argc, argv);
		} else if (argc > 2 && !strcmp(argv[2], "mount")) {
			return do_help_backup(argc, argv);
		} else {
			return do_help(argc, argv);
		}
	} else {
		return do_help(argc, argv);
	}
}
