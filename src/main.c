#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>

#include "types.h"
#include "index.h"
#include "block_stack.h"
#include "dir.h"
#include "filter.h"
#include "util.h"
#include "fuse.h"


#define DEFAULT_BLOCK_SIZE 65536

static int read_root_ref_from_tty(int fd, unsigned char *ref) {
	// TODO: maybe put temp in locked memory?
	char temp[MAX_REF_SIZE * 2 + 1];

	struct termios termios, termios_org;
	if (tcgetattr(fd, &termios)) {
		perror("tcgetattr failed");
		return -1;
	}
	memcpy(&termios_org, &termios, sizeof(struct termios));

	termios.c_lflag = (termios.c_lflag & ~ECHO) | ICANON;
	if (termios.c_lflag != termios_org.c_lflag) {
		if (tcsetattr(fd, TCSANOW, &termios)) {
			perror("tcsetattr failed");
			return -1;
		}
	}

	fprintf(stderr, "root reference: ");

	ssize_t n = read(fd, temp, sizeof(temp));

	fprintf(stderr, "\n");

	if (termios.c_lflag != termios_org.c_lflag) {
		if (tcsetattr(fd, TCSANOW, &termios_org)) {
			perror("tcsetattr failed");
		}
	}

	if (n < 0) {
		perror("read failed");
		return -1;
	}

	if (!n) {
		fprintf(stderr, "read failed\n");
		return -1;
	}

	if (n == sizeof(temp) && temp[n - 1] != '\n') {
		fprintf(stderr, "reference too long\n");
		while (n == sizeof(temp) && temp[n - 1] != '\n') {
			n = read(fd, temp, sizeof(temp));
			if (n < 0) {
				perror("read failed");
			}
		}
		return -1;
	}

	if (temp[n - 1] != '\n') {
		fprintf(stderr, "expected line feed\n");
		return -1;
	}

	temp[n-1] = 0;
	int ref_len = parse_hex_reference(temp, ref);
	if (ref_len < 0) {
		return -1;
	}

	return ref_len;
}

static int read_root_ref_from_pipe(int fd, unsigned char *ref) {
	// TODO: maybe put temp in locked memory?
	char temp[MAX_REF_SIZE * 2 + 1];
	memset(temp, 0, sizeof(temp));

	size_t len = 0, n;
	char chr;
	while ((n = read(fd, &chr, 1)) == 1) {
		if (chr == '\n') {
			temp[len] = 0;
			n = 0;
			break;
		} else if (len == MAX_REF_SIZE * 2) {
			fprintf(stderr, "reference too long\n");
			return -1;
		} else {
			temp[len++] = chr;
		}
	}

	if (n < 0) {
		perror("read failed");
		return -1;
	}

	int ref_len = parse_hex_reference(temp, ref);
	if (ref_len < 0) {
		return -1;
	}

	return ref_len;
}

static int read_root_ref_from_stdin(unsigned char *ref) {
	const int fd = fileno(stdin);
	int result;
	if (isatty(fd)) {
		result = read_root_ref_from_tty(fd, ref);
	} else {
		result = read_root_ref_from_pipe(fd, ref); // _or_regular_file_or_whatever
	}
	return result;
}

int do_help(int argc, char *argv[]) {
	fprintf(stdout, "Usage: %s [--help] <command> [<args>]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "Where command is one of:\n");
	fprintf(stdout, "   backup   Create backup.\n");
	fprintf(stdout, "   mount    Mount backup.\n");
	fprintf(stdout, "   info     Display index information.\n");
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
	fprintf(stdout, "Usage: %s mount [-R|--root-ref <reference>] <index>... [--] <mountpoint> [fuse-options]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "   -R,--root-ref           The root reference. May also be entered on stdin.\n");
	return 1;
}

int do_help_info(int argc, char *argv[]) {
	fprintf(stdout, "Usage: %s info <index>...\n", argv[0]);
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

	if (index_init(&index, 0, (const unsigned char*)"SALT", 4)) {
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

	if (index_set_blksize(&index, blksize)) {
		fprintf(stderr, "index_set_blksize failed\n");
		return 1;
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
		if (index_write(&index, idx_fd)) {
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
	// TODO: maybe put ref in locked memory?
	unsigned char ref[MAX_REF_SIZE];

	index_t index;

	if (index_init(&index, 1, NULL, 0)) {
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
			// hide ref (from publicly viewable /proc/$$/cmdline)
			memset(optarg, 'X', strlen(optarg));
			continue;
		}

		if (c == 1) {
			struct stat stbuf;
			// could this be a mountpoint (i.e.: an existing directory)? if so, we assume fuse arguments start here
			if (!stat(optarg, &stbuf) && S_ISDIR(stbuf.st_mode)) {
				optind--;
				break;
			}

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

	if (!ref_len) {
		ref_len = read_root_ref_from_stdin(ref);
		if (ref_len < 0) {
			index_free(&index);
			return 1;
		}
	}
	close(fileno(stdin));

	size_t blksize = 0;
	for (size_t i = 0; i < index.num_ondiskidx; i++) {
		if (index.ondiskidx[i].blksize > blksize) {
			blksize = index.ondiskidx[i].blksize;
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

int do_info(int argc, char *argv[], int idx) {
	index_t index;

	char hash[BLOCK_KEY_SIZE * 2 + 1];

	for (; idx < argc; idx++) {
		if (index_init(&index, 1, NULL, 0)) {
			fprintf(stderr, "index_init failed\n");
			return 1;
		}

		if (add_ondiskidx_by_name(&index, argv[idx], 0)) {
			fprintf(stderr, "add_ondiskidx_by_name failed: %s\n", argv[idx]);
			index_free(&index);
			continue;
		}
		ondiskidx_t *ondiskidx = index.ondiskidx;

		fprintf(stdout, "%s:\n", argv[idx]);
		hex_format(hash, ondiskidx->header->index_hash, BLOCK_KEY_SIZE);
		fprintf(stdout, "\tindex hash: %s\n", hash);
		for (size_t i = 0; i < MAX_REFERENCED_INDICES; i++) {
			int flag = 0;
			for (size_t j = 0; j < BLOCK_KEY_SIZE; j++) {
				if (ondiskidx->header->referenced_indices[i][j]) {
					flag = 1;
					break;
				}
			}
			if (!flag) {
				break;
			}
			hex_format(hash, ondiskidx->header->referenced_indices[i], BLOCK_KEY_SIZE);
			fprintf(stdout, "\treferences index: %s\n", hash);
		}
		fprintf(stdout, "\ttotal: %'zd bytes in %'zd blocks\n",
			be64toh(ondiskidx->header->total_bytes),
			be64toh(ondiskidx->header->total_blocks));
		fprintf(stdout, "\tafter deduplication: %'zd bytes in %'zd blocks; compressed: %'zd bytes\n",
			be64toh(ondiskidx->header->dedup_bytes),
			be64toh(ondiskidx->header->dedup_blocks),
			be64toh(ondiskidx->header->dedup_compressed_bytes));
		fprintf(stdout, "\twritten: %'zd bytes in %'zd blocks; compressed: %'zd bytes\n",
			be64toh(ondiskidx->header->internal_bytes),
			be64toh(ondiskidx->header->internal_blocks),
			be64toh(ondiskidx->header->internal_compressed_bytes));
		fprintf(stdout, "\texternal references: %'zd bytes in %'zd blocks; compressed: %'zd bytes\n",
			be64toh(ondiskidx->header->dedup_bytes) - be64toh(ondiskidx->header->internal_bytes),
			be64toh(ondiskidx->header->dedup_blocks) - be64toh(ondiskidx->header->internal_blocks),
			be64toh(ondiskidx->header->dedup_compressed_bytes) - be64toh(ondiskidx->header->internal_compressed_bytes
		));

		index_free(&index);
	}

	return 0;
}

int main(int argc, char *argv[]) {
	if (argc <= 1) {
		return do_help(argc, argv);
	}

	if (!strcmp(argv[1], "backup")) {
		return do_backup(argc, argv, 2);
	} else if (!strcmp(argv[1], "mount")) {
		return do_mount(argc, argv, 2);
	} else if (!strcmp(argv[1], "info")) {
		return do_info(argc, argv, 2);
	} else if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
		if (argc > 2 && !strcmp(argv[2], "backup")) {
			return do_help_backup(argc, argv);
		} else if (argc > 2 && !strcmp(argv[2], "mount")) {
			return do_help_backup(argc, argv);
		} else if (argc > 2 && !strcmp(argv[2], "info")) {
			return do_help_info(argc, argv);
		} else {
			return do_help(argc, argv);
		}
	} else {
		return do_help(argc, argv);
	}
}
