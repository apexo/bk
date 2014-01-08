#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

#include "types.h"
#include "index.h"
#include "block_stack.h"
#include "dir.h"
#include "filter.h"
#include "util.h"
#include "fuse.h"
#include "inode_cache.h"
#include "mempool.h"
#include "mtime_index.h"
#include "salt.h"


#define DEFAULT_BLOCK_SIZE 65536
#define MAX_HEXREF_SIZE ((MAX_REF_SIZE)*2+1)

static int _check_root_reference(index_t *index, char *ref, ondiskidx_t **ondiskidx_ret) {
	const size_t len = ref[0], indir = ref[1];

	if (!indir || len < BLOCK_KEY_SIZE) {
		// empty reference (?)
		*ondiskidx_ret = NULL;
		return 0;
	}

	block_size_t block_size, compressed_block_size;
	file_offset_t file_offset;
	ondiskidx_t *ondiskidx;

	block_key_t storage_key;
	SHA256_CTX ctx;
	memcpy(&ctx, &(index->storage_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, ref + 2, BLOCK_KEY_SIZE);
	SHA256_Final((unsigned char*)storage_key, &ctx);

	if (index_lookup(index, storage_key, &file_offset, &block_size, &compressed_block_size, &ondiskidx)) {
		fprintf(stderr, "error resolving root reference, you either have the wrong reference or you're missing the correct index\n");
		return -1;
	}

	assert(ondiskidx);
	*ondiskidx_ret = ondiskidx;

	int rc = 0;

	for (size_t i = 0; i < MAX_REFERENCED_INDICES; i++) {
		int zero = 1;
		for (size_t j = 0; j < BLOCK_KEY_SIZE; j++) {
			if (ondiskidx->header->referenced_indices[i][j]) {
				zero = 0;
				break;
			}
		}
		if (zero) {
			break;
		}

		int found = 0;
		for (size_t j = 0; j < index->num_ondiskidx; j++) {
			ondiskidx_t *test = index->ondiskidx + j;
			if (test == ondiskidx) {
				continue;
			}
			if (!memcmp(test->header->index_hash, ondiskidx->header->referenced_indices[i], BLOCK_KEY_SIZE)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			rc = 1;
			char hash[BLOCK_KEY_SIZE * 2 + 1];
			hex_format(hash, ondiskidx->header->referenced_indices[i], BLOCK_KEY_SIZE);
			fprintf(stderr, "missing index: %s\n", hash);
		}
	}

	return rc;
}

static int read_root_ref_from_tty(int fd, char* temp, char *ref) {
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

	ssize_t n = read(fd, temp, MAX_HEXREF_SIZE);

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

	if (n == MAX_HEXREF_SIZE && temp[n - 1] != '\n') {
		fprintf(stderr, "reference too long\n");
		while (n == sizeof(temp) && temp[n - 1] != '\n') {
			n = read(fd, temp, MAX_HEXREF_SIZE);
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

static int read_root_ref_from_pipe(int fd, char* temp, char *ref) {
	memset(temp, 0, MAX_HEXREF_SIZE);

	size_t len = 0;
	ssize_t n;
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

static int read_root_ref_from_stdin(char *temp, char *ref) {
	const int fd = fileno(stdin);
	int result;
	if (isatty(fd)) {
		result = read_root_ref_from_tty(fd, temp, ref);
	} else {
		result = read_root_ref_from_pipe(fd, temp, ref); // _or_regular_file_or_whatever
	}
	return result;
}

int do_help(char *argv[]) {
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

int do_help_backup(char *argv[]) {
	fprintf(stdout, "Usage: %s backup [-v] [-n|--no-act] [--xdev] [--create-midx] [--dont-use-midx] [--dont-save-atime] [--lz4hc] [-E|--exclude|-I|--include <pattern>...] <path> [<target> [<index>...]]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "   -v                      Verbose output. Print names of files as they are being backed up.\n");
	fprintf(stdout, "   -n,--no-act             Don't write any outputs. Just walk directories and print what would be backed up. Implies -v.\n");
	fprintf(stdout, "   --xdev                  Do not descend into directories on other filesystems.\n");
	fprintf(stdout, "   --create-midx           Create midx for fast, mtime-based deduplication. Potentially unsafe, read the docs! Default: disabled.\n");
	fprintf(stdout, "   --dont-use-midx         Don't use existing midx. Default: use existing an midx.\n");
	fprintf(stdout, "   --dont-save-atime       Don't save atime (use ctime instead). May shrink differential backups.\n");
	fprintf(stdout, "   --lz4hc                 Use LZ4's high compression mode. Significantly slower but saves some space. Decompression is still very fast.\n");
	fprintf(stdout, "   -E,--exclude <pattern>  Exclude files/directories. E.g.: home/*/.cache, **/.*.swp\n");
	fprintf(stdout, "   -I,--include <pattern>  Include files/directories.\n");
	fprintf(stdout, "   --blksize <n>           Set block size; valid values for n range from 0 (4 KiByte) to 19 (2 GiByte); 4 (64 kiByte) is the default\n");
	return 1;
}

int do_help_mount(char *argv[]) {
	fprintf(stdout, "Usage: %s mount [-R|--root-ref <reference>] <index>... [--] <mountpoint> [fuse-options]\n", argv[0]);
	fprintf(stdout, "\n");
	fprintf(stdout, "   -R,--root-ref           The root reference. May also be entered on stdin.\n");
	fprintf(stdout, "   --stats                 Calculate number of blocks used.\n");
	return 1;
}

int do_help_info(char *argv[]) {
	fprintf(stdout, "Usage: %s info <index>...\n", argv[0]);
	return 1;
}

int do_backup(int argc, char *argv[], int idx) {
	int rc = 1, f_index = 0, f_filter = 0, f_dws = 0, f_midx = 0, dir_fd = -1, idx_fd = -1, midx_fd = -1, ref_len = 0;
	char *target = NULL;
	optind = idx;

	static struct option long_options[] = {
		{"no-act",  no_argument,       0, 0 },
		{"xdev",    no_argument,       0, 0 },
		{"exclude", required_argument, 0, 0 },
		{"include", required_argument, 0, 0 },
		{"blksize", required_argument, 0, 0 },

		{"create-midx",   no_argument, 0, 0 },
		{"dont-use-midx", no_argument, 0, 0 },
		{"dont-save-atime", no_argument, 0, 0 },
		{"lz4hc",   no_argument, 0, 0 },
		{0,         0,                 0, 0 }
	};

	args_t args;
	memset(&args, 0, sizeof(args_t));
	if (filter_init(&args.filter, 0)) {
		fprintf(stderr, "filter_init failed\n");
		goto out;
	}
	f_filter = 1;

	char salt[SALT_LENGTH];
	ssize_t salt_length = get_salt(salt, SALT_LENGTH);
	if (salt_length < 0) {
		fprintf(stderr, "get_salt failed\n");
		goto out;
	}

	index_t index;
	if (index_init(&index, 0, salt, salt_length)) {
		fprintf(stderr, "index_init failed\n");
		goto out;
	}
	f_index = 1;

	mtime_index_t mtime_index;
	if (mtime_index_init(&mtime_index, salt, salt_length)) {
		fprintf(stderr, "mtime_index_init failed\n");
		goto out;
	}
	f_midx = 1;

	memset(salt, 0, SALT_LENGTH);

	size_t blksize = DEFAULT_BLOCK_SIZE;
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
				goto out;
			}
			continue;
		}

		if (c == 'I' || (!c && option_index == 3)) {
			if (filter_rule_add(&args.filter, 1, optarg)) {
				fprintf(stderr, "filter_rule_add failed\n");
				goto out;
			}
			continue;
		}

		if (!c && option_index == 4) {
			char *endptr;
			long int v = strtol(optarg, &endptr, 10);
			if (*endptr || v == LONG_MIN || v == LONG_MAX || v < 0 || v > 19) {
				fprintf(stderr, "illegal blksize, must be 0 <= x <= 19: %s\n", optarg);
				goto out;
			}
			blksize = 4096 << v;
		}

		if (!c && option_index == 5) {
			args.create_midx = 1;
		}

		if (!c && option_index == 6) {
			args.dont_use_midx = 1;
		}

		if (!c && option_index == 7) {
			args.dont_save_atime = 1;
		}

		if (!c && option_index == 8) {
			args.lz4hc = 1;
		}

		if (c == 1) {
			if (!path) {
				path = optarg;
			} else if (!target) {
				target = optarg;
			} else {
				if (add_ondiskidx_by_name(&index, &mtime_index, optarg, 1, args.dont_use_midx)) {
					fprintf(stderr, "add_ondiskidx_by_name failed\n");
					goto out;
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
		goto out;
	}

	if (!path) {
		fprintf(stderr, "path missing\n");
		rc = do_help_backup(argv);
		goto out;
	}

	if (!args.list_only) {
		if (!target) {
			fprintf(stderr, "target missing\n");
			rc = do_help_backup(argv);
			goto out;
		}

		if (open_outputs(&index, target, 0, &idx_fd, args.create_midx ? &midx_fd : NULL)) {
			fprintf(stderr, "open_outputs failed\n");
			goto out;
		}
	}

	dir_write_state_t dws;

	if (dir_write_state_init(&dws, &args, &index, &mtime_index, blksize)) {
		fprintf(stderr, "dir_write_state_init failed\n");
		goto out;
	}
	f_dws = 1;

	dir_fd = open(path, O_NOFOLLOW | O_RDONLY | O_DIRECTORY);
	if (dir_fd < 0) {
		perror("open failed");
		fprintf(stderr, "error opening directory %s\n", path);
		goto out;
	}

	char ref[MAX_REF_SIZE];
	if ((ref_len = dir_write(&dws, 0, dir_fd, ref)) < 0) {
		fprintf(stderr, "dir_write failed\n");
		goto out;
	}

	if (idx_fd >= 0 && index_write(&index, idx_fd)) {
		fprintf(stderr, "index_write failed\n");
		goto out;
	}

	if (midx_fd >= 0 && mtime_index_write(&mtime_index, &index, midx_fd)) {
		fprintf(stderr, "index_write failed\n");
		goto out;
	}

	rc = 0;

out:
	if (dir_fd >= 0 && close(dir_fd)) {
		perror("close failed");
	}
	if ((idx_fd >= 0 || midx_fd >= 0) && close_outputs(&index, idx_fd, midx_fd, target, rc ? 1 : 0)) {
		fprintf(stderr, "close_outputs failed\n");
	}
	if (!rc && !args.list_only) {
		char hex_ref[MAX_REF_SIZE * 2 + 1];
		hex_format(hex_ref, ref, ref_len);
		fprintf(stdout, "%s\n", hex_ref);
	}
	if (f_dws) {
		dir_write_state_free(&dws);
	}
	if (f_filter) {
		filter_free(&args.filter);
	}
	if (f_midx) {
		mtime_index_free(&mtime_index);
	}
	if (f_index) {
		index_free(&index);
	}
	return rc;
}

int do_mount(int argc, char *argv[], int idx) {
	int rc = 1, f_mempool = 0, f_mempool_temp = 0, f_inode_cache = 0, f_index = 0, stats = 0;
	char **fuse_argv = NULL;
	char *fuse_args = NULL;

	optind = idx;
	mempool_t mempool_temp;
	if (mempool_init(&mempool_temp, sizeof(void*), 1)) {
		fprintf(stderr, "mempool_init failed\n");
		goto out;
	}
	f_mempool_temp = 1;

	static struct option long_options[] = {
		{"root-ref", required_argument, 0, 0 },
		{"stats",    no_argument,       0, 0 },
		{0,          0,                 0, 0 }
	};

	int ref_len = 0;
	char *ref = mempool_alloc(&mempool_temp, MAX_REF_SIZE);
	if (!ref) {
		fprintf(stderr, "mempool_alloc failed\n");
		goto out;
	}

	index_t index;
	if (index_init(&index, 1, NULL, 0)) {
		fprintf(stderr, "index_init failed\n");
		goto out;
	}
	f_index = 1;

	char c;
	int option_index;
	while ((c = getopt_long(argc, argv, "-R:", long_options, &option_index)) != -1) {
		if (c == 'R' || (!c && option_index == 0)) {
			if (ref_len) {
				fprintf(stderr, "duplicate root reference\n");
				rc = do_help_mount(argv);
				goto out;
			}
			ref_len = parse_hex_reference(optarg, ref);
			if (ref_len < 0) {
				fprintf(stderr, "illegal root reference\n");
				rc = do_help_mount(argv);
				goto out;
			}
			// hide ref (from publicly viewable /proc/$$/cmdline)
			memset(optarg, 'X', strlen(optarg));
			continue;
		}

		if (!c && option_index == 1) {
			stats = 1;
		}

		if (c == 1) {
			struct stat stbuf;
			// could this be a mountpoint (i.e.: an existing directory)? if so, we assume fuse arguments start here
			if (!stat(optarg, &stbuf) && S_ISDIR(stbuf.st_mode)) {
				optind--;
				break;
			}

			if (add_ondiskidx_by_name(&index, NULL, optarg, 0, 1)) {
				fprintf(stderr, "add_ondiskidx_by_name failed\n");
				goto out;
			}
		}
	}

	if (!index.num_ondiskidx) {
		fprintf(stderr, "at least one index required\n");
		rc = do_help_mount(argv);
		goto out;
	}

	if (!ref_len) {
		char *temp = mempool_alloc(&mempool_temp, MAX_HEXREF_SIZE);
		if (!temp) {
			fprintf(stderr, "mempool_alloc failed\n");
			goto out;
		}

		ref_len = read_root_ref_from_stdin(temp, ref);
		if (ref_len < 0) {
			goto out;
		}
	}
	close(fileno(stdin));

	char* arg0_a = argv[0];
	const char* arg0_b = " mount [...] --";
	size_t arglen = strlen(arg0_a) + strlen(arg0_b) + 1;
	for (int i = optind; i < argc; i++) {
		arglen += strlen(argv[i]) + 1;
	}
	const int fuse_argc = argc - optind + 1;
	fuse_argv = malloc(sizeof(char*) * fuse_argc);
	if (!fuse_argv) {
		perror("out of memory");
		goto out;
	}
	fuse_args = malloc(arglen);
	if (!fuse_argc) {
		perror("out of memory");
		goto out;
	}
	char *argpos = fuse_args;
	fuse_argv[0] = argpos;
	memcpy(argpos, arg0_a, strlen(arg0_a)); argpos += strlen(arg0_a);
	memcpy(argpos, arg0_b, strlen(arg0_b)); argpos += strlen(arg0_b);
	*argpos = 0; argpos++;
	for (int i = optind; i < argc; i++) {
		fuse_argv[i - optind + 1] = argpos;
		memcpy(argpos, argv[i], strlen(argv[i]));
		argpos += strlen(argv[i]);
		*argpos = 0;
		argpos++;
	}
	assert(argpos == fuse_args + arglen);

	mempool_t mempool;
	if (mempool_init(&mempool, sizeof(void*), 1)) {
		fprintf(stderr, "mempool_init failed\n");
		goto out;
	}
	f_mempool = 1;

	ondiskidx_t *ondiskidx;
	if (_check_root_reference(&index, ref, &ondiskidx)) {
		goto out;
	}

	inode_cache_t inode_cache;
	if (inode_cache_init(&inode_cache, &mempool, ref, ref_len)) {
		fprintf(stderr, "inode_cache_init failed\n");
		goto out;
	}
	f_inode_cache = 1;

	mempool_free(&mempool_temp);
	f_mempool_temp = 0;

	rc = fuse_main(&index, &inode_cache, ondiskidx, stats, fuse_argc, fuse_argv);

out:
	if (f_inode_cache) { inode_cache_free(&inode_cache); }
	if (f_mempool_temp) { mempool_free(&mempool_temp); }
	if (f_mempool) { mempool_free(&mempool); }
	if (f_index) { index_free(&index); }
	if (fuse_args) { free(fuse_args); }
	if (fuse_argv) { free(fuse_argv); }
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

		if (add_ondiskidx_by_name(&index, NULL, argv[idx], 1, 1)) {
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
		fprintf(stdout, "\ttotal: %zd bytes in %zd blocks\n",
			be64toh(ondiskidx->header->total_bytes),
			be64toh(ondiskidx->header->total_blocks));
		fprintf(stdout, "\tafter deduplication: %zd bytes in %zd blocks; compressed: %zd bytes\n",
			be64toh(ondiskidx->header->dedup_bytes),
			be64toh(ondiskidx->header->dedup_blocks),
			be64toh(ondiskidx->header->dedup_compressed_bytes));
		fprintf(stdout, "\twritten: %zd bytes in %zd blocks; compressed: %zd bytes\n",
			be64toh(ondiskidx->header->internal_bytes),
			be64toh(ondiskidx->header->internal_blocks),
			be64toh(ondiskidx->header->internal_compressed_bytes));
		fprintf(stdout, "\texternal references: %zd bytes in %zd blocks; compressed: %zd bytes\n",
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
		return do_help(argv);
	}

	if (!strcmp(argv[1], "backup")) {
		return do_backup(argc, argv, 2);
	} else if (!strcmp(argv[1], "mount")) {
		return do_mount(argc, argv, 2);
	} else if (!strcmp(argv[1], "info")) {
		return do_info(argc, argv, 2);
	} else if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
		if (argc > 2 && !strcmp(argv[2], "backup")) {
			return do_help_backup(argv);
		} else if (argc > 2 && !strcmp(argv[2], "mount")) {
			return do_help_backup(argv);
		} else if (argc > 2 && !strcmp(argv[2], "info")) {
			return do_help_info(argv);
		} else {
			return do_help(argv);
		}
	} else {
		return do_help(argv);
	}
}
