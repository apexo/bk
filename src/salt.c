#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>

#include "util.h"

extern char **environ;

static int _get_home() {
	for (size_t i = 0; environ[i]; i++) {
		const char *name = environ[i];
		const char *value = strchr(name, '=');
		if ((!*value) || (value - name) != 4 || memcmp(name, "HOME", 4)) {
			continue;
		}
		int fd = open(value + 1, O_PATH | O_DIRECTORY);
		if (fd < 0) {
			perror("open failed");
			return -1;
		}
		return fd;
	}

	long initial_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (initial_size <= 0 || initial_size > SIZE_MAX) {
		perror("sysconf failed");
		return -1;
	}

	uid_t uid = getuid();

	size_t buf_len = initial_size;
	char *buf = malloc(buf_len);
	if (!buf) {
		perror("out of memory");
		return -1;
	}

	int eno;
	struct passwd pwd;
	struct passwd *result;
	while ((eno = getpwuid_r(uid, &pwd, buf, buf_len, &result)) == ERANGE) {
		if (buf_len > SIZE_MAX / 2) {
			fprintf(stderr, "buffer too large\n");
			return -1;
		}
		buf_len *= 2;
		free(buf);
		buf = malloc(buf_len);
		if (!buf) {
			perror("out of memory");
			return -1;
		}
	}

	if (eno) {
		errno = eno;
		perror("getpwuid_r failed");
		free(buf);
		return -1;
	}

	if (!result) {
		fprintf(stderr, "user not found: %d\n", uid);
		free(buf);
		return -1;
	}

	int fd = open(pwd.pw_dir, O_PATH | O_DIRECTORY);
	if (fd < 0) {
		perror("open failed");
	}

	free(buf);
	return fd;
}

static int _open_mkdir(int fd, const char *name) {
	int result = openat(fd, name, O_PATH | O_DIRECTORY);
	if (result < 0 && errno != ENOENT) {
		perror("openat failed");
		return -1;
	}
	if (result >= 0) {
		return result;
	}

	result = mkdirat(fd, name, 0777);
	if (result < 0) {
		perror("mkdirat failed");
		return -1;
	}
	
	result = openat(fd, name, O_PATH | O_DIRECTORY);
	if (result < 0) {
		perror("openat failed");
	}

	return result;
}

static ssize_t _create_salt(int path, char *salt, size_t max_len) {
	int rc = 0, urandom = -1;
	int fd = openat(path, ".salt", O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0) {
		perror("openat failed");
		rc = -1;
	}

	if (!rc && (urandom = open("/dev/urandom", O_RDONLY)) < 0) {
		perror("open failed");
		rc = -1;
	}

	if (!rc && read_exactly(urandom, salt, max_len)) {
		fprintf(stderr, "read_exactly failed\n");
		rc = -1;
	}

	if (urandom >= 0 && close(urandom)) {
		perror("close failed");
	}

	if (!rc && write_all(fd, salt, max_len)) {
		fprintf(stderr, "write_all failed\n");
		rc = -1;
	}

	if (fd >= 0 && close(fd)) {
		perror("close failed");
		rc = -1;
	}

	return rc;
}

static ssize_t _read_salt(int path, char *salt, size_t max_len) {
	int fd = openat(path, ".salt", O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			perror("openat failed");
			return -1;
		}
		if (_create_salt(path, salt, max_len)) {
			fprintf(stderr, "_create_salt failed\n");
			return -1;
		}
		return max_len;
	}

	size_t n = read_upto(fd, salt, max_len);
	if (n < 0) {
		fprintf(stderr, "read_upto failed\n");
	}

	if (close(fd)) {
		perror("close failed");
	}
	return n;
}

ssize_t get_salt(char *salt, size_t max_len) {
	assert(max_len <= SSIZE_MAX);

	int fd_home = _get_home();
	if (fd_home < 0) {
		fprintf(stderr, "_get_home failed\n");
		return -1;
	}

	int fd_config = _open_mkdir(fd_home, ".config");
	close(fd_home);
	if (fd_config < 0) {
		fprintf(stderr, "error opening/creating ~/.config\n");
		return -1;
	}

	int fd_bk_config = _open_mkdir(fd_config, "bk");
	close(fd_config);
	if (fd_bk_config < 0) {
		fprintf(stderr, "error opening/creating ~/.config/bk\n");
		return -1;
	}

	ssize_t result = _read_salt(fd_bk_config, salt, max_len);
	close(fd_bk_config);
	if (result < 0) {
		fprintf(stderr, "_get_salt failed\n");
	}
	return result;
}
