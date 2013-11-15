#include <sys/mman.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <lz4.h>

#include "fuse_state.h"

#define INITIAL_REPLY_BUFFER 131072
#define ALIGN 128

static char* _mmap_locked(size_t size, long page_size, size_t *real_size) {
	if (size > SIZE_MAX - page_size + 1) {
		fprintf(stderr, "cannot allocate that much memory\n");
		return NULL;
	}
	size += (-size) & (page_size - 1);

	char *result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	if (result == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		return NULL;
	}

	*real_size = size;
	return result;
}

static int _mremap_locked(size_t size, long page_size, size_t *real_size, char **ptr) {
	assert(size > *real_size);
	size_t old_size = *real_size;
	char *temp = _mmap_locked(size, page_size, real_size);
	if (!temp) {
		fprintf(stderr, "_mmap_locked failed\n");
		return -1;
	}

	if (munmap(*ptr, old_size)) {
		fprintf(stderr, "(in _mremap_locked) munmap failed\n");
	}

	*ptr = temp;
	return 0;
}

static void _fuse_thread_state_free(fuse_thread_state_t *fuse_thread_state) {
	if (fuse_thread_state->block_thread_state.crypt) {
		free(fuse_thread_state->block_thread_state.crypt);
	}
	if (fuse_thread_state->reply_buffer) {
		if (munmap(fuse_thread_state->reply_buffer, fuse_thread_state->reply_buffer_size)) {
			fprintf(stderr, "munmap failed\n");
		}
	}
	if (fuse_thread_state->block_thread_state.pack) {
		if (munmap(fuse_thread_state->block_thread_state.pack, fuse_thread_state->locked_size)) {
			fprintf(stderr, "munmap failed\n");
		}
	}
}

static fuse_thread_state_t *_fuse_thread_state_alloc(fuse_global_state_t *global_state) {
	fuse_thread_state_t fuse_thread_state;
	memset(&fuse_thread_state, 0, sizeof(fuse_thread_state_t));

	const size_t blksize = global_state->ondiskidx ? global_state->ondiskidx->blksize : MIN_BLOCK_SIZE;

	size_t bp_size = LZ4_compressBound(blksize);
	bp_size += (-bp_size)%ALIGN;

	size_t dd_size = DENTRY_MAX_SIZE;
	dd_size += (-dd_size)%ALIGN;

	size_t fs_size = sizeof(fuse_thread_state_t);

	size_t locked_size = bp_size + dd_size + fs_size;

	fuse_thread_state.reply_buffer = _mmap_locked(INITIAL_REPLY_BUFFER, global_state->page_size, &fuse_thread_state.reply_buffer_size);
	if (!fuse_thread_state.reply_buffer) {
		fprintf(stderr, "_mmap_locked failed\n");
		goto err;
	}

	fuse_thread_state.block_thread_state.crypt = malloc(blksize);
	if (!fuse_thread_state.block_thread_state.crypt) {
		perror("out of memory");
		goto err;
	}

	char* locked = _mmap_locked(locked_size, global_state->page_size, &fuse_thread_state.locked_size);
	if (!locked) {
		fprintf(stderr, "_mmap_locked failed\n");
		goto err;
	}

	fuse_thread_state.block_thread_state.pack = locked;
	fuse_thread_state.dir_thread_state.dentry = locked + bp_size;
	fuse_thread_state_t *result = (fuse_thread_state_t*)(locked + bp_size + dd_size);

	memcpy(result, &fuse_thread_state, sizeof(fuse_thread_state_t));

	return result;
err:
	_fuse_thread_state_free(&fuse_thread_state);
	return NULL;
}

char *fuse_thread_state_get_reply_buffer(fuse_global_state_t *global_state, fuse_thread_state_t *fuse_thread_state, size_t size) {
	if (size <= fuse_thread_state->reply_buffer_size) {
		return fuse_thread_state->reply_buffer;
	}

	if (!_mremap_locked(size, global_state->page_size, &fuse_thread_state->reply_buffer_size, &fuse_thread_state->reply_buffer)) {
		fprintf(stderr, "_mremap_locked locked\n");
		return NULL;
	}
	return fuse_thread_state->reply_buffer;
}

int fuse_thread_state_setup(fuse_global_state_t *global_state) {
	global_state->page_size = sysconf(_SC_PAGESIZE);
	if (global_state->page_size < 0) {
		perror("sysconf failed\n");
		return -1;
	}
	if (global_state->page_size < 1 || ((global_state->page_size - 1) & global_state->page_size)) {
		fprintf(stderr, "illegal page size: %ld\n", global_state->page_size);
		return -1;
	}
#ifdef MULTITHREADED
	if (pthread_key_create(&global_state->state_key, (void(*)(void *))&_fuse_thread_state_free)) {
		perror("pthread_key_create failed");
		return -1;
	}
	if (pthread_mutex_init(&global_state->dir_index_mutex, NULL)) {
		perror("pthread_mutex_init failed");
		if (pthread_key_delete(global_state->state_key)) {
			perror("(in fuse_thread_state_free) pthread_key_delete failed");
		}
		return -1;
	}
#else
	global_state->single_thread_state = _fuse_thread_state_alloc(global_state);
	if (!global_state->single_thread_state) {
		fprintf(stderr, "fuse_thread_state_alloc failed\n");
		return -1;
	}
#endif
	return 0;
}

fuse_thread_state_t *fuse_thread_state_get(fuse_global_state_t *global_state) {
#ifdef MULTITHREADED
	fuse_thread_state_t *result = pthread_getspecific(global_state->state_key);
	if (!result) {
		result = _fuse_thread_state_alloc(global_state);
		if (!result) {
			fprintf(stderr, "_fuse_thread_state_alloc failed\n");
			return NULL;
		}
		pthread_setspecific(global_state->state_key, result);
	}
	return result;
#else
	return global_state->single_thread_state;
#endif
}

void fuse_thread_state_free(fuse_global_state_t *global_state) {
#ifdef MULTITHREADED
	if (pthread_key_delete(global_state->state_key)) {
		perror("(in fuse_thread_state_free) pthread_key_delete failed");
	}
#else
	_fuse_thread_state_free(global_state->single_thread_state);
#endif
}
