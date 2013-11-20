.PHONY: debug release debug-mt release-mt

C_SRC=src/index.c src/block.c src/util.c src/block_stack.c src/dir.c src/inode_cache.c src/block_cache.c src/fuse.c src/filter.c src/main.c src/mempool.c src/dir_index.c src/fuse_state.c src/mtime_index.c src/salt.c
C_OPTS=-std=c99 -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_BSD_SOURCE -Wall -Werror
LIBS=-lcrypto -llz4 -lssl -lfuse
INCLUDE=-Iinclude
MT_ARGS=-lpthread -DMULTITHREADED
COMMON_ARGS=-o ${BINARY} ${C_SRC} ${LIBS} ${INCLUDE} ${C_OPTS}
DEBUG_FLAGS=-g -fstack-check -fstack-protector
RELEASE_FLAGS=-O2 -DNDEBUG -DNVALGRIND
BINARY=bk

all: release

clean:
	rm -f ${BINARY}

debug: ${C_SRC}
	${CC} ${DEBUG_FLAGS} ${COMMON_ARGS}

debug-mt: ${C_SRC}
	${CC} ${DEBUG_FLAGS} ${COMMON_ARGS} ${MT_ARGS}

release: ${C_SRC}
	${CC} ${RELEASE_FLAGS} ${COMMON_ARGS}

release-mt: ${C_SRC}
	${CC} ${RELEASE_FLAGS} ${COMMON_ARGS} ${MT_ARGS}
