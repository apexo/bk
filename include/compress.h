#ifndef BK_COMPRESS_H
#define BK_COMPRESS_H

#ifndef NO_LZ4
#include <lz4.h>
#define COMPRESS_LZ4 0x000000
#ifndef NO_LZ4HC
#include <lz4hc.h>
#define COMPRESS_LZ4HC 0x010900
#endif
#endif

#ifndef NO_ZSTD
#include <zstd.h>
#define COMPRESS_ZSTD 0x000301
#endif


size_t compress_bound(size_t block_size, int compression);
size_t compress_compress(const char *src, size_t n, char *dst, size_t dstSize, int compression);
size_t compress_decompress(const char *src, size_t n, char *dst, size_t dstSize, int compression);

#endif
