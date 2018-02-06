#include <stdio.h>

#include "compress.h"
#include "mixed_limits.h"

#define COMPRESSION_ALGO(x) ((x) & 0xFF00FF)
#define DECOMPRESSION_ALGO(x) ((x) & 0x0000FF)
#define COMPRESSION_LEVEL(x) (((x) >> 8) & 0xFF)

#define _COMPRESS_LZ4 0
#define _COMPRESS_LZ4HC 0x010000
#define _COMPRESS_ZSTD 1

#define _DECOMPRESS_LZ4 0
#define _DECOMPRESS_ZSTD 1

size_t compress_bound(size_t block_size, int compression) {
#ifndef NO_LZ4
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_LZ4) {
		return LZ4_compressBound(block_size);
	}
#endif
#ifndef NO_ZSTD
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_ZSTD) {
		return ZSTD_compressBound(block_size);
	}
#endif
	return 0;
}

size_t compress_compress(const char *src, size_t n, char *dst, size_t dstSize, int compression) {
#ifndef NO_LZ4
	if (COMPRESSION_ALGO(compression) == _COMPRESS_LZ4) {
		int result = LZ4_compress_default(src, dst, n, dstSize);
		if (result > 0 && result <= INT_SIZE_MAX) {
			return result;
		} else {
			fprintf(stderr, "%s compression failed\n", "LZ4");
			return 0;
		}
	}
#ifndef NO_LZ4HC
	if (COMPRESSION_ALGO(compression) == _COMPRESS_LZ4HC) {
		int result = LZ4_compress_HC(src, dst, n, dstSize, COMPRESSION_LEVEL(compression));
		if (result > 0 && result <= INT_SIZE_MAX) {
			return result;
		} else {
			fprintf(stderr, "%s compression failed\n", "LZ4HC");
			return 0;
		}
	}
#endif
#endif

#ifndef NO_ZSTD
	if (COMPRESSION_ALGO(compression) == _COMPRESS_ZSTD) {
		size_t result = ZSTD_compress(dst, dstSize, src, n, COMPRESSION_LEVEL(compression));
		if (result > 0 && !ZSTD_isError(result)) {
			return result;
		} else {
			fprintf(stderr, "%s compression failed\n", "ZSTD");
			return 0;
		}
	}
#endif

	return 0;
}

size_t compress_decompress(const char *src, size_t n, char *dst, size_t dstSize, int compression) {
#ifndef NO_LZ4
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_LZ4) {
		int result = LZ4_decompress_safe(src, dst, n, dstSize);
		if (result > 0 && result <= INT_SIZE_MAX) {
			return (size_t)result;
		} else {
			fprintf(stderr, "%s decompression failed\n", "LZ4");
			return 0;
		}
	}
#endif

#ifndef NO_ZSTD
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_ZSTD) {
		size_t result = ZSTD_decompress(dst, dstSize, src, n);
		if (result > 0 && !ZSTD_isError(result)) {
			return result;
		} else {
			fprintf(stderr, "%s decompression failed\n", "ZSTD");
			return 0;
		}
	}
#endif

#ifdef NO_LZ4
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_LZ4) {
		fprintf(stderr, "unsupported compression algorithm: %s\n", "LZ4");
		return 0;
	}
#endif

#ifdef NO_ZSTD
	if (DECOMPRESSION_ALGO(compression) == _DECOMPRESS_ZSTD) {
		fprintf(stderr, "unsupported compression algorithm: %s\n", "ZSTD");
		return 0;
	}
#endif

	fprintf(stderr, "unknown compression algorithm: %d\n", DECOMPRESSION_ALGO(compression));
	return 0;
}
