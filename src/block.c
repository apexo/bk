#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>
#include <assert.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <lz4.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "types.h"
#include "index.h"
#include "block.h"

void block_free(block_t *block);

#define ALIGN 128

int blksize_check(size_t blksize) {
	if (blksize < MIN_BLOCK_SIZE) {
		fprintf(stderr, "block size too small\n");
		return -1;
	}
	if (blksize > LZ4_MAX_INPUT_SIZE || blksize > UINT32_MAX) {
		fprintf(stderr, "illegal block size: block size too big\n");
		return -1;
	}
	if (blksize & (blksize - 1)) {
		fprintf(stderr, "illegal block size: must be power of 2\n");
		return -1;
	}
	return 0;
}

static int _safe_add(ssize_t *accum, ssize_t *limit, ssize_t value) {
	if (value < 0 || value > *limit) {
		fprintf(stderr, "blksize too large\n");
		return -1;
	}
	*limit -= value;
	*accum += value;
	return 0;
}

/*
 * dynamically calculate the amount of memory we allocate for indirection;
 * we don't need 5 full indirection blocks for 4 MiByte blksize
 */
static void _set_limits(block_t *block) {
	const off_t filesize_limit = 9223372036854775807L; // 2**63-1, we should be compiling with FILE_OFFSET_BITS=64 for fuse, anyway, so this should make sense
	const size_t blksize = block->blksize;
	const off_t inline_blocks = INLINE_THRESHOLD / BLOCK_KEY_SIZE;
	const off_t block_ref_limit = blksize / BLOCK_KEY_SIZE;
	off_t blocks = (filesize_limit / blksize) + 1;


	block->limit[0] = filesize_limit > blksize ? blksize : filesize_limit;
	for (size_t i = 1; i <= MAX_INDIRECTION; i++) {
		if (i == MAX_INDIRECTION && blocks > inline_blocks) {
			// we cannot store the maximal file size with the given block size
			// but with the minimum block size of 4kiByte, the maximal file size is 40 GiByte
			// for 8kiByte, it is already 640 GiByte, which should be enough for everybody ;-)
			block->limit[i] = inline_blocks * BLOCK_KEY_SIZE;
		} else if (blocks >= block_ref_limit) {
			block->limit[i] = blksize;
		} else {
			block->limit[i] = blocks * BLOCK_KEY_SIZE;
		}
		if (blocks <= inline_blocks) {
			blocks = 0;
		} else {
			blocks /= block_ref_limit;
		}
	}
}

static ssize_t _get_locked_size(block_t *block, long *page_size_ret) {
	const size_t blksize = block->blksize;
	ssize_t limit = SSIZE_MAX;
	ssize_t locked_bytes = 0;

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 1) {
		perror("error querying page size");
		return -1;
	}

	// temp0
	if (_safe_add(&locked_bytes, &limit, blksize)) { return -1; }

	// temp1 + align
	if (_safe_add(&locked_bytes, &limit, LZ4_compressBound(blksize))) { return -1; }
	if (_safe_add(&locked_bytes, &limit, (size_t)(-locked_bytes)%ALIGN)) { return -1; }

	// data + align
	for (size_t i = 0; i <= MAX_INDIRECTION; i++) {
		if (block->limit[i]) {
			if (_safe_add(&locked_bytes, &limit, block->limit[i])) { return -1; }
			if (_safe_add(&locked_bytes, &limit, (size_t)(-locked_bytes)%ALIGN)) { return -1; }
		}
	}

	// fill to page_size
	if (_safe_add(&locked_bytes, &limit, (size_t)(-locked_bytes)%page_size)) { return -1; }

	if (page_size_ret) {
		*page_size_ret = page_size;
	}

	return locked_bytes;
}

static int _block_allocate_locked_mem(block_t *block) {
	size_t blksize = block->blksize;

	_set_limits(block);

	long page_size;
	ssize_t locked_bytes = _get_locked_size(block, &page_size);
	if (locked_bytes < 0) {
		fprintf(stderr, "_get_locked_size failed\n");
		return -1;
	}

	unsigned char *locked_mem = mmap(NULL, locked_bytes, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_LOCKED | MAP_PRIVATE, -1, 0);
	if (locked_mem == MAP_FAILED) {
		perror("error allocating locked memory");
		fprintf(stderr, "failed to mmap %zd bytes of locked memory\n", locked_bytes);
		return -1;
	}

	ssize_t ofs = 0;

	block->temp0 = locked_mem;
	ofs += blksize;

	block->temp1 = locked_mem + ofs;
	ofs += LZ4_compressBound(blksize);
	ofs += (size_t)(-ofs) % ALIGN;

	for (size_t i = 0; i <= MAX_INDIRECTION; i++) {
		if (block->limit[i]) {
			block->data[i] = locked_mem + ofs;
			ofs += block->limit[i];
			ofs += (size_t)(-ofs) % ALIGN;
		}
	}
	assert(ofs + (size_t)(-ofs)%page_size == locked_bytes);

	return 0;
}

int block_init(block_t *block, size_t blksize) {
	memset(block, 0, sizeof(block_t));

	if (blksize_check(blksize)) {
		fprintf(stderr, "blksize_check failed\n");
		return -1;
	}

	block->blksize = blksize;

	block->temp2 = malloc(blksize);
	if (!block->temp2) {
		perror("out of memory");
		return -1;
	}

	if (_block_allocate_locked_mem(block)) {
		fprintf(stderr, "_block_allocate_locked_mem failed\n");
		free(block->temp2);
		return -1;
	}
	return 0;
}

void block_free(block_t *block) {
	ssize_t locked_bytes = _get_locked_size(block, NULL);
	assert(locked_bytes > 0);
	if (munmap(block->temp0, locked_bytes) < 0) {
		perror("(in block_free) munmap failed");
	}
	free(block->temp2);
}

static void _block_hash(index_t *index, const unsigned char *data, size_t n, block_key_t encryption_key) {
	assert(sizeof(block_key_t) == SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	memcpy(&ctx, &(index->encryption_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, data, n);
	SHA256_Final(encryption_key, &ctx);
}

static void _block_hash2(index_t *index, const block_key_t encryption_key, block_key_t storage_key) {
	assert(sizeof(block_key_t) == SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	memcpy(&ctx, &(index->storage_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, encryption_key, SHA256_DIGEST_LENGTH);
	SHA256_Final(storage_key, &ctx);
}

// only store compressed data if compressible by at least 5%
#define IS_COMPRESSIBLE(size, compressed) ((compressed) && ((compressed) < (size)) && ((size) - (compressed) > (size) / 20))

static const unsigned char *_block_compress(const unsigned char *src, size_t n, unsigned char *dst, block_size_t *compressed_block_size) {
	int compressed = LZ4_compress((const char*)src, (char*)dst, n);
	if (IS_COMPRESSIBLE(n, compressed)) {
		*compressed_block_size = compressed;
		return dst;
	} else {
		*compressed_block_size = n;
		return src;
	}
}

static int _block_crypt(const unsigned char *src, size_t n, unsigned char *dst, block_key_t encryption_key, int enc) {
	const EVP_CIPHER *cipher = EVP_aes_256_ctr();
	if (!cipher) {
		fprintf(stderr, "EVP_aes_256_ctr failed\n");
		return -1;
	}

	unsigned char iv[16];
	assert(sizeof(iv) == EVP_CIPHER_iv_length(cipher));
	memset(iv, 0, 12);
	*(uint32_t*)(iv + 12) = htobe32(n);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (!EVP_CipherInit_ex(&ctx, cipher, NULL, encryption_key, iv, enc)) {
		fprintf(stderr, "error %scrypting block; EVP_CipherInit_ex failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	int len;
 	if (!EVP_CipherUpdate(&ctx, dst, &len, src, n)) {
		fprintf(stderr, "error %scrypting block; EVP_CipherUpdate failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	int f_len;
	if (!EVP_CipherFinal_ex(&ctx, dst+len, &f_len)) {
		fprintf(stderr, "error %scrypting block; EVP_CipherFinal_ex failed: %s\n", enc?"en":"de", ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	assert(len + f_len == n);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 0;
}

static int _block_data_write(index_t *index, const unsigned char *data, block_key_t storage_key, block_size_t block_size, block_size_t compressed_block_size) {
	assert(compressed_block_size && compressed_block_size <= block_size);

	off64_t file_offset = lseek64(index->data_fd, 0, SEEK_CUR);
	if (file_offset == (off64_t)-1) {
		perror("lseek64 failed");
		return -1;
	}
	if (index_add_block(index, storage_key, file_offset, block_size, compressed_block_size)) {
		fprintf(stderr, "index_add_block failed\n");
		return -1;
	}

	const ssize_t bytes_written = write(index->data_fd, data, compressed_block_size);

	if (bytes_written < 0) {
		perror("write failed");
		return -1;
	}

	if (bytes_written < compressed_block_size) {
		fprintf(stderr, "short write - disk full?\n");
		return -1;
	}

	return 0;
}

static int _block_dedup(block_t *block, index_t *index, const unsigned char *block_data, size_t block_size, block_key_t encryption_key) {
	file_offset_t file_offset;
	block_size_t temp_block_size, compressed_block_size;
	block_key_t storage_key;

	_block_hash(index, block_data, block_size, encryption_key);
	_block_hash2(index, encryption_key, storage_key);

	ondiskidx_t *ondiskidx;

	index->header.total_blocks++;
	index->header.total_bytes += block_size;

	if (index_lookup(index, storage_key, &file_offset, &temp_block_size, &compressed_block_size, &ondiskidx)) {
		const unsigned char* compressed_data = _block_compress(block_data, block_size, block->temp1, &compressed_block_size);
		if (_block_crypt(compressed_data, compressed_block_size, block->temp2, encryption_key, 1)) {
			fprintf(stderr, "_block_crypt failed\n");
			return -1;
		}
		if (_block_data_write(index, block->temp2, storage_key, block_size, compressed_block_size)) {
			fprintf(stderr,  "_block_data_write failed\n");
			return -1;
		}
		block->allocated_bytes += compressed_block_size;
		index->header.dedup_blocks++;
		index->header.dedup_bytes += block_size;
		index->header.dedup_compressed_bytes += compressed_block_size;
		index->header.internal_blocks++;
		index->header.internal_bytes += block_size;
		index->header.internal_compressed_bytes += compressed_block_size;
	}

	return 0;
}

static int _block_flush(block_t *block, index_t *index, size_t indir, const unsigned char *block_data, size_t block_size) {
	if (indir == MAX_INDIRECTION) {
		fprintf(stderr, "file too big\n");
		return -1;
	}

	if (indir == block->indirection) {
		if (!block->data[indir+1]) {
			block->data[indir+1] = malloc(block->blksize);
			if (!block->data[indir+1]) {
				perror("out of memory\n");
				return -1;
			}
		}
		block->indirection++;
		block->len[indir+1] = 0;
	}

	assert(block->len[indir+1] + BLOCK_KEY_SIZE <= block->blksize);

	if (_block_dedup(block, index, block_data, block_size, (block->data[indir+1] + block->len[indir + 1]))) {
		fprintf(stderr, "_block_dedup failed\n");
		return -1;
	}

	block->len[indir+1] += BLOCK_KEY_SIZE;

	if (block->len[indir+1] == block->blksize) {
		if (_block_flush(block, index, indir+1, block->data[indir+1], block->len[indir+1])) {
			return -1;
		}
		block->len[indir+1] = 0;
	}

	return 0;
}

int block_append(block_t *block, index_t *index, const unsigned char *data, size_t size) {
	const size_t bs = block->blksize;

	block->raw_bytes += size;

	if (!block->len[0] && size == bs) {
		if (_block_flush(block, index, 0, data, size)) {
			fprintf(stderr, "_block_flush failed\n");
			return -1;
		}
		return 0;
	}

	while (block->len[0] + size >= bs) {
		const size_t n1 = bs - block->len[0];
		memcpy(block->data[0] + block->len[0], data, n1);
		data += n1;
		size -= n1;
		block->len[0] = bs;

		if (_block_flush(block, index, 0, block->data[0], block->len[0])) {
			fprintf(stderr, "_block_flush failed\n");
			return -1;
		}

		block->len[0] = 0;
	}

	if (size) {
		memcpy(block->data[0] + block->len[0], data, size);
		block->len[0] += size;
		return 0;
	}

	return 0;
}

int block_flush(block_t *block, index_t *index, unsigned char* ref) {
	size_t indir = 0;
	while (indir < block->indirection || (indir == block->indirection && block->len[indir] > INLINE_THRESHOLD)) {
		if (block->len[indir]) {
			if (_block_flush(block, index, indir, block->data[indir], block->len[indir])) {
				fprintf(stderr, "_block_flush failed\n");
				return -1;
			}
			block->len[indir] = 0;
		}
		indir++;
	}
	assert(indir <= MAX_INDIRECTION);
	assert(block->len[indir] <= INLINE_THRESHOLD);

	ref[0] = block->len[indir];
	ref[1] = indir;
	memcpy(ref+2, block->data[indir], block->len[indir]);
	int n = 2 + block->len[indir];

	block->len[indir] = 0;
	block->indirection = 0;

	return n;
}

int block_ref_length(const unsigned char *ref) {
	return ref[0] + 2;
}

int block_ref_check(const unsigned char *ref, size_t ref_len) {
	const size_t len = ref[0], indir = ref[1];

	if (indir > MAX_INDIRECTION || (indir && len < BLOCK_KEY_SIZE) || len > INLINE_THRESHOLD || (indir && len % BLOCK_KEY_SIZE)) {
		fprintf(stderr, "illegal reference\n");
		return -1;
	}

	if (ref_len != block_ref_length(ref)) {
		fprintf(stderr, "illegal reference\n");
		return -1;
	}

	return 0;
}

int block_setup(block_t *block, const unsigned char *ref, size_t ref_len) {
	if (block_ref_check(ref, ref_len)) {
		fprintf(stderr, "block_ref_check failed\n");
		return -1;
	}

	const size_t len = ref[0], indir = ref[1];

	block->idx_blksize = 0;

	for (size_t i = 1; i <= indir; i++) {
		if (!block->data[i]) {
			block->data[i] = malloc(block->blksize);
			if (!block->data[i]) {
				perror("out of memory\n");
				return -1;
			}
		}
	}

	memset(block->len, 0, sizeof(block->len));
	memset(block->idx, 0, sizeof(block->idx));

	block->indirection = indir;
	block->len[indir] = len;
	memcpy(block->data[indir], ref+2, len);

	return 0;
}

static ssize_t _block_fetch(block_t *block, index_t *index, unsigned char *dst, size_t size, block_key_t encryption_key) {
	block_key_t storage_key;
	int data_fd;
	file_offset_t file_offset;
	block_size_t block_size, compressed_block_size;

	_block_hash2(index, encryption_key, storage_key);

	ondiskidx_t *ondiskidx;
	if (index_lookup(index, storage_key, &file_offset, &block_size, &compressed_block_size, &ondiskidx)) {
		fprintf(stderr, "index_lookup failed\n");
		return -1;
	}

	if (ondiskidx) {
		block->idx_blksize = ondiskidx->blksize;
		data_fd = ondiskidx->data_fd;
	} else {
		block->idx_blksize = index->blksize;
		data_fd = index->data_fd;
	}

	assert(block->blksize >= block->idx_blksize);
	assert(size >= block->idx_blksize);

	if (!compressed_block_size || compressed_block_size > block_size) {
		fprintf(stderr, "illegal compressed block size: %d (%d)\n", compressed_block_size, block_size);
		return -1;
	}
	
	if (block_size > block->idx_blksize) {
		fprintf(stderr, "block size too big\n");
		return -1;
	}

	off64_t ofs = lseek64(data_fd, file_offset, SEEK_SET);
	if (ofs == (off64_t)-1) {
		perror("lseek64 failed");
		return -1;
	}
	ssize_t n = read(data_fd, block->temp2, compressed_block_size);
	if (n < 0) {
		perror("error reading data");
		return -1;
	}

	if (n < compressed_block_size) {
		fprintf(stderr, "short read - file truncated?\n");
		return -1;
	}

	unsigned char *decrypted = compressed_block_size < block_size ? block->temp1 : dst;

	if (_block_crypt(block->temp2, compressed_block_size, decrypted, encryption_key, 0)) {
		fprintf(stderr, "_block_crypt failed\n");
		return -1;
	}

	if (compressed_block_size < block_size) {
		int n = LZ4_decompress_safe((const char*)decrypted, (char*)dst, compressed_block_size, size);
		if (n < 0) {
			fprintf(stderr, "LZ4_decompress_safe failed\n");
			return -1;
		}

		if (n != block_size) {
			fprintf(stderr, "unexpected LZ4_decompress_safe result\n");
			return -1;
		}
	}

	return block_size;
}

static ssize_t _block_read(block_t *block, index_t *index, size_t indir, unsigned char *dst, size_t size);

static ssize_t _block_next(block_t *block, index_t *index, size_t indir) {
	if (indir == block->indirection) {
		return 0;
	}

	block_key_t encryption_key;
	ssize_t n = _block_read(block, index, indir+1, encryption_key, BLOCK_KEY_SIZE);
	if (n < 0) {
		fprintf(stderr, "_block_read failed\n");
		return -1;
	}

	if (n == 0) {
		return 0;
	}

	if (n != BLOCK_KEY_SIZE) {
		fprintf(stderr, "_block_read short result\n");
		return -1;
	}

	n = _block_fetch(block, index, block->data[indir], block->blksize, encryption_key);
	if (n < 0) {
		fprintf(stderr, "_block_fetch failed\n");
		return -1;
	}

	assert(n > 0);

	block->len[indir] = n;
	block->idx[indir] = 0;

	return n;
}

static ssize_t _block_read(block_t *block, index_t *index, size_t indir, unsigned char *dst, size_t size) {
	if (block->idx[indir] == block->len[indir]) {
		ssize_t n = _block_next(block, index, indir);
		if (!n) {
			return 0;
		}
		if (n < 0) {
			fprintf(stderr, "_block_next failed\n");
			return -1;
		}
	}

	size_t n = block->len[indir] - block->idx[indir];
	n = n < size ? n : size;
	memcpy(dst, block->data[indir] + block->idx[indir], n);
	block->idx[indir] += n;
	return n;
}

static ssize_t _block_skip(block_t *block, index_t *index, size_t indir, size_t ofs) {
	size_t rem = block->len[indir] - block->idx[indir];
	if (rem) {
		if (ofs > rem) {
			block->idx[indir] = block->len[indir];
			return rem;
		} else {
			block->idx[indir] += ofs;
			return ofs;
		}
	}

	if (indir == block->indirection) {
		return 0;
	}

	if (block->idx_blksize && ofs >= block->idx_blksize) {
		size_t blocks = ofs / block->idx_blksize;
		ssize_t skipped = _block_skip(block, index, indir + 1, blocks * BLOCK_KEY_SIZE);
		if (skipped < 0) {
			fprintf(stderr, "_block_skip failed\n");
			return -1;
		}
		if (!skipped) {
			return 0;
		}
		assert(!(skipped % BLOCK_KEY_SIZE));
		return (skipped / BLOCK_KEY_SIZE) * block->idx_blksize;
	}

	ssize_t bytes = _block_next(block, index, indir);
	if (!bytes) {
		return 0;
	}
	if (bytes < 0) {
		fprintf(stderr, "_block_next failed\n");
		return -1;
	}

	if (ofs >= bytes) {
		block->idx[indir] = block->len[indir];
		return bytes;
	} else {
		block->idx[indir] += ofs;
		return ofs;
	}
}

int block_skip(block_t *block, index_t *index, off64_t ofs) {
	off64_t org_ofs = ofs;
	if (ofs < 0) {
		fprintf(stderr, "negative offset not supported\n");
		return -1;
	}
	while (ofs > 0) {
		const ssize_t chunk = ofs > SSIZE_MAX ? SSIZE_MAX : ofs;
		const ssize_t skipped = _block_skip(block, index, 0, chunk);
		if (skipped < 0) {
			fprintf(stderr, "_block_skip failed\n");
			return -1;
		}
		if (!skipped) {
			fprintf(stderr, "block_skip: short by %zd bytes (from: %zd)\n", ofs, org_ofs);
			return 0;
		}
		ofs -= skipped;
	}
	return 1;
}

ssize_t block_read(block_t *block, index_t *index, unsigned char *dst, size_t size) {
	block_key_t encryption_key;

	if (block->idx[0] < block->len[0]) {
		size_t n = block->len[0] - block->idx[0];
		n = n < size ? n : size;
		memcpy(dst, block->data[0] + block->idx[0], n);
		block->idx[0] += n;
		return n;
	}

	if (!block->indirection) {
		return 0;
	}

	ssize_t n = _block_read(block, index, 1, encryption_key, BLOCK_KEY_SIZE);
	if (n < 0) {
		fprintf(stderr, "_block_read failed\n");
		return -1;
	}

	if (n == 0) {
		return 0;
	}

	if (n != BLOCK_KEY_SIZE) {
		fprintf(stderr, "_block_read short result\n");
		return -1;
	}

	if (size >= block->blksize) {
		n = _block_fetch(block, index, dst, block->blksize, encryption_key);
		if (n < 0) {
			fprintf(stderr, "_block_fetch failed\n");
			return -1;
		}

		return n;
	}

	n = _block_fetch(block, index, block->data[0], block->blksize, encryption_key);
	if (n < 0) {
		fprintf(stderr, "_block_fetch failed\n");
		return -1;
	}

	block->len[0] = n;
	n = n < size ? n : size;
	memcpy(dst, block->data[0], n);
	block->idx[0] = n;
	return n;
}
