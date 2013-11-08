#define _BSD_SOURCE
#define _LARGEFILE64_SOURCE

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

#include "types.h"
#include "index.h"

void block_free(block_t *block);

int block_init(block_t *block, size_t block_size) {
	memset(block, 0, sizeof(block_t));

	if (block_size < MIN_BLOCK_SIZE) {
		fprintf(stderr, "block size too small\n");
		return -1;
	}
	size_t pow2 = MIN_BLOCK_SIZE;
	while (pow2 <= (SIZE_MAX / 2) && pow2 < block_size) {
		pow2 *= 2;
	}
	if (pow2 > block_size) {
		fprintf(stderr, "illegal block size: must be power of 2\n");
		return -1;
	}
	if (pow2 < block_size) {
		fprintf(stderr, "illegal block size: block size too big\n");
		return -1;
	}

	block->size = block_size;

	block->data[0] = malloc(block_size);
	if (!block->data[0]) {
		perror("out of memory");
		return -1;
	}

	block->temp0 = malloc(block_size);
	if (!block->temp0) {
		perror("out of memory");
		block_free(block);
		return -1;
	}

	block->temp1 = malloc(LZ4_compressBound(block_size));
	if (!block->temp1) {
		perror("out of memory");
		block_free(block);
		return -1;
	}

	block->temp2 = malloc(block_size);
	if (!block->temp2) {
		perror("out of memory");
		block_free(block);
		return -1;
	}
	return 0;
}

void block_free(block_t *block) {
	for (size_t i = 0; i <= MAX_INDIRECTION; i++) {
		block->data[i] = realloc(block->data[i], 0);
	}
	block->temp0 = realloc(block->temp0, 0);
	block->temp1 = realloc(block->temp1, 0);
	block->temp2 = realloc(block->temp2, 0);
}

void _block_hash(index_t *index, const unsigned char *data, size_t n, block_key_t encryption_key) {
	assert(sizeof(block_key_t) == SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	memcpy(&ctx, &(index->encryption_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, data, n);
	SHA256_Final(encryption_key, &ctx);
}

void _block_hash2(index_t *index, const block_key_t encryption_key, block_key_t storage_key) {
	assert(sizeof(block_key_t) == SHA256_DIGEST_LENGTH);

	SHA256_CTX ctx;
	memcpy(&ctx, &(index->storage_key_context), sizeof(SHA256_CTX));
	SHA256_Update(&ctx, encryption_key, SHA256_DIGEST_LENGTH);
	SHA256_Final(storage_key, &ctx);
}

// only store compressed data if compressible by at least 5%
#define IS_COMPRESSIBLE(size, compressed) ((compressed) && ((compressed) < (size)) && ((size) - (compressed) > (size) / 20))

const unsigned char *_block_compress(const unsigned char *src, size_t n, unsigned char *dst, block_size_t *compressed_block_size) {
	int compressed = LZ4_compress(src, dst, n);
	if (IS_COMPRESSIBLE(n, compressed)) {
		*compressed_block_size = compressed;
		return dst;
	} else {
		*compressed_block_size = n;
		return src;
	}
}

int _block_crypt(const unsigned char *src, size_t n, unsigned char *dst, block_key_t encryption_key, int enc) {
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

int _block_data_write(index_t *index, const unsigned char *data, block_key_t storage_key, block_size_t block_size, block_size_t compressed_block_size) {
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
		perror("error writing data\n");
		return -1;
	}

	if (bytes_written < compressed_block_size) {
		fprintf(stderr, "short write - disk full?\n");
		return -1;
	}

	return 0;
}

int _block_dedup(block_t *block, index_t *index, const unsigned char *block_data, size_t block_size, block_key_t encryption_key) {
	file_offset_t file_offset;
	block_size_t temp_block_size, compressed_block_size;

	block_key_t storage_key;
	int data_fd;

	_block_hash(index, block_data, block_size, encryption_key);
	_block_hash2(index, encryption_key, storage_key);

	if (index_lookup(index, storage_key, &data_fd, &file_offset, &temp_block_size, &compressed_block_size)) {
		const unsigned char* compressed_data = _block_compress(block_data, block_size, block->temp1, &compressed_block_size);
		// fprintf(stderr, "new block, awesome! %zd -> %zd\n", block_size, compressed_block_size);
		if (_block_crypt(compressed_data, compressed_block_size, block->temp2, encryption_key, 1)) {
			fprintf(stderr, "_block_crypt failed\n");
			return -1;
		}
		if (_block_data_write(index, block->temp2, storage_key, block_size, compressed_block_size)) {
			fprintf(stderr,  "_block_data_write failed\n");
			return -1;
		}
		block->allocated_bytes += compressed_block_size;
	}

	return 0;
}

int _block_flush(block_t *block, index_t *index, size_t indir, const unsigned char *block_data, size_t block_size) {
	if (indir == MAX_INDIRECTION) {
		fprintf(stderr, "file too big\n");
		return -1;
	}

	if (indir == block->indirection) {
		if (!block->data[indir+1]) {
			block->data[indir+1] = malloc(block->size);
			if (!block->data[indir+1]) {
				perror("out of memory\n");
				return -1;
			}
		}
		block->indirection++;
		block->len[indir+1] = 0;
	}

	assert(block->len[indir+1] + BLOCK_KEY_SIZE <= block->size);

	if (_block_dedup(block, index, block_data, block_size, (block->data[indir+1] + block->len[indir + 1]))) {
		fprintf(stderr, "_block_dedup failed\n");
		return -1;
	}

	block->len[indir+1] += BLOCK_KEY_SIZE;

	if (block->len[indir+1] == block->size) {
		if (_block_flush(block, index, indir+1, block->data[indir+1], block->len[indir+1])) {
			return -1;
		}
		block->len[indir+1] = 0;
	}

	return 0;
}

int block_append(block_t *block, index_t *index, const unsigned char *data, size_t size) {
	const size_t bs = block->size;

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
		memcpy(block->data[0] + block->len[0], data, size);
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
	assert(indir < MAX_INDIRECTION);
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

int block_setup(block_t *block, const unsigned char *ref, size_t ref_len) {
	size_t len = ref[0], indir = ref[1];

	if (indir > MAX_INDIRECTION || len < BLOCK_KEY_SIZE || len > INLINE_THRESHOLD || len % BLOCK_KEY_SIZE) {
		fprintf(stderr, "illegal reference\n");
		return -1;
	}

	if (ref_len != block_ref_length(ref)) {
		fprintf(stderr, "illegal reference\n");
		return -1;
	}

	for (size_t i = 1; i <= indir; i++) {
		if (!block->data[i]) {
			block->data[i] = malloc(block->size);
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

ssize_t _block_fetch(block_t *block, index_t *index, unsigned char *dst, size_t size, block_key_t encryption_key) {
	block_key_t storage_key;
	int data_fd;
	file_offset_t file_offset;
	block_size_t block_size, compressed_block_size;

	_block_hash2(index, encryption_key, storage_key);

	if (index_lookup(index, storage_key, &data_fd, &file_offset, &block_size, &compressed_block_size)) {
		fprintf(stderr, "index_lookup failed\n");
		return -1;
	}

	assert(size >= block->size);

	if (!compressed_block_size || compressed_block_size > block_size) {
		fprintf(stderr, "illegal compressed block size: %zd (%zd)\n", compressed_block_size, block_size);
		return -1;
	}
	
	if (block_size > block->size) {
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
		int n = LZ4_decompress_safe(decrypted, dst, compressed_block_size, size);
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

ssize_t _block_read(block_t *block, index_t *index, size_t indir, unsigned char *dst, size_t size) {
	if (block->idx[indir] == block->len[indir]) {
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

		n = _block_fetch(block, index, block->data[indir], block->size, encryption_key);
		if (n < 0) {
			fprintf(stderr, "_block_fetch failed\n");
			return -1;
		}

		assert(n > 0);

		block->len[indir] = n;
		block->idx[indir] = 0;
	}


	size_t n = block->len[indir] - block->idx[indir];
	n = n < size ? n : size;
	memcpy(dst, block->data[indir] + block->idx[indir], n);
	block->idx[indir] += n;
	return n;
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

	if (size >= block->size) {
		n = _block_fetch(block, index, dst, size, encryption_key);
		if (n < 0) {
			fprintf(stderr, "_block_fetch failed\n");
			return -1;
		}

		return n;
	}

	n = _block_fetch(block, index, block->data[0], block->size, encryption_key);
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
