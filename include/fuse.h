#ifndef BK_FUSE_H
#define BK_FUSE_H

int fuse_main(index_t *index, const unsigned char *ref, int ref_len, size_t blksize, int argc, char *argv[]);

#endif
