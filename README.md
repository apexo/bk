bk: yet another backup tool
===========================

What is it?
-----------

An archiving utility with deduplication, compression, encryption, and random access (via FUSE mount).

What is it not?
---------------

A full-featured backup solution.

Some terminology
----------------

A bk archive consists of up to four artifacts:

- an index file (.idx); this is required for deduplication (which is also used for differential backup) and for data recovery, this file does not contain sensitive information
- a data file (.data); required for recovery, this file is encrypted
- the root reference; required for recovery, this is very small and should be kept safe (i.e.: encrypted) since it contains the decryption key to all data
- optionally, an .midx file; this is only required for fast, mtime-based deduplication, it contains potentially sensitive information; should never leave the host on which the backup was created; the midx is disabled by default if you want it and understand the security implications use --create-midx

Create standalone archive
-------------------------

    bk backup / archive

Does a backup of the whole filesystem (/) and creates two files: archive.idx and archive.data. The root reference is printed on stdout. It is recommended to pipe it through gpg for encryption and store the result in archive.root, e.g.:

    bk backup / archive | gpg -a -e -r KEYID >archive.root

Of course, backing up the root filesystem with all special files is a bad idea. A simple fix may be to just exclude contents of directories on other filesystems via --xdev:

    bk backup --xdev / archive | gpg -a -e -r KEYID >archive.root

This will still backup the generated backup itself, which is a bad idea. You will want to exclude the folder in which the backups are generated, e.g. if you're working in /var/local/backups:

    bk backup --xdev -Evar/local/backups / archive | gpg -a -e -r KEYID >archive.root

Create differential archive
---------------------------

Basic syntax is the same as for a standalone archive, just add the name of one or more existing indices behind the archive name.

    bk backup / archive index1 index2 ...

Recovery
--------

There's only one way to get your data out: mount the archive (via FUSE).

For recovery you need the index and data files of the generated archive and of all referenced archives. You also need the root reference that was generated together with the archive. If you have stored the encrypted root reference in archive.root, as recommended above, your command line might look like this:

    gpg -d <archive.root | bk mount archive /mnt/backup

Any number of archives may be specified instead of "archive". You will need the archive that was generated together with the root reference and all other archives that were used (for deduplication) when creating that archive.

Filters
-------

Files may be included (excluded) with -I/--include (-E/--exclude). Filter argument must be a relative path which is interpreted relative to the backup root, the only special path component allowed is \*\* to match any number (including none) of path components. Empty path components, ".", and ".." are not allowed. Other path components are interpreted as shell wildcard patterns (via fnmatch). The filter order is important: the first matched filter wins. A final -I\*\* is implicit. Examples:

    bk backup / archive

will back up everything under /.

    bk backup -Ietc -Iroot -E\*\* / archive

will back up everything in /etc and /root, but nothing else.

    bk backup -Eproc -Edev -Esys / archive

will back up everything except /proc, /dev, and /sys.

    bk backup -E\*\*/.cache -Ihome -E\*\* / archive

will back up all home directories, but no files or directories (incl. their content) named .cache. You may want to use the --no-act option to verify that your filters behave as intended. You will need to escape wildcards to avoid having them by expanded by the shell, either by escaping or single-quoting arguments with wildcards or by disabling expansion, e.g. via set -f.

Backup Internals
----------------

The backup itself works by recursively walking the directory that is to be backed up (+/- filters and --xdev). Files are split into blocks of blksize (64kiByte by default). The hash of the salt and the block contents is the block's encryption key. The hash of the block's encryption is the block's storage key. Blocks are compressed with lz4 and encrypted with AES-256-CTR with the block's encryption key, stored in the data file and a reference (via the storage key) is put into the index. The encryption key is block reference. Files longer than a few blocks will have their block references put into indirection blocks (multiple levels, potentially) which are compressed (to no avail) and encrypted just like regular file blocks. The reference(s) to highest-level indirection block(s) will be put (together with file stats and name) into the directory. Directory contents is stored (and indirected) just like file contents. The reference to the root directory is the root reference. Thus, the root reference is the decryption key to the root directory, which contains the decryption keys to all files/directories in the root directory and so on …

The .midx is a mapping of file (hashed, with salt) path + size + mtime to the file's reference, which is encrypted with the salt. It is thusly quite unsafe, since the salt is stored on disk.

Salt
----

The salt is stored in ~/.config/bk/bk.salt. If the salt file doesn't exist, it will be created by bk backup. Deduplication (via .idx and/or .midx) only works against archives that have been created with the same salt. Knowledge of the salt allows certain attacks against .idx (an attacker may query the index to find out if it contains a block of data known by the attacker) and full decryption of your data via .midx. As long not both, salt and midx, leave the system, this shouldn't be a problem (but it generally is not required for any of them to leave the system). Of course, not enabling .midx is even more secure.

Caveat
------

We're using O\_NOATIME to open directories and files. This only works if you're the owner of the files/directories, root, or have the capability CAP\_FOWNER. If one of those criteria is not met, you will receive "Operation not permitted" error messages (and those files/directories will NOT get backed up).
