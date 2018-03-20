/*
   Copyright (C) 2014 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <asm/fcntl.h>

#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw.h>

#include <sys/syscall.h>
#include <dlfcn.h>

#define NFS_MAX_FD  255
#define NFS_MAX_DIR 255

static int debug = 0;
static int nfsuid = -1;
static int nfsgid = -1;

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

#define LD_NFS_DPRINTF(level, fmt, args...) \
	do { \
		if ((debug) >= level) { \
			fprintf(stderr,"ld_nfs: "); \
			fprintf(stderr, (fmt), ##args); \
			fprintf(stderr,"\n"); \
		} \
	} while (0);

struct nfs_fd_list {
       int is_nfs;
       struct nfs_context *nfs;
       struct nfsfh *fh;

       /* so we can reopen and emulate dup2() */
       const char *path;
       int flags;
       mode_t mode;
};

static struct nfs_fd_list nfs_fd_list[NFS_MAX_FD];

struct nfs_dir_list {
	int is_allocated;
	struct nfs_context *nfs;
	struct nfsdir *dir;
};

static struct nfs_dir_list nfs_dir_list[NFS_MAX_DIR];

static void *alloc_dir(struct nfs_context *nfs,
                      struct nfsdir *dir)
{
	int i;
	for (i = 0; i < NFS_MAX_DIR; i++) {
		if (!nfs_dir_list[i].is_allocated) {
			nfs_dir_list[i].is_allocated = 1;
			nfs_dir_list[i].nfs = nfs;
			nfs_dir_list[i].dir = dir;
			return &nfs_dir_list[i];
		}
	}

	return NULL;
}

static int lookup_dir(void *dirp, struct nfs_context **nfs_out,
                      struct nfsdir **dir_out)
{
	int i;
	for (i = 0; i < NFS_MAX_DIR; i++) {
		if (dirp == &nfs_dir_list[i]) {
			*nfs_out = nfs_dir_list[i].nfs;
			*dir_out = nfs_dir_list[i].dir;
			return 0;
		}
	}

	return -1;
}

static void free_dir(void *dirp)
{
	((struct nfs_dir_list*)dirp)->is_allocated = 0;
}

/* statically allocated dirent to be returned by 'readdir()' */
static struct dirent dirent;

static struct nfs_context *mount_path(const char *path)
{
	struct nfs_context *nfs;
	struct nfs_url *url;
	int ret;

	nfs = nfs_init_context();
	if (nfs == NULL) {
		LD_NFS_DPRINTF(1, "Failed to create context");
		errno = ENOMEM;
		return NULL;
	}

	if (nfsuid >= 0)
		nfs_set_uid(nfs, nfsuid);
	if (nfsgid >= 0)
		nfs_set_gid(nfs, nfsgid);

	url = nfs_parse_url_dir(nfs, path);

	if ((url == NULL) || (url->server == NULL) || (url->path == NULL)) {
		LD_NFS_DPRINTF(1, "Failed to parse URL: %s\n",
			nfs_get_error(nfs));
		if (url != NULL)
			nfs_destroy_url(url);
		nfs_destroy_context(nfs);
		errno = EINVAL;
		return NULL;
	}

	if ((ret = nfs_mount(nfs, url->server, url->path)) != 0) {
		LD_NFS_DPRINTF(1, "Failed to mount nfs share : %s\n",
		       nfs_get_error(nfs));
		nfs_destroy_url(url);
		nfs_destroy_context(nfs);
		errno = -ret;
		return NULL;
	}

	nfs_destroy_url(url);

	return nfs;
}

int (*real_open)(__const char *path, int flags, mode_t mode);

int open(const char *path, int flags, mode_t mode)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfsfh *fh = NULL;
		int ret, fd;

		LD_NFS_DPRINTF(9, "open(%s, %x, %o)", path, flags, mode);

		if ((nfs = mount_path(path)) == NULL)
			return -1;

		if (flags & O_CREAT) {
			if ((ret = nfs_creat(nfs, "", mode, &fh)) != 0) {
				LD_NFS_DPRINTF(1, "Failed to creat nfs file : "
					"%s\n", nfs_get_error(nfs));
				nfs_destroy_context(nfs);
				errno = -ret;
				return -1;
			}
		} else {
			if ((ret = nfs_open(nfs, "", flags, &fh)) != 0) {
				LD_NFS_DPRINTF(1, "Failed to open nfs file : "
					"%s\n", nfs_get_error(nfs));
				nfs_destroy_context(nfs);
				errno = -ret;
				return -1;
			}
		}

		fd = nfs_get_fd(nfs);
		if (fd >= NFS_MAX_FD) {
			LD_NFS_DPRINTF(1, "Too many files open");
			nfs_destroy_context(nfs);
			errno = ENFILE;
			return -1;
		}		

		nfs_fd_list[fd].is_nfs     = 1;
		nfs_fd_list[fd].nfs        = nfs;
		nfs_fd_list[fd].fh         = fh;
		nfs_fd_list[fd].path       = strdup(path);
		nfs_fd_list[fd].flags      = flags;
		nfs_fd_list[fd].mode       = mode;

		LD_NFS_DPRINTF(9, "open(%s) == %d", path, fd);
		return fd;
	}

	return real_open(path, flags, mode);
}

int open64(const char *path, int flags, mode_t mode)
{
	return open(path, flags | O_LARGEFILE, mode);
}

int (*real_close)(int fd);

int close(int fd)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int i;

		LD_NFS_DPRINTF(9, "close(%d)", fd);

		nfs_fd_list[fd].is_nfs = 0;

		nfs_close(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh);
		nfs_fd_list[fd].fh = NULL;

		nfs_destroy_context(nfs_fd_list[fd].nfs);
		nfs_fd_list[fd].nfs = NULL;

		free(discard_const(nfs_fd_list[fd].path));
		nfs_fd_list[fd].path = NULL;

		return 0;
	}

        return real_close(fd);
}

ssize_t (*real_read)(int fd, void *buf, size_t count);

ssize_t read(int fd, void *buf, size_t count)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "read(fd:%d count:%d)", fd, (int)count);
		if ((ret = nfs_read(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				count, buf)) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_read(fd, buf, count);
}

ssize_t (*real_pread)(int fd, void *buf, size_t count, off_t offset); 
ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "pread(fd:%d offset:%d count:%d)", fd,
			(int)offset, (int)count);
		if ((ret = nfs_pread(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				offset, count, buf)) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_pread(fd, buf, count, offset);
}

ssize_t (*real_write)(int fd, const void *buf, size_t count);

ssize_t write(int fd, const void *buf, size_t count)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "write(fd:%d count:%d)", fd, (int)count);
		if ((ret = nfs_write(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				count,
				(char *)discard_const(buf))) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_write(fd, buf, count);
}

ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset); 
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "pwrite(fd:%d offset:%d count:%d)", fd,
			(int)offset, (int)count);
		if ((ret = nfs_pwrite(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				offset, count,
				(char *)discard_const(buf))) < 0) {
			errno = -ret;
			return -1;
		}
		return ret;
	}
	return real_pwrite(fd, buf, count, offset);
}

int (*real_dup2)(int oldfd, int newfd);

int dup2(int oldfd, int newfd)
{
	close(newfd);

	if (nfs_fd_list[oldfd].is_nfs == 1) {
		struct nfs_context *nfs;
		struct nfs_url *url;
		struct nfsfh *fh = NULL;
		int ret, fd;

		LD_NFS_DPRINTF(9, "dup2(%s:%d, %d)", nfs_fd_list[oldfd].path,
			oldfd, newfd);
		nfs = nfs_init_context();
		if (nfs == NULL) {
			LD_NFS_DPRINTF(1, "Failed to create context");
			errno = ENOMEM;
			return -1;
		}

		url = nfs_parse_url_full(nfs, nfs_fd_list[oldfd].path);
		if (url == NULL) {
			LD_NFS_DPRINTF(1, "Failed to parse URL: %s\n",
				nfs_get_error(nfs));
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if (nfs_mount(nfs, url->server, url->path) != 0) {
			LD_NFS_DPRINTF(1, "Failed to mount nfs share : %s\n",
			       nfs_get_error(nfs));
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = EINVAL;
			return -1;
		}

		if ((ret = nfs_open(nfs, url->file, nfs_fd_list[oldfd].mode,
				&fh)) != 0) {
			LD_NFS_DPRINTF(1, "Failed to open nfs file : %s\n",
			       nfs_get_error(nfs));
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = -ret;
			return -1;
		}

		/* We could actually end on the right descriptor by chance */
		if (nfs_get_fd(nfs) != newfd) {
			if (real_dup2(nfs_get_fd(nfs), newfd) < 0) {
				LD_NFS_DPRINTF(1, "Failed to dup2 file : %d",
					errno);
				return -1;
			}

			close(rpc_get_fd(nfs_get_rpc_context(nfs)));
			rpc_set_fd(nfs_get_rpc_context(nfs), newfd);
		}

		fd = nfs_get_fd(nfs);
		if (fd >= NFS_MAX_FD) {
			LD_NFS_DPRINTF(1, "Too many files open");
			nfs_destroy_url(url);
			nfs_destroy_context(nfs);
			errno = ENFILE;
			return -1;
		}		

		nfs_fd_list[fd].is_nfs     = 1;
		nfs_fd_list[fd].nfs        = nfs;
		nfs_fd_list[fd].fh         = fh;
		nfs_fd_list[fd].path       = strdup(nfs_fd_list[oldfd].path);
		nfs_fd_list[fd].flags      = nfs_fd_list[oldfd].flags;
		nfs_fd_list[fd].mode       = nfs_fd_list[oldfd].mode;

		nfs_destroy_url(url);

		LD_NFS_DPRINTF(9, "dup2(%s) successful",
			nfs_fd_list[oldfd].path);
		return fd;
	}

	return real_dup2(oldfd, newfd);
}

int (*real___xstat)(int ver, __const char *path, struct stat *buf);

int __xstat(int ver, const char *path, struct stat *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfs_stat_64 st64;
		int ret;

		LD_NFS_DPRINTF(9, "__xstat(%s)", path);

		if ((nfs = mount_path(path)) == NULL)
			return -1;

		ret = nfs_stat64(nfs, "", (void *)&st64);

		nfs_destroy_context(nfs);
	
		if (ret < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__xstat(%s) success", path);
		return ret;
	}

	return real___xstat(ver, path, buf);
}

int (*real___xstat64)(int ver, __const char *path, struct stat64 *buf);

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfs_stat_64 st64;
		int ret;

		LD_NFS_DPRINTF(9, "__xstat64(%s)", path);

		if ((nfs = mount_path(path)) == NULL)
			return -1;

		ret = nfs_stat64(nfs, "", (void *)&st64);

		nfs_destroy_context(nfs);
	
		if (ret < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__xstat64(%s) success", path);
		return ret;
	}

	return real___xstat64(ver, path, buf);

}

int (*real___lxstat)(int ver, __const char *path, struct stat *buf);

int __lxstat(int ver, const char *path, struct stat *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfs_stat_64 st64;
		int ret;

		LD_NFS_DPRINTF(9, "__lxstat(%s)", path);

		if ((nfs = mount_path(path)) == NULL)
			return -1;

		ret = nfs_lstat64(nfs, "", (void *)&st64);

		nfs_destroy_context(nfs);
	
		if (ret < 0) {
			LD_NFS_DPRINTF(9, "__lxstat(%s): nfs_lstat64() failed", path);
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__lxstat(%s) success", path);
		return ret;
	}

	return real___lxstat(ver, path, buf);
}

int (*real___lxstat64)(int ver, __const char *path, struct stat64 *buf);

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfs_stat_64 st64;
		int ret;

		LD_NFS_DPRINTF(9, "__lxstat64(%s)", path);

		if ((nfs = mount_path(path)) == NULL)
			return -1;

		ret = nfs_lstat64(nfs, "", (void *)&st64);

		nfs_destroy_context(nfs);
	
		if (ret < 0) {
			LD_NFS_DPRINTF(9, "__lxstat64(%s): lstat failed", path);
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__lxstat64(%s) success", path);
		return ret;
	}

	return real___lxstat64(ver, path, buf);
}

int (*real___fxstat)(int ver, int fd, struct stat *buf);

int __fxstat(int ver, int fd, struct stat *buf)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;
		struct nfs_stat_64 st64;

		LD_NFS_DPRINTF(9, "__fxstat(%d)", fd);
		if ((ret = nfs_fstat64(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				(void *)&st64)) < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__fxstat(%d) success", fd);
		return ret;
	}

	return real___fxstat(ver, fd, buf);
}

int (*real___fxstat64)(int ver, int fd, struct stat64 *buf);

int __fxstat64(int ver, int fd, struct stat64 *buf)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;
		struct nfs_stat_64 st64;

		LD_NFS_DPRINTF(9, "__fxstat64(%d)", fd);
		if ((ret = nfs_fstat64(nfs_fd_list[fd].nfs, nfs_fd_list[fd].fh,
				(void *)&st64)) < 0) {
			errno = -ret;
			return -1;
		}

		buf->st_dev     = st64.nfs_dev;
		buf->st_ino     = st64.nfs_ino;
		buf->st_mode    = st64.nfs_mode;
		buf->st_nlink   = st64.nfs_nlink;
		buf->st_uid     = st64.nfs_uid;
		buf->st_gid     = st64.nfs_gid;
		buf->st_rdev    = st64.nfs_rdev;
		buf->st_size    = st64.nfs_size;
		buf->st_blksize = st64.nfs_blksize;
		buf->st_blocks  = st64.nfs_blocks;
		buf->st_atim.tv_sec   = st64.nfs_atime;
		buf->st_mtim.tv_sec   = st64.nfs_mtime;
		buf->st_ctim.tv_sec   = st64.nfs_ctime;

		LD_NFS_DPRINTF(9, "__fxstat64(%d) success", fd);
		return ret;
	}

	return real___fxstat64(ver, fd, buf);
}

int (*real___fxstatat)(int ver, int fd, const char *path, struct stat *buf, int flag);

int __fxstatat(int ver, int fd, const char *path, struct stat *buf, int flag)
{
	if (!strncmp(path, "nfs:", 4)) {
		return __xstat(ver, path, buf);
	}

	return real___fxstatat(ver, fd, path, buf, flag);
}

int (*real___fxstatat64)(int ver, int fd, const char *path, struct stat64 *buf, int flag);

int __fxstatat64(int ver, int fd, const char *path, struct stat64 *buf, int flag)
{
	if (!strncmp(path, "nfs:", 4)) {
		return __xstat64(ver, path, buf);
	}
	return real___fxstatat64(ver, fd, path, buf, flag);
}

int (*real_fallocate)(int fd, int mode, off_t offset, off_t len);

int fallocate(int fd, int mode, off_t offset, off_t len)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		LD_NFS_DPRINTF(9, "fallocate(%d)", fd);
		errno = EOPNOTSUPP;
		return -1;
	}

	return real_fallocate(fd, mode, offset, len);
}

int (*real_ftruncate)(int fd, off_t len);

int ftruncate(int fd, off_t len)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "ftruncate(%d, %d)", fd, (int)len);
		if ((ret = nfs_ftruncate(nfs_fd_list[fd].nfs,
				nfs_fd_list[fd].fh,
				len)) < 0) {
			errno = -ret;
			return -1;
		}
		return 0;
	}

	return real_ftruncate(fd, len);
}

int (*real_truncate)(const char *path, off_t len);

int truncate(const char *path, off_t len)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "truncate(%s, %d)", path, (int)len);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = ftruncate(fd, len);
		close(fd);
		return ret;
	}

	return real_truncate(path, len);
}

int (*real_fchmod)(int fd, mode_t mode);

int fchmod(int fd, mode_t mode)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "fchmod(%d, %o)", fd, (int)mode);
		if ((ret = nfs_fchmod(nfs_fd_list[fd].nfs,
				nfs_fd_list[fd].fh,
				mode)) < 0) {
			errno = -ret;
			return -1;
		}
		return 0;
	}

	return real_fchmod(fd, mode);
}

int (*real_chmod)(const char *path, mode_t mode);

int chmod(const char *path, mode_t mode)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "chmod(%s, %o)", path, (int)mode);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = fchmod(fd, mode);
		close(fd);
		return ret;
	}

	return real_chmod(path, mode);
}

int (*real_fchmodat)(int fd, const char *path, mode_t mode, int flags);

int fchmodat(int fd, const char *path, mode_t mode, int flags)
{
	if (!strncmp(path, "nfs:", 4)) {
		return chmod(path, mode);
	}

	return real_fchmodat(fd, path, mode, flags);
}

int (*real_fchown)(int fd, __uid_t uid, __gid_t gid);

int fchown(int fd, __uid_t uid, __gid_t gid)
{
	if (nfs_fd_list[fd].is_nfs == 1) {
		int ret;

		LD_NFS_DPRINTF(9, "fchown(%d, %o, %o)", fd, (int)uid, (int)gid);
		if ((ret = nfs_fchown(nfs_fd_list[fd].nfs,
				nfs_fd_list[fd].fh,
				uid, gid)) < 0) {
			errno = -ret;
			return -1;
		}
		return 0;
	}

	return real_fchown(fd, uid, gid);
}

int (*real_chown)(const char *path, __uid_t uid, __gid_t gid);

int chown(const char *path, __uid_t uid, __gid_t gid)
{
	if (!strncmp(path, "nfs:", 4)) {
		int fd, ret;

		LD_NFS_DPRINTF(9, "chown(%s, %o, %o)", path, (int)uid, (int)gid);
		fd = open(path, 0, 0);
		if (fd == -1) {
			return fd;
		}

		ret = fchown(fd, uid, gid);
		close(fd);
		return ret;
	}

	return real_chown(path, uid, gid);
}

int (*real_fchownat)(int fd, const char *path, __uid_t uid, __gid_t gid, int flags);

int fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flags)
{
	if (!strncmp(path, "nfs:", 4)) {
		return chown(path, uid, gid);
	}

	return real_fchownat(fd, path, uid, gid, flags);
}

DIR *(*real_opendir)(const char *name);

DIR *opendir(const char *path)
{
	if (!strncmp(path, "nfs:", 4)) {
		struct nfs_context *nfs;
		struct nfsdir *nfsdir;
		DIR *dir;
		int ret;

		LD_NFS_DPRINTF(9, "opendir(%s)", path);

		if ((nfs = mount_path(path)) == NULL)
			return NULL;

		ret = nfs_opendir(nfs, "", &nfsdir);

		if (ret != 0) {
			nfs_destroy_context(nfs);
			errno = -ret;
			return NULL;
		}

		dir = alloc_dir(nfs, nfsdir);

		if (dir == NULL) {
			errno = ENFILE; 
			return NULL;
		}

		LD_NFS_DPRINTF(9, "opendir(%s) success", path);

		return (DIR*)dir;
	}

	return real_opendir(path);
}

struct dirent *(*real_readdir)(DIR *dirp);

struct dirent *readdir(DIR *dirp)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		struct nfsdirent *nfsdirent;
		int ret;

		LD_NFS_DPRINTF(9, "readdir()");

		nfsdirent = nfs_readdir(nfs, nfsdir);

		if (nfsdirent == NULL)
			return NULL;

		/* only 'd_ino' and 'd_name' are required by POSIX */
		dirent.d_ino = nfsdirent->inode;
		strncpy (dirent.d_name, nfsdirent->name, sizeof(dirent.d_name) - 1);

		return &dirent;
	}

	return real_readdir(dirp);
}

int (*real_readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result);

int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		LD_NFS_DPRINTF(9, "readdir_r(): not implemented");
		*result = NULL;
		return 0;
	}

	return real_readdir_r(dirp, entry, result);
}

void (*real_rewinddir)(DIR *dirp);

void rewinddir(DIR *dirp)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		LD_NFS_DPRINTF(9, "rewinddir()");
		nfs_rewinddir(nfs, nfsdir);
		return;
	}

	real_rewinddir(dirp);
}

void (*real_seekdir)(DIR *dirp, long loc);

void seekdir(DIR *dirp, long loc)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		LD_NFS_DPRINTF(9, "seekdir()");
		nfs_seekdir(nfs, nfsdir, loc);
		return;
	}

	real_seekdir(dirp, loc);
}

long (*real_telldir)(DIR *dirp);

long telldir(DIR *dirp)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		LD_NFS_DPRINTF(9, "telldir()");
		return nfs_telldir(nfs, nfsdir);
	}

	return real_telldir(dirp);
}

int (*real_closedir)(DIR *dirp);

int closedir(DIR *dirp)
{
	struct nfs_context *nfs;
	struct nfsdir *nfsdir;

	if (lookup_dir(dirp, &nfs, &nfsdir) == 0) {
		LD_NFS_DPRINTF(9, "closedir()");
		nfs_closedir(nfs, nfsdir);
		nfs_destroy_context(nfs);
		free_dir(dirp);
		return 0;
	}

	return real_closedir(dirp);
}

#define DLSYM(func) \
	do { \
		real_##func = dlsym(RTLD_NEXT, #func); \
		if (real_##func == NULL) { \
			LD_NFS_DPRINTF(0, "Failed to dlsym("#func")"); \
			exit(10); \
		} \
	} while(0);

static void __attribute__((constructor)) _init(void)
{
	int i;

	if (getenv("LD_NFS_DEBUG") != NULL) {
		debug = atoi(getenv("LD_NFS_DEBUG"));
	}

	if (getenv("LD_NFS_UID") != NULL) {
		nfsuid = atoi(getenv("LD_NFS_UID"));
	}

	if (getenv("LD_NFS_GID") != NULL) {
		nfsgid = atoi(getenv("LD_NFS_GID"));
	}

	DLSYM(open)
	DLSYM(close)
	DLSYM(read)
	DLSYM(pread)
	DLSYM(write)
	DLSYM(pwrite)
	DLSYM(__xstat)
	DLSYM(__xstat64)
	DLSYM(__lxstat)
	DLSYM(__lxstat64)
	DLSYM(__fxstat)
	DLSYM(__fxstat64)
	DLSYM(__fxstatat)
	DLSYM(__fxstatat64)
	DLSYM(fallocate)
	DLSYM(dup2)
	DLSYM(truncate)
	DLSYM(ftruncate)
	DLSYM(chmod)
	DLSYM(fchmod)
	DLSYM(fchmodat)
	DLSYM(chown)
	DLSYM(fchown)
	DLSYM(fchownat)
	DLSYM(opendir)
	DLSYM(readdir)
	DLSYM(readdir_r)
	DLSYM(closedir)
	DLSYM(rewinddir)
	DLSYM(seekdir)
	DLSYM(telldir)
}
