/*
 * fakepipes.c - LD_PRELOAD stand-in for the kernel's rpc.idmapd channels.
 *
 * 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * rpc.idmapd talks to nfsd through /proc/net/rpc/nfs4.{nametoid,idtoname}/channel
 * and to the NFS client through rpc_pipefs/nfs/clnt.../idmap: files it opens read-write,
 * reads one message from, and writes one answer to. Neither exists in a sandbox, and
 * a regular file or a FIFO can't play the part (epoll refuses regular files; a FIFO
 * hands the program its own answer back).
 *
 * This shim wraps open() and open64():
 *
 * - TEST_REMAP="from=to;from=to..." moves paths under each "from" prefix to "to"
 *   (/proc/net/rpc can't be mounted over, being per process);
 * - a read-write open of a Unix socket (which the kernel refuses with ENXIO) connects a
 *   SOCK_SEQPACKET socket to it instead, so the probe listening there sees a
 *   connection, and messages keep their boundaries both ways. The descriptor is the
 *   lowest free one, as open()'s would be. When nothing listens, the open fails with
 *   ENXIO.
 *
 * Everything else goes to the real open().
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static const char *remap(const char *path, char *buf, size_t size)
{
	const char *spec = getenv("TEST_REMAP");
	const char *p;

	if (spec == NULL || path == NULL)
		return path;
	for (p = spec; *p; ) {
		const char *eq = strchr(p, '=');
		const char *end = strchr(p, ';');
		size_t flen, tlen;

		if (end == NULL)
			end = p + strlen(p);
		if (eq == NULL || eq > end)
			break;
		flen = eq - p;
		tlen = end - eq - 1;
		if (strncmp(path, p, flen) == 0 && (path[flen] == '/' || path[flen] == '\0')) {
			if (snprintf(buf, size, "%.*s%s", (int)tlen, eq + 1, path + flen) < (int)size)
				return buf;
		}
		p = *end ? end + 1 : end;
	}
	return path;
}

static int do_open(int (*real)(const char *, int, ...), const char *path, int flags, mode_t mode)
{
	char buf[8192];
	const char *p = remap(path, buf, sizeof(buf));
	struct stat st;

	if ((flags & O_ACCMODE) == O_RDWR && stat(p, &st) == 0 && S_ISSOCK(st.st_mode)) {
		struct sockaddr_un sun;
		int type = SOCK_SEQPACKET;
		int fd;

		if (strlen(p) >= sizeof(sun.sun_path)) {
			errno = ENXIO;
			return -1;
		}
		if (flags & O_CLOEXEC)
			type |= SOCK_CLOEXEC;
		if (flags & O_NONBLOCK)
			type |= SOCK_NONBLOCK;
		fd = socket(AF_UNIX, type, 0);
		if (fd < 0)
			return -1;
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		strcpy(sun.sun_path, p);
		if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
			close(fd);
			errno = ENXIO;
			return -1;
		}
		return fd;
	}
	return real(p, flags, mode);
}

int open(const char *path, int flags, ...)
{
	static int (*real)(const char *, int, ...);
	mode_t mode = 0;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (real == NULL)
		real = dlsym(RTLD_NEXT, "open");
	return do_open(real, path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
	static int (*real)(const char *, int, ...);
	mode_t mode = 0;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (real == NULL)
		real = dlsym(RTLD_NEXT, "open64");
	return do_open(real, path, flags, mode);
}
