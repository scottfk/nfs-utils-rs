/*
 * fakekeys.c - an LD_PRELOAD stand-in for the kernel's key calls, for the nfsidmap
 * differential tests
 *
 * 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * A sandbox can't have the kernel call request-key into it, so the keys nfsidmap is
 * asked to answer can't be real. libkeyutils and the Rust port both make their key
 * calls through glibc's syscall(); this replaces it for SYS_keyctl and
 * SYS_request_key (everything else goes to the real one), with keys from the file
 * $TEST_KEYS, and logs every call to $TEST_KEYLOG. Without TEST_KEYS it does nothing.
 *
 * The file has one entry per line:
 *
 *   key SERIAL TYPE DESC     a key (SERIAL in hex)
 *   member RING SERIAL       SERIAL is on keyring RING
 *   expired SERIAL           describing it fails with EKEYEXPIRED
 *   request TYPE DESC SERIAL request_key(TYPE, DESC) finds SERIAL (else ENOKEY)
 *   fail OP SERIAL ERRNO [N] OP on SERIAL (hex, or *) fails with ERRNO, the first N
 *                            times (default: always); OP is describe, read, clear,
 *                            instantiate, set_timeout, invalidate, revoke or
 *                            request_key
 *
 * /proc/keys is the test's to fake (a file bound over it).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#define KEYCTL_REVOKE 3
#define KEYCTL_DESCRIBE 6
#define KEYCTL_CLEAR 7
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12
#define KEYCTL_SET_TIMEOUT 15
#define KEYCTL_INVALIDATE 21

#define MAXKEYS 64
#define MAXMEM 64
#define MAXRULES 32

struct key {
	int serial;
	char type[64];
	char desc[256];
	int expired;
	int gone;
	int nmem;
	int mem[MAXMEM];
};

struct rule {
	char op[32];
	int serial; /* -1: any */
	int err;
	int left; /* -1: always */
};

struct req {
	char type[64];
	char desc[256];
	int serial;
};

static struct key keys[MAXKEYS];
static int nkeys;
static struct rule rules[MAXRULES];
static int nrules;
static struct req reqs[MAXRULES];
static int nreqs;
static int loaded, active;
static FILE *logf;

static long (*real_syscall)(long, ...);

static struct key *find(int serial)
{
	for (int i = 0; i < nkeys; i++)
		if (keys[i].serial == serial && !keys[i].gone)
			return &keys[i];
	return NULL;
}

static void load(void)
{
	char line[1024];
	const char *path, *lp;
	FILE *f;

	if (loaded)
		return;
	loaded = 1;
	path = getenv("TEST_KEYS");
	if (!path)
		return;
	active = 1;
	lp = getenv("TEST_KEYLOG");
	if (lp)
		logf = fopen(lp, "a");
	f = fopen(path, "r");
	if (!f)
		return;
	while (fgets(line, sizeof line, f)) {
		char a[256], b[256], c[256], d[256], e[256];
		int n = sscanf(line, "%255s %255s %255s %255s %255s", a, b, c, d, e);
		if (n >= 4 && strcmp(a, "key") == 0 && nkeys < MAXKEYS) {
			struct key *k = &keys[nkeys++];
			memset(k, 0, sizeof *k);
			k->serial = (int)strtoul(b, NULL, 16);
			snprintf(k->type, sizeof k->type, "%s", c);
			snprintf(k->desc, sizeof k->desc, "%s", d);
		} else if (n >= 3 && strcmp(a, "member") == 0) {
			struct key *r = find((int)strtoul(b, NULL, 16));
			if (r && r->nmem < MAXMEM)
				r->mem[r->nmem++] = (int)strtoul(c, NULL, 16);
		} else if (n >= 2 && strcmp(a, "expired") == 0) {
			struct key *k = find((int)strtoul(b, NULL, 16));
			if (k)
				k->expired = 1;
		} else if (n >= 4 && strcmp(a, "request") == 0 && nreqs < MAXRULES) {
			struct req *q = &reqs[nreqs++];
			snprintf(q->type, sizeof q->type, "%s", b);
			snprintf(q->desc, sizeof q->desc, "%s", c);
			q->serial = (int)strtoul(d, NULL, 16);
		} else if (n >= 4 && strcmp(a, "fail") == 0 && nrules < MAXRULES) {
			struct rule *r = &rules[nrules++];
			snprintf(r->op, sizeof r->op, "%s", b);
			r->serial = strcmp(c, "*") == 0 ? -1 : (int)strtoul(c, NULL, 16);
			r->err = atoi(d);
			r->left = n >= 5 ? atoi(e) : -1;
		}
	}
	fclose(f);
}

static void logit(const char *fmt, ...)
{
	va_list ap;

	if (!logf)
		return;
	va_start(ap, fmt);
	vfprintf(logf, fmt, ap);
	va_end(ap);
	fflush(logf);
}

/* An injected failure for OP on SERIAL, or 0. */
static int failure(const char *op, int serial)
{
	for (int i = 0; i < nrules; i++) {
		struct rule *r = &rules[i];
		if (strcmp(r->op, op) != 0 || (r->serial != -1 && r->serial != serial) || r->left == 0)
			continue;
		if (r->left > 0)
			r->left--;
		return r->err;
	}
	return 0;
}

static long result(long r, int err)
{
	if (r < 0) {
		logit(" -> -1 %s\n", strerrorname_np(err) ? strerrorname_np(err) : "?");
		errno = err;
		return -1;
	}
	logit(" -> %ld\n", r);
	return r;
}

static void logbytes(const unsigned char *p, unsigned long n)
{
	logit(" \"");
	for (unsigned long i = 0; i < n; i++) {
		if (p[i] >= 0x20 && p[i] < 0x7f && p[i] != '"' && p[i] != '\\')
			logit("%c", p[i]);
		else
			logit("\\x%02x", p[i]);
	}
	logit("\"");
}

static long copyout(char *buf, unsigned long len, const void *data, unsigned long size)
{
	if (buf && len > 0)
		memcpy(buf, data, len < size ? len : size);
	return (long)size;
}

static long do_keyctl(long cmd, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5)
{
	int serial = (int)a2;
	struct key *k = find(serial);
	int e;

	switch (cmd) {
	case KEYCTL_DESCRIBE: {
		char d[512];
		logit("describe 0x%x len=%lu", (unsigned)serial, a4);
		if ((e = failure("describe", serial)))
			return result(-1, e);
		if (!k)
			return result(-1, ENOKEY);
		if (k->expired)
			return result(-1, EKEYEXPIRED);
		snprintf(d, sizeof d, "%s;0;0;3f030000;%s", k->type, k->desc);
		return result(copyout((char *)a3, a4, d, strlen(d) + 1), 0);
	}
	case KEYCTL_READ: {
		logit("read 0x%x len=%lu", (unsigned)serial, a4);
		if ((e = failure("read", serial)))
			return result(-1, e);
		if (!k)
			return result(-1, ENOKEY);
		return result(copyout((char *)a3, a4, k->mem, sizeof(int) * (unsigned long)k->nmem), 0);
	}
	case KEYCTL_CLEAR:
		logit("clear 0x%x", (unsigned)serial);
		if ((e = failure("clear", serial)))
			return result(-1, e);
		if (!k)
			return result(-1, ENOKEY);
		if (strcmp(k->type, "keyring") != 0)
			return result(-1, ENOTDIR);
		k->nmem = 0;
		return result(0, 0);
	case KEYCTL_INSTANTIATE:
		logit("instantiate 0x%x", (unsigned)serial);
		logbytes((const unsigned char *)a3, a4);
		logit(" ring=%d", (int)a5);
		if ((e = failure("instantiate", serial)))
			return result(-1, e);
		return result(0, 0);
	case KEYCTL_SET_TIMEOUT:
		logit("set_timeout 0x%x %u", (unsigned)serial, (unsigned)a3);
		if ((e = failure("set_timeout", serial)))
			return result(-1, e);
		return result(0, 0);
	case KEYCTL_INVALIDATE:
	case KEYCTL_REVOKE: {
		const char *op = cmd == KEYCTL_INVALIDATE ? "invalidate" : "revoke";
		logit("%s 0x%x", op, (unsigned)serial);
		if ((e = failure(op, serial)))
			return result(-1, e);
		if (!k)
			return result(-1, ENOKEY);
		k->gone = 1;
		return result(0, 0);
	}
	default:
		logit("keyctl %ld", cmd);
		return result(-1, EOPNOTSUPP);
	}
}

static long do_request_key(const char *type, const char *desc, const char *callout, int dest)
{
	int e;

	logit("request_key %s %s callout=%s dest=%d", type, desc, callout ? callout : "NULL", dest);
	if ((e = failure("request_key", -1)))
		return result(-1, e);
	for (int i = 0; i < nreqs; i++)
		if (strcmp(reqs[i].type, type) == 0 && strcmp(reqs[i].desc, desc) == 0)
			return result(reqs[i].serial, 0);
	return result(-1, ENOKEY);
}

long syscall(long number, ...)
{
	va_list ap;
	long a[6];

	va_start(ap, number);
	for (int i = 0; i < 6; i++)
		a[i] = va_arg(ap, long);
	va_end(ap);

	if (number == SYS_keyctl || number == SYS_request_key) {
		load();
		if (active) {
			if (number == SYS_keyctl)
				return do_keyctl(a[0], (unsigned long)a[1], (unsigned long)a[2], (unsigned long)a[3],
						 (unsigned long)a[4]);
			return do_request_key((const char *)a[0], (const char *)a[1], (const char *)a[2], (int)a[3]);
		}
	}
	if (!real_syscall)
		real_syscall = (long (*)(long, ...))dlsym(RTLD_NEXT, "syscall");
	return real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}
