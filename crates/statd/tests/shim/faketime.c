/*
 * faketime.c - LD_PRELOAD clock for the differential tests
 *
 * 20261111 - Created by Claude (claude.ai, Anthropic) - scottfk
 * 20261111 - Copied from metalog-rs for the cronie-rs tests; $TEST_FAKETIME - Claude - scottfk
 * 20261111 - Virtual sleep() for crond ($TEST_VIRTUAL_SLEEP, $TEST_STOP) - Claude - scottfk
 * 20261111 - Virtual alarm() for anacron - Claude - scottfk
 * 20261115 - Copied from cronie-rs for the logrotate-rs tests - Claude - scottfk
 * 20261122 - Copied from logrotate-rs for the rpcbind-rs tests - Claude - scottfk
 * 20261122 - Map the file once, so reading the clock needs no descriptor - Claude - scottfk
 * 20261125 - Copied from rpcbind-rs for the nfs-utils-rs tests - Claude - scottfk
 * 20261125 - Virtual poll() timeouts ($TEST_VIRTUAL_POLL) - Claude - scottfk
 * 20261125 - Virtual select() timeouts, for rpc.statd - Claude - scottfk
 *
 * If $TEST_FAKETIME names a readable file holding "SECONDS NANOSECONDS",
 * time(), gettimeofday() and clock_gettime(CLOCK_REALTIME) return that
 * instant.  The file is mapped at the first call and read through the mapping
 * on every call, so a test steps the clock by rewriting it in place (not by
 * replacing it), and a process out of descriptors still reads it.  Other clocks (CLOCK_MONOTONIC) pass
 * through.  Both the C reference and the Rust port call these through the PLT,
 * so one shim controls both.  errno is preserved: the C code prints
 * it after unrelated calls.
 *
 * With $TEST_VIRTUAL_SLEEP set, sleep() doesn't sleep: it waits until every
 * child of the caller has finished (is a zombie or gone), then moves the
 * fake clock forward by the requested seconds.  So crond runs a day of
 * minutes in moments, and each minute's jobs are done before the next one
 * starts.  If that would reach $TEST_STOP (seconds), the clock stops there
 * and the process gets SIGTERM, for a clean shutdown.  alarm(n) works the
 * same way, then raises SIGALRM at once (anacron waits with alarm() and
 * sigsuspend()).
 *
 * With $TEST_VIRTUAL_POLL set, a poll() with a positive timeout waits for
 * real only up to $TEST_VIRTUAL_POLL milliseconds; if nothing became ready
 * by then, the fake clock moves forward by the whole timeout and poll()
 * returns 0, as if it had waited.  So sm-notify's and statd's retry timers
 * run in moments.  Replies from the test's fake peers arrive well within
 * the real wait.
 *
 * select() with a timeout works the same way, except that a timeout that
 * passes moves the clock on to the start of the second after it.  rpc.statd
 * waits until a callback is due and then, finding it due only "this second",
 * spins on time() until the next second begins; this is where the real clock
 * would be when the spin ends.
 *
 * Build: cc -shared -fPIC -O2 -o faketime.so faketime.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <sys/select.h>

static int fake(struct timespec *ts)
{
    static const char *map;
    static int mapped;  /* 1 mapped, -1 not possible */
    const char *f = getenv("TEST_FAKETIME");
    char buf[64];
    long long s = 0, ns = 0;
    int saved = errno, i = 0, neg = 0;

    if (!f)
        return 0;
    if (!mapped) {
        int fd = open(f, O_RDONLY | O_CLOEXEC);

        mapped = -1;
        if (fd >= 0) {
            void *p = mmap(NULL, sizeof buf, PROT_READ, MAP_SHARED, fd, 0);

            close(fd);
            if (p != MAP_FAILED) {
                map = p;
                mapped = 1;
            }
        }
        errno = saved;
    }
    if (mapped < 0)
        return 0;
    memcpy(buf, map, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    /* No stdio here: the Rust port emulates stdio buffering, and the C
     * reference's FILE list should look the same with or without us. */
    if (buf[i] == '-') {
        neg = 1;
        i++;
    }
    if (buf[i] < '0' || buf[i] > '9')
        return 0;
    while (buf[i] >= '0' && buf[i] <= '9')
        s = s * 10 + (buf[i++] - '0');
    while (buf[i] == ' ')
        i++;
    while (buf[i] >= '0' && buf[i] <= '9')
        ns = ns * 10 + (buf[i++] - '0');
    ts->tv_sec = neg ? -s : s;
    ts->tv_nsec = ns;
    return 1;
}

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real)(clockid_t, struct timespec *);

    if (id == CLOCK_REALTIME && fake(ts))
        return 0;
    if (!real)
        real = (int (*)(clockid_t, struct timespec *)) dlsym(RTLD_NEXT, "clock_gettime");
    return real(id, ts);
}

time_t time(time_t *t)
{
    struct timespec ts;

    if (!fake(&ts))
        clock_gettime(CLOCK_REALTIME, &ts);
    if (t)
        *t = ts.tv_sec;
    return ts.tv_sec;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz)
{
    struct timespec ts;

    (void) tz;
    if (!fake(&ts))
        clock_gettime(CLOCK_REALTIME, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000;
    return 0;
}

/* All of our children finished (zombies or reaped)? */
static int children_done(void)
{
    char path[64], buf[4096], stat[512];
    int fd, n, i = 0;

    snprintf(path, sizeof path, "/proc/self/task/%d/children", (int) getpid());
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
        return 1;
    n = (int) read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 1;
    buf[n] = 0;
    while (i < n) {
        long pid = 0;
        while (i < n && (buf[i] < '0' || buf[i] > '9'))
            i++;
        if (i >= n)
            break;
        while (i < n && buf[i] >= '0' && buf[i] <= '9')
            pid = pid * 10 + (buf[i++] - '0');
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
            continue;
        int m = (int) read(fd, stat, sizeof stat - 1);
        close(fd);
        if (m <= 0)
            continue;
        stat[m] = 0;
        char *p = strrchr(stat, ')');
        if (p && p[1] == ' ' && p[2] != 'Z' && p[2] != 'X')
            return 0;
    }
    return 1;
}

static void advance(unsigned int secs, int *stopping);

unsigned int alarm(unsigned int secs)
{
    static unsigned int (*real)(unsigned int);
    int stopping = 0;

    if (!getenv("TEST_FAKETIME") || !getenv("TEST_VIRTUAL_SLEEP")) {
        if (!real)
            real = (unsigned int (*)(unsigned int)) dlsym(RTLD_NEXT, "alarm");
        return real(secs);
    }
    if (secs == 0)
        return 0;
    advance(secs, &stopping);
    kill(getpid(), stopping ? SIGTERM : SIGALRM);
    return 0;
}

unsigned int sleep(unsigned int secs)
{
    static unsigned int (*real)(unsigned int);
    int stopping = 0;

    if (!getenv("TEST_FAKETIME") || !getenv("TEST_VIRTUAL_SLEEP")) {
        if (!real)
            real = (unsigned int (*)(unsigned int)) dlsym(RTLD_NEXT, "sleep");
        return real(secs);
    }
    advance(secs, &stopping);
    if (stopping)
        kill(getpid(), SIGTERM);
    return 0;
}

/* Wait for our children, then move the fake clock on by secs (stopping at
 * $TEST_STOP, if set). */
static void advance(unsigned int secs, int *stopping)
{
    const char *f = getenv("TEST_FAKETIME");
    const char *stop = getenv("TEST_STOP");
    struct timespec ts, nap = { 0, 2000000 };
    char buf[64];
    int fd, saved = errno, n;

    while (!children_done())
        nanosleep(&nap, NULL);
    if (!fake(&ts))
        return;
    ts.tv_sec += secs;
    *stopping = stop && ts.tv_sec >= atoll(stop);
    if (*stopping)
        ts.tv_sec = atoll(stop);
    /* In place and at a fixed width: readers have the file mapped. */
    n = snprintf(buf, sizeof buf, "%020lld %09ld\n", (long long) ts.tv_sec, (long) ts.tv_nsec);
    if ((fd = open(f, O_WRONLY | O_CLOEXEC)) >= 0) {
        if (pwrite(fd, buf, (size_t) n, 0) < 0) { /* the clock just stays */ }
        close(fd);
    }
    errno = saved;
}

/* Move the fake clock forward by ms milliseconds. */
static void advance_ms(long ms)
{
    const char *f = getenv("TEST_FAKETIME");
    struct timespec ts;
    char buf[64];
    int fd, saved = errno, n;

    if (!fake(&ts))
        return;
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    n = snprintf(buf, sizeof buf, "%020lld %09ld\n", (long long) ts.tv_sec, (long) ts.tv_nsec);
    if ((fd = open(f, O_WRONLY | O_CLOEXEC)) >= 0) {
        if (pwrite(fd, buf, (size_t) n, 0) < 0) { /* the clock just stays */ }
        close(fd);
    }
    errno = saved;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    static int (*real)(struct pollfd *, nfds_t, int);
    const char *v = getenv("TEST_VIRTUAL_POLL");
    int r, wait;

    if (!real)
        real = (int (*)(struct pollfd *, nfds_t, int)) dlsym(RTLD_NEXT, "poll");
    if (!v || !getenv("TEST_FAKETIME") || timeout <= 0)
        return real(fds, nfds, timeout);
    wait = atoi(v);
    r = real(fds, nfds, timeout < wait ? timeout : wait);
    if (r == 0)
        advance_ms(timeout);
    return r;
}

int select(int nfds, fd_set *restrict r, fd_set *restrict w, fd_set *restrict e,
           struct timeval *restrict timeout)
{
    static int (*real)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
    const char *v = getenv("TEST_VIRTUAL_POLL");
    struct timeval tv;
    struct timespec ts;
    long ms;
    int res;

    if (!real)
        real = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *)) dlsym(RTLD_NEXT, "select");
    if (!v || !getenv("TEST_FAKETIME") || !timeout || (timeout->tv_sec <= 0 && timeout->tv_usec <= 0))
        return real(nfds, r, w, e, timeout);
    ms = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    tv.tv_sec = atoi(v) / 1000;
    tv.tv_usec = (atoi(v) % 1000) * 1000;
    if (ms < atoi(v)) {
        tv.tv_sec = timeout->tv_sec;
        tv.tv_usec = timeout->tv_usec;
    }
    res = real(nfds, r, w, e, &tv);
    if (res == 0) {
        advance_ms(ms);
        if (fake(&ts) && ts.tv_nsec != 0)
            advance_ms((1000000000L - ts.tv_nsec) / 1000000L);
        else
            advance_ms(1000);
        timeout->tv_sec = 0;
        timeout->tv_usec = 0;
    }
    return res;
}
