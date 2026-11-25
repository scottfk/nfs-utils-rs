//! `support/nfs/mydaemon.c` (`daemon_init()`, `daemon_ready()`) and
//! `support/nfs/closeall.c`.

use std::sync::atomic::{AtomicI32, Ordering::Relaxed};

use crate::sys::{self, Fd};
use crate::xlog::xlog_err;

/// `pipefds[1]`, the write end to the waiting parent.
static PIPE_W: AtomicI32 = AtomicI32::new(-1);

/// `closeall(min)`: close every descriptor from `min` up, as listed in
/// `/proc/self/fd` (or else up to `sysconf(_SC_OPEN_MAX)`).
pub fn closeall(min: Fd) {
    match sys::Dir::open(b"/proc/self/fd") {
        Some(mut dir) => {
            let dfd = dir.fd();
            while let Some((name, _)) = dir.next_entry() {
                let (n, used, err) = sys::strtol10(&name);
                if !err && used == name.len() && used != 0 && n >= i64::from(min) && n != i64::from(dfd) {
                    sys::close(n as Fd);
                }
            }
        }
        None => {
            let mut fd = sys::open_max();
            loop {
                fd -= 1;
                if fd < i64::from(min) {
                    break;
                }
                if fd >= 0 {
                    sys::close(fd as Fd);
                }
            }
        }
    }
}

/// `daemon_init(fg)`: unless `fg`, fork; the parent waits for the child's status on a
/// pipe (from [`daemon_ready`], or end of file when the child dies) and exits with it.
/// The child starts a session in `/`, puts `/dev/null` on 0-2 and the pipe on 3, and
/// closes everything else.
pub fn daemon_init(fg: bool) {
    if fg {
        return;
    }
    let Some((r, w)) = sys::pipe() else {
        let e = sys::errno();
        xlog_err(&crate::bfmt!("mydaemon: pipe() failed: errno {} ({})\n", e, sys::strerror(e)));
    };
    let pid = sys::fork();
    if pid < 0 {
        let e = sys::errno();
        xlog_err(&crate::bfmt!("mydaemon: fork() failed: errno {} ({})\n", e, sys::strerror(e)));
    }
    if pid > 0 {
        sys::close(w);
        let mut status = [0u8; 4];
        if sys::read(r, &mut status) != 4 {
            sys::exit(1);
        }
        sys::exit(i32::from_ne_bytes(status));
    }
    sys::close(r);
    sys::setsid();
    if sys::chdir(b"/") != 0 {
        let e = sys::errno();
        xlog_err(&crate::bfmt!("mydaemon: chdir() failed: errno {} ({})\n", e, sys::strerror(e)));
    }
    let mut w = w;
    while w <= 2 {
        w = sys::dup(w);
        if w < 0 {
            let e = sys::errno();
            xlog_err(&crate::bfmt!("mydaemon: dup() failed: errno {} ({})\n", e, sys::strerror(e)));
        }
    }
    let tempfd = sys::open(b"/dev/null", libc::O_RDWR, 0);
    if tempfd < 0 {
        let e = sys::errno();
        xlog_err(&crate::bfmt!("mydaemon: can't open /dev/null: errno {} ({})\n", e, sys::strerror(e)));
    }
    sys::dup2(tempfd, 0);
    sys::dup2(tempfd, 1);
    sys::dup2(tempfd, 2);
    sys::close(tempfd);
    sys::closelog();
    sys::dup2(w, 3);
    PIPE_W.store(3, Relaxed);
    closeall(4);
}

/// `daemon_ready()`: tell the parent the daemon is up (status 0).
pub fn daemon_ready() {
    let w = PIPE_W.load(Relaxed);
    if w > 0 {
        if sys::write(w, &0i32.to_ne_bytes()) != 4 {
            let e = sys::errno();
            xlog_err(&crate::bfmt!("WARN: writing to parent pipe failed: errno {} ({})\n", e, sys::strerror(e)));
        }
        sys::close(w);
        PIPE_W.store(-1, Relaxed);
    }
}
