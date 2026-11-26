//! `support/nfs/xlog.c`: messages to stderr and syslog, debug facilities, and the
//! `SIGUSR1`/`SIGUSR2` toggles.
//!
//! The state lives in atomics because, as in C, the signal handlers log straight away.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::Relaxed};

use crate::sys;

pub const L_FATAL: i32 = 0x0100;
pub const L_ERROR: i32 = 0x0200;
pub const L_WARNING: i32 = 0x0400;
pub const L_NOTICE: i32 = 0x0800;
pub const L_ALL: i32 = 0xFF00;
pub const D_GENERAL: i32 = 0x0001;
pub const D_CALL: i32 = 0x0002;
pub const D_AUTH: i32 = 0x0004;
pub const D_PARSE: i32 = 0x0040;
pub const D_ALL: i32 = 0x00FF;
/// `LOG_INFO` passed as a kind, as `conffile.c` does: `D_CALL | D_AUTH`.
pub const LOG_INFO_KIND: i32 = 6;

static LOG_STDERR: AtomicI32 = AtomicI32::new(1);
static LOG_SYSLOG: AtomicI32 = AtomicI32::new(1);
static LOGGING: AtomicI32 = AtomicI32::new(0);
static LOGMASK: AtomicI32 = AtomicI32::new(0);
static LOG_NAME: OnceLock<Vec<u8>> = OnceLock::new();
/// Set while code runs that, in C, has its own copy of `xlog.c` (libnfsidmap and its
/// plugins each link `libnfsconf` with hidden symbols): that copy is never opened or
/// configured, so it logs with an empty name, to both stderr and syslog, and no debug
/// facilities.
static IN_COPY: AtomicBool = AtomicBool::new(false);

/// Run `f` as code with its own, never configured, copy of `xlog.c`.
pub fn in_library_copy<T>(f: impl FnOnce() -> T) -> T {
    let was = IN_COPY.swap(true, Relaxed);
    let r = f();
    IN_COPY.store(was, Relaxed);
    r
}

/// `debugnames[]`.
const DEBUGNAMES: &[(&[u8], i32)] = &[
    (b"0", 0),
    (b"general", D_GENERAL),
    (b"call", D_CALL),
    (b"auth", D_AUTH),
    (b"parse", D_PARSE),
    (b"all", D_ALL),
    (b"1", D_ALL),
];

/// `xlog_open()`: `openlog(progname, LOG_PID, LOG_DAEMON)`, remember the name, and
/// install the toggles.
pub fn xlog_open(progname: &[u8]) {
    sys::openlog(progname, libc::LOG_PID, libc::LOG_DAEMON);
    // log_name is char[256]: strncpy(log_name, progname, 255).
    let n = &progname[..progname.len().min(255)];
    let _ = LOG_NAME.set(n.to_vec());
    sys::signal(libc::SIGUSR1, sys::Handler::Func(xlog_toggle));
    sys::signal(libc::SIGUSR2, sys::Handler::Func(xlog_toggle));
}

/// `xlog_stderr()`.
pub fn xlog_stderr(on: bool) {
    LOG_STDERR.store(i32::from(on), Relaxed);
}

/// `xlog_syslog()`.
pub fn xlog_syslog(on: bool) {
    LOG_SYSLOG.store(i32::from(on), Relaxed);
}

/// `xlog_toggle()`, the signal handler.
extern "C" fn xlog_toggle(sig: libc::c_int) {
    let saved = sys::errno();
    if sig == libc::SIGUSR1 {
        let logmask = LOGMASK.load(Relaxed);
        if (logmask & D_ALL) != 0 && LOGGING.load(Relaxed) == 0 {
            xlog(D_GENERAL, b"turned on logging");
            LOGGING.store(1, Relaxed);
            sys::set_errno(saved);
            return;
        }
        let tmp = !logmask;
        let logmask = logmask | ((logmask & D_ALL) << 1) | D_GENERAL;
        LOGMASK.store(logmask, Relaxed);
        // for (i = -1, tmp &= logmask; tmp; tmp >>= 1, i++): i is unsigned, printed
        // with %d.
        let mut tmp = (tmp & logmask) as u32;
        let mut i: u32 = u32::MAX;
        while tmp != 0 {
            if tmp & 1 != 0 {
                xlog(D_GENERAL, &bfmt!("turned on logging level {}", i as i32));
            }
            tmp >>= 1;
            i = i.wrapping_add(1);
        }
    } else {
        xlog(D_GENERAL, b"turned off logging");
        LOGGING.store(0, Relaxed);
    }
    sys::signal(sig, sys::Handler::Func(xlog_toggle));
    sys::set_errno(saved);
}

/// `xlog_config()`.
pub fn xlog_config(fac: i32, on: bool) {
    if on {
        LOGMASK.fetch_or(fac, Relaxed);
        LOGGING.store(1, Relaxed);
    } else {
        LOGMASK.fetch_and(!fac, Relaxed);
    }
}

/// `xlog_sconfig()`.
pub fn xlog_sconfig(kind: &[u8], on: bool) {
    match DEBUGNAMES.iter().find(|(n, _)| sys::strcaseeq(n, kind)) {
        None => xlog(L_WARNING, &bfmt!("Invalid debug facility: {}\n", kind)),
        Some(&(_, fac)) => {
            if fac != 0 {
                xlog_config(fac, on);
            }
        }
    }
}

/// `xlog_set_debug()`: the `debug` list in the program's section.
pub fn xlog_set_debug(service: &[u8]) {
    if let Some(kinds) = crate::conffile::conf_get_list(service, b"debug") {
        for k in kinds {
            xlog_sconfig(&k, true);
        }
    }
}

/// `xlog_enabled()`.
pub fn xlog_enabled(fac: i32) -> bool {
    LOGGING.load(Relaxed) != 0 && (fac & LOGMASK.load(Relaxed)) != 0
}

/// `xlog_backend()`: `msg` is the formatted message (`%m` already expanded).
pub fn xlog(kind: i32, msg: &[u8]) {
    let copy = IN_COPY.load(Relaxed);
    let (logging, logmask) = if copy { (0, 0) } else { (LOGGING.load(Relaxed), LOGMASK.load(Relaxed)) };
    if (kind & L_ALL) == 0 && !(logging != 0 && (kind & logmask) != 0) {
        return;
    }
    let log_stderr = copy || LOG_STDERR.load(Relaxed) != 0;
    if log_stderr {
        let name: &[u8] = if copy { b"" } else { LOG_NAME.get().map_or(b"", |v| v) };
        // fprintf(stderr, "%s: ", log_name); vfprintf(stderr, ...); fprintf(stderr, "\n").
        let mut head = name.to_vec();
        head.extend_from_slice(b": ");
        sys::stderr(&head);
        sys::stderr(c_str(msg));
        sys::stderr(b"\n");
    }
    if copy || LOG_SYSLOG.load(Relaxed) != 0 {
        let pri = match kind {
            L_FATAL | L_ERROR => Some(libc::LOG_ERR),
            L_WARNING => Some(libc::LOG_WARNING),
            L_NOTICE => Some(libc::LOG_NOTICE),
            _ if !log_stderr => Some(libc::LOG_INFO),
            _ => None,
        };
        if let Some(p) = pri {
            sys::syslog(p, msg);
        }
    }
    if kind == L_FATAL {
        sys::exit(1);
    }
}

/// `xlog_warn()`.
pub fn xlog_warn(msg: &[u8]) {
    xlog(L_WARNING, msg);
}

/// `xlog_errno()`: `errno = err`, then logs (`%m` in `msg` already expanded from
/// `err`) and exits 1.
pub fn xlog_errno(err: i32, msg: &[u8]) -> ! {
    sys::set_errno(err);
    xlog(L_FATAL, msg);
    sys::exit(1);
}

/// `xlog_err()`: logs and exits 1.
pub fn xlog_err(msg: &[u8]) -> ! {
    xlog(L_FATAL, msg);
    sys::exit(1);
}

/// What a `%s` of `s` prints: up to the first NUL.
pub fn c_str(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    &s[..end]
}

/// `%m`: `strerror(errno)` now.
pub fn m() -> Vec<u8> {
    sys::strerror(sys::errno())
}
