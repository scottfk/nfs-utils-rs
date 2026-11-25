//! Thin wrappers over libc.
//!
//! This is the only module of the crate with `unsafe` code. Where nfs-utils' behavior
//! depends on the C library (`getaddrinfo()`, `getnameinfo()`, `getservbyport()`,
//! `scandir()` with `versionsort()`, `strerror()`, `daemon()`, syslog), the C library
//! is called rather than imitated, so both programs get the same answers.

use std::ffi::{CStr, CString, c_char, c_int};

/// A file descriptor.
pub type Fd = c_int;

/// `s` as a C string, cut at the first NUL (as C sees it).
pub fn cstring(s: &[u8]) -> CString {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    CString::new(&s[..end]).unwrap()
}

/// `errno`.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Set `errno`.
pub fn set_errno(e: i32) {
    // SAFETY: __errno_location returns this thread's errno.
    unsafe { *libc::__errno_location() = e };
}

/// `strerror(e)`, as `%m` prints it.
pub fn strerror(e: i32) -> Vec<u8> {
    // SAFETY: strerror returns a valid C string; we copy it before anything else runs.
    unsafe { CStr::from_ptr(libc::strerror(e)) }.to_bytes().to_vec()
}

/// `open(path, flags, mode)`.
pub fn open(path: &[u8], flags: i32, mode: u32) -> Fd {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::open(p.as_ptr(), flags, mode as libc::c_uint) }
}

/// `close(fd)`.
pub fn close(fd: Fd) -> i32 {
    // SAFETY: closing a descriptor has no memory-safety preconditions.
    unsafe { libc::close(fd) }
}

/// `read(fd, buf, buf.len())`.
pub fn read(fd: Fd, buf: &mut [u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// `write(fd, buf, buf.len())`.
pub fn write(fd: Fd, buf: &[u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) }
}

/// `lseek(fd, off, whence)`.
pub fn lseek(fd: Fd, off: i64, whence: i32) -> i64 {
    // SAFETY: no memory is involved.
    unsafe { libc::lseek(fd, off, whence) }
}

/// `flock(fd, op)`.
pub fn flock(fd: Fd, op: i32) -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::flock(fd, op) }
}

/// `fchown(fd, uid, gid)`.
pub fn fchown(fd: Fd, uid: u32, gid: u32) -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::fchown(fd, uid, gid) }
}

/// What nfs-utils looks at in a `struct stat`.
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub mtime: i64,
}

impl Stat {
    pub fn is_reg(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
}

fn to_stat(st: &libc::stat) -> Stat {
    Stat { mode: st.st_mode, uid: st.st_uid, gid: st.st_gid, size: st.st_size, mtime: st.st_mtime }
}

/// `stat(path)`; `None` with `errno` set on failure.
pub fn stat(path: &[u8]) -> Option<Stat> {
    let p = cstring(path);
    // SAFETY: an all-zero struct stat is valid; p is a valid C string.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::stat(p.as_ptr(), &mut st) == 0).then(|| to_stat(&st))
    }
}

/// `lstat(path)`; `None` with `errno` set on failure.
pub fn lstat(path: &[u8]) -> Option<Stat> {
    let p = cstring(path);
    // SAFETY: as for stat.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::lstat(p.as_ptr(), &mut st) == 0).then(|| to_stat(&st))
    }
}

/// `rename(from, to)`.
pub fn rename(from: &[u8], to: &[u8]) -> i32 {
    let (a, b) = (cstring(from), cstring(to));
    // SAFETY: valid C strings.
    unsafe { libc::rename(a.as_ptr(), b.as_ptr()) }
}

/// `unlink(path)`.
pub fn unlink(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: a valid C string.
    unsafe { libc::unlink(p.as_ptr()) }
}

/// `chdir(path)`.
pub fn chdir(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: a valid C string.
    unsafe { libc::chdir(p.as_ptr()) }
}

/// `umask(mask)`.
pub fn umask(mask: u32) -> u32 {
    // SAFETY: no memory is involved.
    unsafe { libc::umask(mask) }
}

/// `getuid()`.
pub fn getuid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::getuid() }
}

/// `getpid()`.
pub fn getpid() -> i32 {
    // SAFETY: no preconditions.
    unsafe { libc::getpid() }
}

/// `prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)`.
pub fn keepcaps() -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0) }
}

/// `setgroups(0, NULL)`.
pub fn setgroups_none() -> i32 {
    // SAFETY: an empty list.
    unsafe { libc::setgroups(0, std::ptr::null()) }
}

/// `setgid(gid)`.
pub fn setgid(gid: u32) -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::setgid(gid) }
}

/// `setuid(uid)`.
pub fn setuid(uid: u32) -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::setuid(uid) }
}

/// `opendir()`/`readdir()`/`closedir()`.
#[derive(Debug)]
pub struct Dir(*mut libc::DIR);

impl Dir {
    /// `opendir(path)`; `None` with `errno` set on failure.
    pub fn open(path: &[u8]) -> Option<Dir> {
        let p = cstring(path);
        // SAFETY: a valid C string.
        let d = unsafe { libc::opendir(p.as_ptr()) };
        if d.is_null() { None } else { Some(Dir(d)) }
    }

    /// `readdir()`: the next entry's name and `d_type`.
    pub fn next_entry(&mut self) -> Option<(Vec<u8>, u8)> {
        // SAFETY: self.0 is an open DIR; the entry is copied before the next call.
        unsafe {
            let e = libc::readdir(self.0);
            if e.is_null() {
                return None;
            }
            Some((CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec(), (*e).d_type))
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: self.0 is an open DIR, closed once.
        unsafe { libc::closedir(self.0) };
    }
}

unsafe extern "C" {
    fn scandir(
        dir: *const c_char,
        list: *mut *mut *mut libc::dirent,
        filter: Option<unsafe extern "C" fn(*const libc::dirent) -> c_int>,
        compar: Option<unsafe extern "C" fn(*mut *const libc::dirent, *mut *const libc::dirent) -> c_int>,
    ) -> c_int;
    fn versionsort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
    fn __res_init() -> c_int;
}

/// `scandir(path, &list, NULL, versionsort)`: each entry's name and `d_type`, or `errno`.
pub fn scandir_versionsort(path: &[u8]) -> Result<Vec<(Vec<u8>, u8)>, i32> {
    let p = cstring(path);
    let mut list: *mut *mut libc::dirent = std::ptr::null_mut();
    // SAFETY: versionsort has scandir's comparison signature; the list is freed below.
    let n = unsafe { scandir(p.as_ptr(), &mut list, None, Some(versionsort)) };
    if n < 0 {
        return Err(errno());
    }
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        // SAFETY: scandir returned n malloc'ed entries in a malloc'ed array.
        unsafe {
            let e = *list.add(i);
            out.push((CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec(), (*e).d_type));
            libc::free(e.cast());
        }
    }
    // SAFETY: the array itself.
    unsafe { libc::free(list.cast()) };
    Ok(out)
}

/// `res_init()`.
pub fn res_init() {
    // SAFETY: no preconditions.
    unsafe { __res_init() };
}

/// One `getaddrinfo()` result.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    /// The `sockaddr`, `ai_addrlen` bytes.
    pub addr: Vec<u8>,
}

/// `getaddrinfo(node, service, hints)`: every result in order, or the error code.
pub fn getaddrinfo(
    node: Option<&[u8]>,
    service: Option<&[u8]>,
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
) -> Result<Vec<AddrInfo>, i32> {
    let n = node.map(cstring);
    let s = service.map(cstring);
    // SAFETY: an all-zero addrinfo is a valid hints structure; the strings outlive the
    // call; the result list is walked and freed here.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_flags = flags;
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_protocol = protocol;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let rc = libc::getaddrinfo(
            n.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            s.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            &hints,
            &mut res,
        );
        if rc != 0 {
            return Err(rc);
        }
        let mut out = Vec::new();
        let mut p = res;
        while !p.is_null() {
            let a = &*p;
            let bytes = std::slice::from_raw_parts(a.ai_addr.cast::<u8>(), a.ai_addrlen as usize).to_vec();
            out.push(AddrInfo { family: a.ai_family, socktype: a.ai_socktype, protocol: a.ai_protocol, addr: bytes });
            p = a.ai_next;
        }
        libc::freeaddrinfo(res);
        Ok(out)
    }
}

/// `gai_strerror(code)`.
pub fn gai_strerror(code: i32) -> Vec<u8> {
    // SAFETY: gai_strerror returns a static string.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)) }.to_bytes().to_vec()
}

/// `getnameinfo(sa, salen, host, NI_MAXHOST, NULL, 0, flags)`: the host, or the code.
pub fn getnameinfo_host(sa: &[u8], flags: i32) -> Result<Vec<u8>, i32> {
    let mut buf = [0 as c_char; libc::NI_MAXHOST as usize];
    // SAFETY: sa is sa.len() bytes of sockaddr; buf has NI_MAXHOST bytes.
    let rc = unsafe {
        libc::getnameinfo(
            sa.as_ptr().cast(),
            sa.len() as libc::socklen_t,
            buf.as_mut_ptr(),
            buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            flags,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    // SAFETY: getnameinfo NUL-terminates on success.
    Ok(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec())
}

/// `getservbyport(port, proto) != NULL`, with `port` passed as is (the C library
/// reads it in network order).
pub fn getservbyport_raw(port: c_int, proto: &[u8]) -> bool {
    let p = cstring(proto);
    // SAFETY: a C string; the result is only tested.
    unsafe { !libc::getservbyport(port, p.as_ptr()).is_null() }
}

/// `socket(af, type, proto)`.
pub fn socket(af: i32, ty: i32, proto: i32) -> Fd {
    // SAFETY: no memory is involved.
    unsafe { libc::socket(af, ty, proto) }
}

/// `fcntl(fd, F_SETFL, flags)`.
pub fn setfl(fd: Fd, flags: i32) -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }
}

/// `setsockopt(fd, level, name, &val, sizeof(int))`.
pub fn setsockopt_int(fd: Fd, level: i32, name: i32, val: i32) -> i32 {
    // SAFETY: val is an int on the stack.
    unsafe { libc::setsockopt(fd, level, name, (&val as *const c_int).cast(), size_of::<c_int>() as libc::socklen_t) }
}

/// `bind(fd, addr, addr.len())`.
pub fn bind(fd: Fd, addr: &[u8]) -> i32 {
    // SAFETY: addr is addr.len() bytes of sockaddr.
    unsafe { libc::bind(fd, addr.as_ptr().cast(), addr.len() as libc::socklen_t) }
}

/// `sendto(fd, buf, len, 0, addr, addr.len())`.
pub fn sendto(fd: Fd, buf: &[u8], addr: &[u8]) -> isize {
    // SAFETY: both slices are valid for their lengths.
    unsafe { libc::sendto(fd, buf.as_ptr().cast(), buf.len(), 0, addr.as_ptr().cast(), addr.len() as libc::socklen_t) }
}

/// `recv(fd, buf, len, 0)`.
pub fn recv(fd: Fd, buf: &mut [u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) }
}

/// `poll()` on one descriptor for `POLLIN`.
pub fn poll_in(fd: Fd, timeout_ms: i32) -> i32 {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd on the stack.
    unsafe { libc::poll(&mut p, 1, timeout_ms) }
}

/// `time(NULL)`.
pub fn time() -> i64 {
    // SAFETY: a NULL argument is allowed.
    unsafe { libc::time(std::ptr::null_mut()) }
}

/// `gettimeofday()`: seconds and microseconds.
pub fn gettimeofday() -> (i64, i64) {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    // SAFETY: tv is valid; a NULL time zone is allowed.
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    (tv.tv_sec, tv.tv_usec)
}

/// `daemon(0, 0)`.
pub fn daemon() -> i32 {
    // SAFETY: no memory is involved.
    unsafe { libc::daemon(0, 0) }
}

/// `exit(status)`: C's exit, which runs the atexit handlers and flushes stdio.
pub fn exit(status: i32) -> ! {
    // SAFETY: ends the process.
    unsafe { libc::exit(status) }
}

/// A signal disposition for [`signal`].
#[derive(Debug, Clone, Copy)]
pub enum Handler {
    Default,
    Ignore,
    Func(extern "C" fn(c_int)),
}

/// `signal(sig, handler)` (glibc's BSD semantics: `SA_RESTART`, not reset).
pub fn signal(sig: i32, h: Handler) {
    let hv = match h {
        Handler::Default => libc::SIG_DFL,
        Handler::Ignore => libc::SIG_IGN,
        Handler::Func(f) => f as usize,
    };
    // SAFETY: hv is SIG_DFL, SIG_IGN or an extern "C" fn(c_int).
    unsafe { libc::signal(sig, hv) };
}

/// `openlog(ident, option, facility)`. The identity string is leaked, as syslog keeps
/// the pointer.
pub fn openlog(ident: &[u8], option: i32, facility: i32) {
    let s = Box::leak(cstring(ident).into_boxed_c_str());
    // SAFETY: s lives forever.
    unsafe { libc::openlog(s.as_ptr(), option, facility) };
}

/// `syslog(pri, "%s", msg)`.
pub fn syslog(pri: i32, msg: &[u8]) {
    let m = cstring(msg);
    // SAFETY: a constant format with one string argument.
    unsafe { libc::syslog(pri, c"%s".as_ptr(), m.as_ptr()) };
}

/// `fprintf(stderr, "%s", msg)` on the unbuffered stderr: one `write()`.
pub fn stderr(msg: &[u8]) {
    let mut b = msg;
    while !b.is_empty() {
        let n = write(2, b);
        if n <= 0 {
            break;
        }
        b = &b[n as usize..];
    }
}

/// `getopt(argc, argv, optstring)` over a C argument vector kept alive by [`Args`].
#[derive(Debug)]
pub struct Args {
    _strings: Vec<CString>,
    ptrs: Vec<*mut c_char>,
}

unsafe extern "C" {
    static mut optarg: *mut c_char;
    static mut optind: c_int;
}

impl Args {
    /// The process's arguments, as C `argv`.
    pub fn from_env() -> Args {
        use std::os::unix::ffi::OsStringExt;
        let strings: Vec<CString> =
            std::env::args_os().map(|a| CString::new(a.into_vec()).unwrap_or_default()).collect();
        let mut ptrs: Vec<*mut c_char> = strings.iter().map(|s| s.as_ptr() as *mut c_char).collect();
        ptrs.push(std::ptr::null_mut());
        Args { _strings: strings, ptrs }
    }

    /// `argv[0]`.
    pub fn argv0(&self) -> Vec<u8> {
        // SAFETY: ptrs[0] is one of the CStrings (argv always has argv[0] here).
        unsafe { CStr::from_ptr(self.ptrs[0]) }.to_bytes().to_vec()
    }

    /// `argc`.
    pub fn argc(&self) -> usize {
        self.ptrs.len() - 1
    }

    /// `getopt()`: the option character (as an int: '?' for errors), or -1, with
    /// `optarg`. glibc prints its own messages to stderr, as for C.
    pub fn getopt(&mut self, optstring: &CStr) -> (i32, Option<Vec<u8>>) {
        let argc = self.argc() as c_int;
        // SAFETY: ptrs is a NULL-terminated array of pointers to live strings; getopt
        // permutes the array, which we own.
        let c = unsafe { libc::getopt(argc, self.ptrs.as_mut_ptr(), optstring.as_ptr()) };
        (c, Self::optarg())
    }

    /// `getopt_long()` with `long` as `(name, has_arg, val)` triples.
    pub fn getopt_long(&mut self, optstring: &CStr, long: &[(&CStr, i32, i32)]) -> (i32, Option<Vec<u8>>) {
        let mut opts: Vec<libc::option> = long
            .iter()
            .map(|(n, h, v)| libc::option { name: n.as_ptr(), has_arg: *h, flag: std::ptr::null_mut(), val: *v })
            .collect();
        opts.push(libc::option { name: std::ptr::null(), has_arg: 0, flag: std::ptr::null_mut(), val: 0 });
        let argc = self.argc() as c_int;
        // SAFETY: as for getopt; opts is a terminated array of options with static names.
        let c = unsafe {
            libc::getopt_long(argc, self.ptrs.as_mut_ptr(), optstring.as_ptr(), opts.as_ptr(), std::ptr::null_mut())
        };
        (c, Self::optarg())
    }

    fn optarg() -> Option<Vec<u8>> {
        // SAFETY: optarg is set by getopt to NULL or into one of our strings.
        unsafe {
            let p = optarg;
            if p.is_null() { None } else { Some(CStr::from_ptr(p).to_bytes().to_vec()) }
        }
    }

    /// `optind`.
    pub fn optind(&self) -> usize {
        // SAFETY: getopt's global, read between calls.
        (unsafe { optind }) as usize
    }
}

/// `getenv(name)`.
pub fn getenv(name: &[u8]) -> Option<Vec<u8>> {
    let n = cstring(name);
    // SAFETY: n is a C string; the value is copied at once.
    unsafe {
        let p = libc::getenv(n.as_ptr());
        if p.is_null() { None } else { Some(CStr::from_ptr(p).to_bytes().to_vec()) }
    }
}

/// `atoi(s)`.
pub fn atoi(s: &[u8]) -> i32 {
    let c = cstring(s);
    // SAFETY: a valid C string.
    unsafe { libc::atoi(c.as_ptr()) }
}

/// `strtoul(s, &end, base)`: the value and how many bytes it used (0 when there was
/// no number).
pub fn strtoul(s: &[u8], base: i32) -> (u64, usize) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: c is a C string; end points into it.
    let v = unsafe { libc::strtoul(c.as_ptr(), &mut end, base) };
    // SAFETY: end is within c (or at its start).
    let used = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as u64, used)
}

/// `isspace(c)` in the C locale.
pub fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// `isblank(c)` in the C locale.
pub fn isblank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `tolower(c)` in the C locale.
pub fn tolower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

/// `strcasecmp(a, b) == 0` in the C locale.
pub fn strcaseeq(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}
