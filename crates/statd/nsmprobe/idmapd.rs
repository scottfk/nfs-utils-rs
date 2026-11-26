//! The probe's rpc.idmapd commands: the kernel's side of its channels, and the
//! `rpc_pipefs` tree it watches.
//!
//! The channels are Unix `SOCK_SEQPACKET` sockets bound where the program opens them;
//! the `fakepipes` shim turns its `open()` of one into a connection (see
//! `crates/idmapd/tests/shim/fakepipes.c`). Each listener is named; its connections are
//! `NAME#1`, `NAME#2`... in the order they were accepted. Connections are accepted, and
//! answers read, only at fixed points (before and after each command), so the log
//! doesn't depend on timing.
//!
//! - `listen NAME PATH` - a listening socket at PATH (directories made as needed).
//! - `mkdir PATH`, `rm PATH` (a file, or a directory and all in it), `file PATH TEXT`
//!   (a regular file, directories made as needed; `%HH` is a byte).
//! - `await-idmapd LAUNCHED` - once the file LAUNCHED exists, until the program is up
//!   (waiting in `epoll_wait()`) or has exited.
//! - `up NAME TEXT` - send TEXT (the rest of the line; `%HH` is a byte) on NAME's
//!   latest connection.
//! - `msg NAME TYPE CONV STATUS ID NAME [TAILHEX]` - send a `struct idmap_msg`
//!   (`-` for an empty name; TAILHEX, if given, fills the bytes after the name's NUL).
//! - `raw NAME HEX` - send these bytes.
//! - `close NAME` - close NAME's latest connection.
//! - `up-close NAME TEXT` - `up`, then close the connection with the answer unread.
//! - `kill SIG` - signal the program.
//! - `idle` - just wait for the program to settle.
//! - `fds` - the program's descriptors and what they are.
//! - `stop` - `SIGTERM`, then wait for the program to exit (`SIGKILL` after five
//!   seconds).
//!
//! After each command the probe waits until the program has handled it: woken (its
//! count of voluntary context switches moved) and back in `epoll_wait()`. It logs
//! `idmapd not woken` when it never woke, `idmapd blocked in SYSCALL` when it stays
//! elsewhere, and `idmapd exited` when it's gone. Then it logs what came back: each
//! answer (`NAME#k reply TEXT`, or decoded for a 140-byte message) and each connection
//! the program closed (`NAME#k closed`).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::{Peer, hex, pump_for, unescape, unhex};

/// `sizeof(struct idmap_msg)`.
const MSG_SIZE: usize = 140;

struct Listener {
    name: String,
    fd: OwnedFd,
    conns: Vec<Option<OwnedFd>>,
}

#[derive(Default)]
pub struct IdmapdState {
    /// Set by the first command only idmapd's cases use (`listen`, `await-idmapd`):
    /// until then `raw`, `close`, `kill`, `fds` and `stop` are rpc.statd's.
    active: bool,
    listeners: Vec<Listener>,
    pid: Option<i32>,
}

fn sockaddr(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in sun.sun_path.iter_mut().zip(path.as_bytes()) {
        *d = *s as libc::c_char;
    }
    (sun, std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t)
}

fn listen(path: &str) -> Result<OwnedFd, i32> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // SAFETY: plain socket calls on a descriptor we own.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(*libc::__errno_location());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let (sun, len) = sockaddr(path);
        if libc::bind(fd.as_raw_fd(), (&sun as *const libc::sockaddr_un).cast(), len) != 0
            || libc::listen(fd.as_raw_fd(), 64) != 0
        {
            return Err(*libc::__errno_location());
        }
        Ok(fd)
    }
}

/// The calling thread's errno.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl IdmapdState {
    /// Take every waiting connection, in order, logging each.
    fn accept_all(&mut self, log: &mut Vec<String>) {
        for l in &mut self.listeners {
            loop {
                // SAFETY: accept4 on our listening socket; no address wanted.
                let c = unsafe {
                    libc::accept4(
                        l.fd.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if c < 0 {
                    break;
                }
                // SAFETY: a new descriptor we own.
                l.conns.push(Some(unsafe { OwnedFd::from_raw_fd(c) }));
                log.push(format!("{}#{} opened", l.name, l.conns.len()));
            }
        }
    }

    /// Read every answer waiting on every connection; log closed ones.
    fn drain(&mut self, log: &mut Vec<String>) {
        for l in &mut self.listeners {
            for (i, c) in l.conns.iter_mut().enumerate() {
                let Some(fd) = c.as_ref() else { continue };
                loop {
                    let mut buf = vec![0u8; 65536];
                    // SAFETY: buf is valid for its length.
                    let n =
                        unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
                    if n == 0 {
                        log.push(format!("{}#{} closed", l.name, i + 1));
                        *c = None;
                        break;
                    }
                    if n < 0 {
                        if errno() != libc::EAGAIN {
                            log.push(format!("{}#{} error {}", l.name, i + 1, errno()));
                            *c = None;
                        }
                        break;
                    }
                    log.push(format!("{}#{} reply {}", l.name, i + 1, show(&buf[..n as usize])));
                }
            }
        }
    }

    fn latest(&self, name: &str) -> Option<(usize, &OwnedFd)> {
        let l = self.listeners.iter().find(|l| l.name == name)?;
        l.conns.iter().enumerate().rev().find_map(|(i, c)| c.as_ref().map(|fd| (i + 1, fd)))
    }

    fn send(&mut self, name: &str, data: &[u8], log: &mut Vec<String>) {
        match self.latest(name) {
            None => log.push(format!("{name} no connection")),
            Some((k, fd)) => {
                // SAFETY: data is valid for its length.
                let n = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        data.as_ptr().cast(),
                        data.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if n != data.len() as isize {
                    log.push(format!("{name}#{k} send failed {}", errno()));
                }
            }
        }
    }
}

/// An answer for the log: a 140-byte one decoded as a `struct idmap_msg`, others as
/// text with unprintable bytes as `%HH`.
fn show(b: &[u8]) -> String {
    if b.len() != MSG_SIZE {
        return text(b);
    }
    let name_end = b[2..130].iter().position(|&x| x == 0).map_or(130, |p| p + 2);
    let id = u32::from_ne_bytes(b[132..136].try_into().unwrap());
    // What follows the name's NUL, and the padding: shown when not all zero.
    let mut extra = b[(name_end + 1).min(132)..132].to_vec();
    extra.extend_from_slice(&b[137..]);
    let note = if extra.iter().any(|&x| x != 0) { format!(" rest {}", hex(&extra)) } else { String::new() };
    format!("msg type={} conv={} name={} id={id} status={}{note}", b[0], b[1], text(&b[2..name_end]), b[136])
}

fn text(b: &[u8]) -> String {
    b.iter()
        .map(|&c| if (0x21..0x7f).contains(&c) && c != b'%' { (c as char).to_string() } else { format!("%{c:02x}") })
        .collect()
}

/// (state, syscall number or "running", voluntary context switches) of `pid`; `None`
/// when it's gone or a zombie.
fn proc_state(pid: i32) -> Option<(String, u64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let state = status.lines().find_map(|l| l.strip_prefix("State:"))?.trim().to_string();
    if state.starts_with('Z') || state.starts_with('X') {
        return None;
    }
    let ctxt = status
        .lines()
        .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let sc = std::fs::read_to_string(format!("/proc/{pid}/syscall")).unwrap_or_default();
    Some((sc.split_whitespace().next().unwrap_or("").to_string(), ctxt))
}

fn in_epoll_wait(nr: &str) -> bool {
    nr == libc::SYS_epoll_wait.to_string() || nr == libc::SYS_epoll_pwait.to_string()
}

fn syscall_name(nr: &str) -> String {
    match nr.parse::<i64>() {
        Ok(libc::SYS_read) => "read".into(),
        Ok(libc::SYS_write) => "write".into(),
        Ok(libc::SYS_sendto) => "sendto".into(),
        Ok(n) => format!("syscall {n}"),
        Err(_) => nr.to_string(),
    }
}

/// Live processes named rpc.idmapd, lowest pid first.
fn idmapd_pids() -> Vec<i32> {
    let mut pids: Vec<i32> = std::fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .filter(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).is_ok_and(|c| c.trim() == "rpc.idmapd"))
                .filter(|&p| proc_state(p).is_some())
                .collect()
        })
        .unwrap_or_default();
    pids.sort();
    pids
}

enum Settled {
    Woke,
    NotWoken,
    Blocked(String),
    Exited,
}

/// Wait until `pid` has handled what was just done: woken since it had `before`
/// voluntary switches, and back in `epoll_wait()` for a few looks in a row.
fn settle(pid: i32, before: u64, peers: &mut [Peer], log: &mut Vec<String>) -> Settled {
    let start = Instant::now();
    let mut stable = 0;
    let mut last = before;
    loop {
        let Some((nr, ctxt)) = proc_state(pid) else { return Settled::Exited };
        let idle = in_epoll_wait(&nr);
        if idle && ctxt > before {
            stable = if ctxt == last { stable + 1 } else { 0 };
            if stable >= 3 {
                return Settled::Woke;
            }
        } else {
            stable = 0;
        }
        last = ctxt;
        let waited = start.elapsed();
        if idle && ctxt == before && waited > Duration::from_millis(400) {
            return Settled::NotWoken;
        }
        if waited > Duration::from_secs(4) {
            return Settled::Blocked(syscall_name(&nr));
        }
        pump_for(peers, log, 2);
    }
}

fn kill(pid: i32, sig: &str) {
    let n = match sig {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "KILL" => libc::SIGKILL,
        n => n.parse().unwrap(),
    };
    // SAFETY: signaling a process.
    unsafe { libc::kill(pid, n) };
}

/// The program's descriptors: `N TARGET` each, sockets and pipes without inodes.
fn fds(pid: i32) -> String {
    let mut v: Vec<(i32, String)> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| {
            d.filter_map(|e| {
                let e = e.ok()?;
                let n: i32 = e.file_name().to_str()?.parse().ok()?;
                let t = std::fs::read_link(e.path()).ok()?.to_string_lossy().to_string();
                let t = if t.starts_with("socket:") {
                    "socket".to_string()
                } else if t.starts_with("pipe:") {
                    "pipe".to_string()
                } else {
                    t
                };
                Some((n, t))
            })
            .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.iter().map(|(n, t)| format!("{n} {t}")).collect::<Vec<_>>().join(", ")
}

/// Run an idmapd command; false if `cmd` isn't one.
pub fn cmd(cmd: &str, f: &[&str], line: &str, peers: &mut [Peer], log: &mut Vec<String>, st: &mut IdmapdState) -> bool {
    // The rest of the line after the first `n` words.
    let rest = |n: usize| -> String { line.splitn(n + 1, ' ').nth(n).unwrap_or("").to_string() };
    match cmd {
        "listen" | "await-idmapd" => st.active = true,
        "mkdir" | "rm" | "file" | "up" | "up-close" | "msg" => {}
        _ if !st.active => return false,
        _ => {}
    }
    let mut stimulus = true;
    let before = st.pid.and_then(proc_state).map(|s| s.1);
    st.accept_all(log);
    match cmd {
        "listen" => {
            // A new socket in a watched directory wakes the program.
            stimulus = st.pid.is_some();
            match listen(f[2]) {
                Ok(fd) => st.listeners.push(Listener { name: f[1].to_string(), fd, conns: Vec::new() }),
                Err(e) => log.push(format!("{} listen failed {e}", f[1])),
            }
        }
        "mkdir" => {
            if let Err(e) = std::fs::create_dir(f[1]) {
                log.push(format!("mkdir {} failed {}", f[1], e.raw_os_error().unwrap_or(0)));
            }
        }
        "rm" => {
            let p = std::path::Path::new(f[1]);
            let r = if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
            if let Err(e) = r {
                log.push(format!("rm {} failed {}", f[1], e.raw_os_error().unwrap_or(0)));
            }
        }
        "file" => {
            if let Some(dir) = std::path::Path::new(f[1]).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(f[1], unescape(&rest(2))) {
                log.push(format!("file {} failed {}", f[1], e.raw_os_error().unwrap_or(0)));
            }
        }
        "await-idmapd" => {
            stimulus = false;
            let launched = std::path::Path::new(f[1]);
            let end = Instant::now() + Duration::from_secs(20);
            while !launched.exists() && Instant::now() < end {
                pump_for(peers, log, 2);
            }
            let launcher: i32 = std::fs::read_to_string(launched).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let mut stable = 0;
            loop {
                let pids = idmapd_pids();
                if pids.is_empty() && proc_state(launcher).is_none() {
                    log.push("idmapd exited".into());
                    break;
                }
                // The daemon: the one waiting in epoll_wait().
                let idle = pids.iter().copied().find(|&p| proc_state(p).is_some_and(|(nr, _)| in_epoll_wait(&nr)));
                match idle {
                    Some(p) if st.pid == Some(p) => {
                        stable += 1;
                        if stable >= 3 {
                            log.push("idmapd up".into());
                            break;
                        }
                    }
                    other => {
                        st.pid = other;
                        stable = 0;
                    }
                }
                if Instant::now() > end {
                    log.push("idmapd not up".into());
                    st.pid = None;
                    break;
                }
                pump_for(peers, log, 2);
            }
        }
        "up" => {
            let data = unescape(&rest(2));
            st.send(f[1], &data, log);
        }
        "msg" => {
            let mut m = vec![0u8; MSG_SIZE];
            m[0] = f[2].parse().unwrap();
            m[1] = f[3].parse().unwrap();
            m[136] = f[4].parse().unwrap();
            m[132..136].copy_from_slice(&f[5].parse::<u32>().unwrap().to_ne_bytes());
            let name = if f[6] == "-" { Vec::new() } else { unescape(f[6]) };
            m[2..2 + name.len()].copy_from_slice(&name);
            if let Some(t) = f.get(7) {
                let t = unhex(t);
                let at = 2 + name.len() + 1;
                m[at..at + t.len()].copy_from_slice(&t);
            }
            st.send(f[1], &m, log);
        }
        "up-close" => {
            // Close with the answer unread: the program's side then reads ECONNRESET.
            let data = unescape(&rest(2));
            st.send(f[1], &data, log);
            if let (Some(pid), Some(b)) = (st.pid, before) {
                settle(pid, b, peers, log);
            }
            let before = st.pid.and_then(proc_state).map(|s| s.1);
            if let Some(c) = st
                .listeners
                .iter_mut()
                .find(|l| l.name == f[1])
                .and_then(|l| l.conns.iter_mut().rev().find(|c| c.is_some()))
            {
                *c = None;
            }
            if let (Some(pid), Some(b)) = (st.pid, before) {
                match settle(pid, b, peers, log) {
                    Settled::Woke => {}
                    Settled::NotWoken => log.push("idmapd not woken".into()),
                    Settled::Blocked(s) => log.push(format!("idmapd blocked in {s}")),
                    Settled::Exited => {
                        log.push("idmapd exited".into());
                        st.pid = None;
                    }
                }
            }
            stimulus = false;
        }
        "raw" => {
            let data = unhex(f[2]);
            st.send(f[1], &data, log);
        }
        "close" => {
            let l = st.listeners.iter_mut().find(|l| l.name == f[1]);
            match l.and_then(|l| l.conns.iter_mut().rev().find(|c| c.is_some())) {
                Some(c) => *c = None,
                None => log.push(format!("{} no connection", f[1])),
            }
        }
        "kill" => match st.pid {
            Some(p) => kill(p, f[1]),
            None => stimulus = false,
        },
        "idle" => {}
        "fds" => {
            stimulus = false;
            if let Some(p) = st.pid {
                log.push(format!("fds {}", fds(p)));
            }
        }
        "stop" => {
            stimulus = false;
            if let Some(p) = st.pid {
                kill(p, "TERM");
                let end = Instant::now() + Duration::from_secs(5);
                while proc_state(p).is_some() && Instant::now() < end {
                    pump_for(peers, log, 2);
                }
                if proc_state(p).is_some() {
                    log.push("idmapd still running".into());
                    kill(p, "KILL");
                } else {
                    log.push("idmapd exited".into());
                }
                st.pid = None;
            }
        }
        _ => return false,
    }
    if stimulus && let (Some(pid), Some(before)) = (st.pid, before) {
        match settle(pid, before, peers, log) {
            Settled::Woke => {}
            Settled::NotWoken => log.push("idmapd not woken".into()),
            Settled::Blocked(s) => log.push(format!("idmapd blocked in {s}")),
            Settled::Exited => {
                log.push("idmapd exited".into());
                st.pid = None;
            }
        }
    }
    st.accept_all(log);
    st.drain(log);
    true
}
