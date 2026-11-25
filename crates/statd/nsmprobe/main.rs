//! nsmprobe: fake NSM peers for the differential tests. Reads a script from stdin:
//!
//! - `peer NAME ADDR PORT ACTIONS` - a UDP socket at ADDR:PORT. Each datagram it gets is
//!   logged, then answered by the next of the comma-separated ACTIONS (the last one
//!   repeats):
//!   - `drop` - no answer;
//!   - `void` - an accepted, successful reply with no results;
//!   - `port:N` - success with the 32-bit number N (a `PMAPPROC_GETPORT` answer);
//!   - `uaddr:STR` - success with the XDR string STR (an `RPCBPROC_GETADDR` answer);
//!   - `accept:N` - accepted with status N;
//!   - `denied` - denied, RPC version mismatch (2-2);
//!   - `hex:HEX` - these bytes, with `XID` standing for the call's xid.
//! - `ready FIFO` - write "ready" to FIFO (the test script waits on it).
//! - `serve STOPFILE` - answer until STOPFILE exists, then print the log: one
//!   `NAME got HEX from ADDR PORT` line per datagram, in arrival order (a port from
//!   the dynamic range, 32768 and up, as `eph`).
//!
//! For rpc.statd, with a real rpcbind in the sandbox (peers keep being answered while
//! these wait):
//!
//! - `await-rpcbind` - until rpcbind answers a NULL call on 127.0.0.1:111.
//! - `register PROG VERS PROT PORT` - `PMAPPROC_SET` from a reserved port (for a fake
//!   lockd, or a fake statd).
//! - `await-statd LAUNCHED` - until rpcbind knows statd (UDP) and statd answers a NULL
//!   call there; gives up when the file LAUNCHED exists and statd isn't registered (the
//!   calls after it are then skipped).
//! - `call NAME udp|tcp SRC SPORT PROC HEX` - an SM call (AUTH_NONE) from SRC:SPORT
//!   (0: any port) with HEX as the arguments, to statd's port on 127.0.0.1 (on ::1 for
//!   an IPv6 SRC); logs `NAME reply HEX`, or `NAME no reply`.
//! - `raw NAME udp|tcp SRC SPORT HEX` - the same with HEX as the whole message
//!   (`XID` stands for the xid).
//! - `wait PEER N` - until PEER has had N datagrams.
//! - `pause MS` - just answer peers for MS milliseconds.
//! - `kill SIG` - signal the pid in /run/rpc.statd.pid, once it's waiting in `select()`.
//! - `gone` - until that process is gone (or a zombie).
//! - `dump` - rpcbind's table (`RPCBPROC_DUMP`, version 3), ports from the dynamic
//!   range shown as `eph`.
//! - `expect FILE TEXT...` - until FILE contains TEXT (the words joined by blanks; `\n`
//!   is a newline).
//! - `expect-n FILE N TEXT...` - until FILE contains TEXT N times.
//! - `finish FIFO` - write "done" to FIFO.
//!
//! Single-threaded on purpose: the sandbox's pids must come out the same in every run.
//! Each round takes every waiting datagram from every peer, then logs and answers them
//! in the order the kernel received them (`SO_TIMESTAMPNS`), so the program under test
//! sees its replies in the same order however the rounds fall.

use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// A datagram as taken in a round: (arrival time, peer index, message, sender).
type Arrival = ((i64, i64), usize, Vec<u8>, SocketAddr);

struct Peer {
    name: String,
    sock: UdpSocket,
    actions: Vec<String>,
    count: usize,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// The answer to a call with `xid`, or `None`.
fn answer(action: &str, xid: u32) -> Option<Vec<u8>> {
    let ok = words(&[xid, 1, 0, 0, 0, 0]);
    let (kind, arg) = action.split_once(':').unwrap_or((action, ""));
    match kind {
        "drop" => None,
        "void" => Some(ok),
        "port" => {
            let mut v = ok;
            v.extend(words(&[arg.parse().unwrap()]));
            Some(v)
        }
        "uaddr" => {
            let mut v = ok;
            v.extend(words(&[arg.len() as u32]));
            v.extend(arg.as_bytes());
            while !v.len().is_multiple_of(4) {
                v.push(0);
            }
            Some(v)
        }
        "accept" => Some(words(&[xid, 1, 0, 0, 0, arg.parse().unwrap()])),
        "denied" => Some(words(&[xid, 1, 1, 0, 2, 2])),
        "hex" => Some(unhex(&arg.replace("XID", &format!("{xid:08x}")))),
        _ => panic!("unknown action {action}"),
    }
}

/// Stamp every datagram as it arrives (`SO_TIMESTAMPNS`), for [`recv_stamped`].
fn enable_timestamps(sock: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let one: libc::c_int = 1;
    // SAFETY: an int option.
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            (&one as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "SO_TIMESTAMPNS");
}

/// `recvfrom()` with the kernel's arrival time (`SCM_TIMESTAMPNS`): the message, the
/// sender and the time, or `None` when nothing is waiting.
fn recv_stamped(sock: &UdpSocket, buf: &mut [u8]) -> Option<(usize, SocketAddr, (i64, i64))> {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero sockaddr_storage and msghdr are valid; the buffers outlive the
    // call; the control messages are walked with the CMSG macros over our own buffer.
    unsafe {
        let mut from: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut ctl = [0u64; 32];
        let mut mh: libc::msghdr = std::mem::zeroed();
        mh.msg_name = (&mut from as *mut libc::sockaddr_storage).cast();
        mh.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        mh.msg_iov = &mut iov;
        mh.msg_iovlen = 1;
        mh.msg_control = ctl.as_mut_ptr().cast();
        mh.msg_controllen = size_of_val(&ctl);
        let n = libc::recvmsg(sock.as_raw_fd(), &mut mh, libc::MSG_DONTWAIT);
        if n < 0 {
            return None;
        }
        let mut stamp = None;
        let mut c = libc::CMSG_FIRSTHDR(&mh);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_TIMESTAMPNS {
                let ts = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::timespec>());
                stamp = Some((ts.tv_sec, ts.tv_nsec));
            }
            c = libc::CMSG_NXTHDR(&mh, c);
        }
        let addr = match i32::from(from.ss_family) {
            libc::AF_INET => {
                let a = &*(&from as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                SocketAddr::new(
                    std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into(),
                    u16::from_be(a.sin_port),
                )
            }
            _ => {
                let a = &*(&from as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                SocketAddr::new(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr).into(), u16::from_be(a.sin6_port))
            }
        };
        Some((n as usize, addr, stamp.expect("no SCM_TIMESTAMPNS")))
    }
}

/// One round: take every waiting datagram from every peer, then log and answer them in
/// arrival order. False if there were none.
fn pump(peers: &mut [Peer], log: &mut Vec<String>) -> bool {
    let mut buf = [0u8; 65536];
    let mut got: Vec<Arrival> = Vec::new();
    for (i, p) in peers.iter().enumerate() {
        while let Some((n, from, at)) = recv_stamped(&p.sock, &mut buf) {
            got.push((at, i, buf[..n].to_vec(), from));
        }
    }
    if got.is_empty() {
        return false;
    }
    got.sort_by_key(|g| g.0);
    for (_, i, msg, from) in got {
        let p = &mut peers[i];
        // An ephemeral source port is the kernel's random pick.
        let port = if from.port() >= 32768 { "eph".to_string() } else { from.port().to_string() };
        log.push(format!("{} got {} from {} {port}", p.name, hex(&msg), from.ip()));
        let xid = if msg.len() >= 4 { u32::from_be_bytes(msg[..4].try_into().unwrap()) } else { 0 };
        let a = &p.actions[p.count.min(p.actions.len() - 1)];
        p.count += 1;
        if let Some(r) = answer(a, xid) {
            let _ = p.sock.send_to(&r, from);
        }
    }
    true
}

/// Answer peers for `ms` milliseconds.
fn pump_for(peers: &mut [Peer], log: &mut Vec<String>, ms: u64) {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end {
        if !pump(peers, log) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// The statd commands' state.
#[derive(Default)]
struct StatdState {
    /// statd's UDP port, once it's up; `None` before, `Some(0)` if it never came up.
    port: Option<u16>,
    xid: u32,
    pid: Option<i32>,
}

/// A call message: xid, CALL, RPC version 2, prog/vers/proc, AUTH_NONE twice, args.
fn call_msg(xid: u32, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> Vec<u8> {
    let mut m = words(&[xid, 0, 2, prog, vers, proc_, 0, 0, 0, 0]);
    m.extend_from_slice(args);
    m
}

/// Send `msg` over UDP to 127.0.0.1:`port` from `src`, and wait up to `ms` for the
/// reply (answering peers meanwhile).
fn udp_call(
    peers: &mut [Peer],
    log: &mut Vec<String>,
    src: SocketAddr,
    port: u16,
    msg: &[u8],
    ms: u64,
) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(src).ok()?;
    sock.set_nonblocking(true).unwrap();
    let dst: SocketAddr = if src.is_ipv6() {
        SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port)
    } else {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port)
    };
    sock.send_to(msg, dst).ok()?;
    let end = Instant::now() + Duration::from_millis(ms);
    let mut buf = [0u8; 65536];
    while Instant::now() < end {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            return Some(buf[..n].to_vec());
        }
        if !pump(peers, log) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    None
}

/// The same over TCP, with record marking (`src` is bound before connecting).
fn tcp_call(
    peers: &mut [Peer],
    log: &mut Vec<String>,
    src: SocketAddr,
    port: u16,
    msg: &[u8],
    ms: u64,
) -> Option<Vec<u8>> {
    use std::os::fd::FromRawFd;
    // SAFETY: a new socket, owned by the TcpStream below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let one: libc::c_int = 1;
    let SocketAddr::V4(s4) = src else { return None };
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: s4.port().to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from(*s4.ip()).to_be() },
        sin_zero: [0; 8],
    };
    let dst = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be() },
        sin_zero: [0; 8],
    };
    let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: plain socket calls with stack structures.
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&one as *const libc::c_int).cast(), 4);
        if libc::bind(fd, (&sin as *const libc::sockaddr_in).cast(), len) != 0
            || libc::connect(fd, (&dst as *const libc::sockaddr_in).cast(), len) != 0
        {
            libc::close(fd);
            return None;
        }
    }
    // SAFETY: fd is a connected socket we own.
    let mut t = unsafe { TcpStream::from_raw_fd(fd) };
    let mut rec = (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
    rec.extend_from_slice(msg);
    t.write_all(&rec).ok()?;
    t.set_nonblocking(true).unwrap();
    let end = Instant::now() + Duration::from_millis(ms);
    let mut got: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    while Instant::now() < end {
        match t.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => {
                if !pump(peers, log) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if got.len() >= 4 {
            let h = u32::from_be_bytes(got[..4].try_into().unwrap());
            let l = (h & 0x7fff_ffff) as usize;
            if got.len() >= 4 + l {
                return Some(got[4..4 + l].to_vec());
            }
        }
    }
    None
}

/// A portmap/rpcbind call to 127.0.0.1:111 from `src`; the reply's results (after the
/// 24-byte header), or `None`.
fn rpcb_call(
    peers: &mut [Peer],
    log: &mut Vec<String>,
    src: SocketAddr,
    vers: u32,
    proc_: u32,
    args: &[u8],
) -> Option<Vec<u8>> {
    let r = udp_call(peers, log, src, 111, &call_msg(0x5eed_0001, 100000, vers, proc_, args), 500)?;
    (r.len() >= 24 && r[8..12] == [0, 0, 0, 0] && r[20..24] == [0, 0, 0, 0]).then(|| r[24..].to_vec())
}

fn any_v4() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// An XDR string at `b[*off..]`.
fn xdr_str(b: &[u8], off: &mut usize) -> String {
    let n = u32::from_be_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
    let s = String::from_utf8_lossy(&b[*off + 4..*off + 4 + n]).to_string();
    *off += 4 + n.div_ceil(4) * 4;
    s
}

/// A universal address with a port from the dynamic range shown as `eph`.
fn norm_uaddr(u: &str) -> String {
    let parts: Vec<&str> = u.rsplitn(3, '.').collect();
    if parts.len() == 3
        && let (Ok(lo), Ok(hi)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
        && hi * 256 + lo >= 32768
    {
        return format!("{}.eph", parts[2]);
    }
    u.to_string()
}

/// Wait (a while, at most) until `pid` is blocked in `select()`/`pselect6()`, so a signal
/// finds it between requests rather than in the middle of a message.
fn wait_idle(peers: &mut [Peer], log: &mut Vec<String>, pid: i32) {
    let end = Instant::now() + Duration::from_secs(5);
    let mut idle = 0;
    while Instant::now() < end && idle < 3 {
        let sc = std::fs::read_to_string(format!("/proc/{pid}/syscall")).unwrap_or_default();
        let nr = sc.split_whitespace().next().unwrap_or("");
        if nr == libc::SYS_select.to_string() || nr == libc::SYS_pselect6.to_string() {
            idle += 1;
        } else {
            idle = 0;
        }
        pump_for(peers, log, 2);
    }
}

/// statd's pid: from its pid file, or (when that was emptied) the lowest pid named
/// `rpc.statd`.
fn statd_pid() -> Option<i32> {
    if let Some(p) = std::fs::read_to_string("/run/rpc.statd.pid").ok().and_then(|s| s.trim().parse().ok()) {
        return Some(p);
    }
    let mut pids: Vec<i32> = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).is_ok_and(|c| c.trim() == "rpc.statd"))
        .collect();
    pids.sort();
    pids.first().copied()
}

/// Run a statd command; false if `cmd` isn't one.
fn statd_cmd(cmd: &str, f: &[&str], peers: &mut [Peer], log: &mut Vec<String>, st: &mut StatdState) -> bool {
    match cmd {
        "await-rpcbind" => {
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                if rpcb_call(peers, log, any_v4(), 2, 0, &[]).is_some() {
                    break;
                }
                if Instant::now() > end {
                    log.push("rpcbind not up".into());
                    break;
                }
            }
        }
        "register" => {
            let n: Vec<u32> = f[1..5].iter().map(|x| x.parse().unwrap()).collect();
            let mut r = None;
            for sport in (600..1000).rev() {
                let src: SocketAddr = format!("127.0.0.1:{sport}").parse().unwrap();
                if UdpSocket::bind(src).is_ok() {
                    r = rpcb_call(peers, log, src, 2, 1, &words(&n));
                    break;
                }
            }
            let ok = r.is_some_and(|b| b.len() >= 4 && b[3] == 1);
            log.push(format!("register {} {} {} {} {ok}", n[0], n[1], n[2], n[3]));
        }
        "await-statd" => {
            let launched = std::path::Path::new(f[1]);
            loop {
                let port = rpcb_call(peers, log, any_v4(), 2, 3, &words(&[100024, 1, 17, 0]))
                    .filter(|b| b.len() >= 4)
                    .map_or(0, |b| u32::from_be_bytes(b[..4].try_into().unwrap()) as u16);
                // A port of one of our own peers is a fake registration, not statd.
                let ours = peers.iter().any(|p| p.sock.local_addr().is_ok_and(|a| a.port() == port));
                if port != 0 && !ours {
                    let ping = call_msg(0x5eed_0002, 100024, 1, 0, &[]);
                    if udp_call(peers, log, any_v4(), port, &ping, 200).is_some() {
                        st.port = Some(port);
                        log.push("statd up".into());
                        break;
                    }
                    continue;
                }
                if launched.exists() {
                    st.port = Some(0);
                    log.push("statd not up".into());
                    break;
                }
                pump_for(peers, log, 2);
            }
        }
        "call" | "raw" => {
            let port = st.port.unwrap_or(0);
            if port == 0 {
                return true;
            }
            let ip: std::net::IpAddr = f[3].parse().unwrap();
            let src = SocketAddr::new(ip, f[4].parse().unwrap());
            st.xid += 1;
            let xid = 0x0c00_0000 + st.xid;
            let msg = if cmd == "call" {
                call_msg(xid, 100024, 1, f[5].parse().unwrap(), &unhex(f.get(6).copied().unwrap_or("")))
            } else {
                unhex(&f[5].replace("XID", &format!("{xid:08x}")))
            };
            let r = if f[2] == "tcp" {
                tcp_call(peers, log, src, port, &msg, 5000)
            } else {
                udp_call(peers, log, src, port, &msg, 5000)
            };
            match r {
                Some(b) => log.push(format!("{} reply {}", f[1], hex(&b))),
                None => log.push(format!("{} no reply", f[1])),
            }
        }
        "wait" => {
            let n: usize = f[2].parse().unwrap();
            let end = Instant::now() + Duration::from_secs(20);
            while peers.iter().find(|p| p.name == f[1]).is_some_and(|p| p.count < n) {
                if Instant::now() > end {
                    log.push(format!("wait {} {n} timed out", f[1]));
                    break;
                }
                if !pump(peers, log) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        "pause" => pump_for(peers, log, f[1].parse().unwrap()),
        "kill" => {
            let sig = match f[1] {
                "TERM" => libc::SIGTERM,
                "HUP" => libc::SIGHUP,
                "INT" => libc::SIGINT,
                "USR1" => libc::SIGUSR1,
                "USR2" => libc::SIGUSR2,
                s => panic!("signal {s}"),
            };
            if st.port.unwrap_or(0) == 0 {
                return true;
            }
            st.pid = statd_pid().or(st.pid);
            if let Some(pid) = st.pid {
                wait_idle(peers, log, pid);
                // SAFETY: signaling a process in the sandbox.
                unsafe { libc::kill(pid, sig) };
                log.push(format!("kill {}", f[1]));
            }
        }
        "gone" => {
            let Some(pid) = st.pid else { return true };
            let end = Instant::now() + Duration::from_secs(20);
            loop {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                let zombie = stat.rsplit_once(") ").is_some_and(|(_, r)| r.starts_with('Z') || r.starts_with('X'));
                if stat.is_empty() || zombie {
                    break;
                }
                if Instant::now() > end {
                    log.push("statd still running".into());
                    break;
                }
                pump_for(peers, log, 2);
            }
        }
        "dump" => match rpcb_call(peers, log, any_v4(), 3, 4, &[]) {
            None => log.push("dump failed".into()),
            Some(b) => {
                let mut off = 0;
                while off + 4 <= b.len() && b[off + 3] == 1 {
                    off += 4;
                    let prog = u32::from_be_bytes(b[off..off + 4].try_into().unwrap());
                    let vers = u32::from_be_bytes(b[off + 4..off + 8].try_into().unwrap());
                    off += 8;
                    let netid = xdr_str(&b, &mut off);
                    let addr = xdr_str(&b, &mut off);
                    let owner = xdr_str(&b, &mut off);
                    if prog != 100000 {
                        log.push(format!("rpcb {prog} {vers} {netid} {} {owner}", norm_uaddr(&addr)));
                    }
                }
            }
        },
        "expect" | "expect-n" => {
            let (n, text) =
                if cmd == "expect" { (1, f[2..].join(" ")) } else { (f[2].parse().unwrap(), f[3..].join(" ")) };
            let text = text.replace("\\n", "\n");
            let end = Instant::now() + Duration::from_secs(20);
            loop {
                if std::fs::read_to_string(f[1]).unwrap_or_default().matches(&text).count() >= n {
                    break;
                }
                if Instant::now() > end {
                    log.push(format!("expect timed out: {text}"));
                    break;
                }
                pump_for(peers, log, 2);
            }
        }
        "finish" => {
            // Keep answering peers until the script opens the FIFO.
            loop {
                if write_fifo(f[1]) {
                    break;
                }
                pump_for(peers, log, 2);
            }
        }
        _ => return false,
    }
    true
}

/// Write "done" to the FIFO if a reader has it open.
fn write_fifo(path: &str) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Ok(mut f) => {
            let _ = f.write_all(b"done\n");
            true
        }
        Err(_) => false,
    }
}

fn main() {
    // The whole script first: if the probe fails, it still releases the test script
    // waiting on the finish FIFO (instead of leaving it to the sandbox timeout).
    let script: Vec<String> = std::io::stdin().lock().lines().map(|l| l.unwrap()).collect();
    if let Some(fifo) = script.iter().find_map(|l| l.strip_prefix("finish ").map(str::to_string)) {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            prev(info);
            let end = Instant::now() + Duration::from_secs(10);
            while !write_fifo(&fifo) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }
    let mut peers: Vec<Peer> = Vec::new();
    let mut log: Vec<String> = Vec::new();
    let mut st = StatdState::default();
    let mut printed = 0;
    for line in script {
        // Each command's log lines as soon as it's done, so a hang shows where.
        {
            let out = std::io::stdout();
            let mut out = out.lock();
            for l in &log[printed..] {
                writeln!(out, "{l}").unwrap();
            }
            out.flush().unwrap();
            printed = log.len();
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first().copied() {
            None => {}
            Some("peer") => {
                let addr: std::net::IpAddr = f[2].parse().unwrap();
                let port: u16 = f[3].parse().unwrap();
                match UdpSocket::bind(SocketAddr::new(addr, port)) {
                    Ok(s) => {
                        s.set_nonblocking(true).unwrap();
                        enable_timestamps(&s);
                        peers.push(Peer {
                            name: f[1].to_string(),
                            sock: s,
                            actions: f[4].split(',').map(String::from).collect(),
                            count: 0,
                        });
                    }
                    Err(e) => log.push(format!("{} bind-failed {}", f[1], e.raw_os_error().unwrap_or(0))),
                }
            }
            Some("ready") => {
                let mut fifo = std::fs::OpenOptions::new().write(true).open(f[1]).unwrap();
                fifo.write_all(b"ready\n").unwrap();
            }
            Some("serve") => {
                let stop = std::path::Path::new(f[1]);
                loop {
                    if !pump(&mut peers, &mut log) {
                        if stop.exists() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            Some(cmd) if statd_cmd(cmd, &f, &mut peers, &mut log, &mut st) => {}
            Some(other) => panic!("unknown command {other}"),
        }
    }
    let out = std::io::stdout();
    let mut out = out.lock();
    for l in &log[printed..] {
        writeln!(out, "{l}").unwrap();
    }
    writeln!(out, "probe done").unwrap();
}
