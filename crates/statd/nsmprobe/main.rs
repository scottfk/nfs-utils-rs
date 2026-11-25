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
//!   `NAME got HEX from ADDR PORT` line per datagram, in arrival order.
//!
//! Single-threaded on purpose: the sandbox's pids must come out the same in every run.
//! Each round takes every waiting datagram from every peer, then logs and answers them
//! in the order the kernel received them (`SO_TIMESTAMPNS`), so the program under test
//! sees its replies in the same order however the rounds fall.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

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

fn main() {
    let mut peers: Vec<Peer> = Vec::new();
    let mut log: Vec<String> = Vec::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
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
                let mut buf = [0u8; 65536];
                loop {
                    // (arrival time, peer, message, sender)
                    let mut got: Vec<Arrival> = Vec::new();
                    for (i, p) in peers.iter().enumerate() {
                        while let Some((n, from, at)) = recv_stamped(&p.sock, &mut buf) {
                            got.push((at, i, buf[..n].to_vec(), from));
                        }
                    }
                    if got.is_empty() {
                        if stop.exists() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    got.sort_by_key(|g| g.0);
                    for (_, i, msg, from) in got {
                        let p = &mut peers[i];
                        log.push(format!("{} got {} from {} {}", p.name, hex(&msg), from.ip(), from.port()));
                        let xid = if msg.len() >= 4 { u32::from_be_bytes(msg[..4].try_into().unwrap()) } else { 0 };
                        let a = &p.actions[p.count.min(p.actions.len() - 1)];
                        p.count += 1;
                        if let Some(r) = answer(a, xid) {
                            let _ = p.sock.send_to(&r, from);
                        }
                    }
                }
            }
            Some(other) => panic!("unknown command {other}"),
        }
    }
    let out = std::io::stdout();
    let mut out = out.lock();
    for l in log {
        writeln!(out, "{l}").unwrap();
    }
    writeln!(out, "probe done").unwrap();
}
