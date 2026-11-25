//! `support/nsm/rpc.c`: NSM builds its RPC calls straight into datagram buffers (one
//! socket serves every program it calls), and parses the replies itself.

use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use tirpc::xdr::{self, XdrDecode, XdrEncode, XdrMem};

use crate::nsm_file::{Mon, SM_MAXSTRLEN};
use crate::sockaddr::{family, nfs_sockaddr2universal, nfs_universal2port};
use crate::sys;
use crate::xlog::{D_CALL, L_ERROR, m, xlog};

/// `NSM_MAXMSGSIZE`.
pub const NSM_MAXMSGSIZE: usize = 2048;
pub const SM_PROG: u32 = 100024;
pub const SM_VERS: u32 = 1;
pub const SM_NOTIFY: u32 = 6;
const PMAPPROG: u32 = 100000;
const PMAPVERS: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const PMAPPORT: u16 = 111;
const RPCBPROG: u32 = 100000;
const RPCBVERS: u32 = 3;
const RPCBPROC_GETADDR: u32 = 3;

static NSM_XID: AtomicU32 = AtomicU32::new(0);

/// `nsm_next_xid()`: never zero (until it wraps), seeded from the pid and the clock.
fn nsm_next_xid() -> u32 {
    if NSM_XID.load(Relaxed) == 0 {
        let (s, us) = sys::gettimeofday();
        NSM_XID.store((sys::getpid() as u32) ^ (s as u32) ^ (us as u32), Relaxed);
    }
    NSM_XID.fetch_add(1, Relaxed)
}

/// `nsm_init_rpc_header()` + `xdr_callmsg()`: the call header with `AUTH_NULL`
/// credential and verifier. Returns the xid.
fn put_call_header(x: &mut XdrMem<'_>, prog: u32, vers: u32, proc_: u32) -> (u32, bool) {
    let xid = nsm_next_xid();
    let ok = [xid, 0, 2, prog, vers, proc_, 0, 0, 0, 0].iter().all(|&w| x.put_long(w));
    (xid, ok)
}

/// `nsm_rpc_sendto()`.
fn nsm_rpc_sendto(sock: sys::Fd, sa: &[u8], buf: &[u8]) -> bool {
    let n = sys::sendto(sock, buf, sa);
    if n < 0 || n as usize != buf.len() {
        xlog(L_ERROR, &bfmt!("nsm_rpc_sendto: sendto failed: {}", m()));
        return false;
    }
    true
}

/// Encode a call into a fresh `NSM_MAXMSGSIZE` buffer with `args`, and send it to `sa`.
/// Returns the xid, or 0 (after `what`'s message) if it couldn't be encoded or sent.
fn xmit(
    sock: sys::Fd,
    sa: &[u8],
    prog: u32,
    vers: u32,
    proc_: u32,
    args: impl FnOnce(&mut XdrMem<'_>) -> bool,
    what: &str,
) -> u32 {
    let mut msgbuf = [0u8; NSM_MAXMSGSIZE];
    let mut x = XdrMem::new(&mut msgbuf);
    let (xid, ok) = put_call_header(&mut x, prog, vers, proc_);
    let sent = if ok && args(&mut x) {
        let len = x.getpos();
        nsm_rpc_sendto(sock, sa, &msgbuf[..len])
    } else {
        xlog(L_ERROR, what.as_bytes());
        false
    };
    if sent { xid } else { 0 }
}

/// `nsm_xmit_getport()`: `PMAPPROC_GETPORT` for (program, version, UDP) to port 111 of
/// the `sockaddr_in` `sin`.
pub fn nsm_xmit_getport(sock: sys::Fd, sin: &[u8], program: u32, version: u32) -> u32 {
    xlog(D_CALL, &bfmt!("Sending PMAP_GETPORT for {}, {}, udp", program, version));
    let mut addr = sin[..size_of::<libc::sockaddr_in>().min(sin.len())].to_vec();
    addr.resize(size_of::<libc::sockaddr_in>(), 0);
    addr[2..4].copy_from_slice(&PMAPPORT.to_be_bytes());
    xmit(
        sock,
        &addr,
        PMAPPROG,
        PMAPVERS,
        PMAPPROC_GETPORT,
        |x| [program, version, libc::IPPROTO_UDP as u32, 0].iter().all(|&w| x.put_long(w)),
        "nsm_xmit_getport: can't encode PMAP_GETPORT call",
    )
}

/// `nsm_xmit_getaddr()`: `RPCBPROC_GETADDR` (version 3) for (program, version, "udp6")
/// to port 111 of the `sockaddr_in6` `sin6`.
pub fn nsm_xmit_getaddr(sock: sys::Fd, sin6: &[u8], program: u32, version: u32) -> u32 {
    xlog(D_CALL, &bfmt!("Sending RPCB_GETADDR for {}, {}, udp6", program, version));
    let mut addr = sin6[..size_of::<libc::sockaddr_in6>().min(sin6.len())].to_vec();
    addr.resize(size_of::<libc::sockaddr_in6>(), 0);
    addr[2..4].copy_from_slice(&PMAPPORT.to_be_bytes());
    let Some(uaddr) = nfs_sockaddr2universal(&addr) else {
        xlog(L_ERROR, b"nsm_xmit_getaddr: can't encode socket address");
        return 0;
    };
    xmit(
        sock,
        &addr,
        RPCBPROG,
        RPCBVERS,
        RPCBPROC_GETADDR,
        |x| {
            x.put_long(program)
                && x.put_long(version)
                && xdr::put_string(x, b"udp6", xdr::RPC_MAXDATASIZE)
                && xdr::put_string(x, &uaddr, xdr::RPC_MAXDATASIZE)
                && xdr::put_string(x, b"", xdr::RPC_MAXDATASIZE)
        },
        "nsm_xmit_getaddr: can't encode RPCB_GETADDR call",
    )
}

/// `nsm_xmit_rpcbind()`: ask the peer's rpcbind where NSM is, by its address family.
pub fn nsm_xmit_rpcbind(sock: sys::Fd, sa: &[u8], program: u32, version: u32) -> u32 {
    match family(sa) {
        libc::AF_INET => nsm_xmit_getport(sock, sa, program, version),
        libc::AF_INET6 => nsm_xmit_getaddr(sock, sa, program, version),
        _ => 0,
    }
}

/// `nsm_xmit_notify()`: `SM_NOTIFY(mon_name, state)` to `sa` (port already set).
pub fn nsm_xmit_notify(sock: sys::Fd, sa: &[u8], program: u32, mon_name: &[u8], state: i32) -> u32 {
    let mon_name = crate::xlog::c_str(mon_name);
    xlog(D_CALL, &bfmt!("Sending SM_NOTIFY for {}", mon_name));
    xmit(
        sock,
        sa,
        program,
        SM_VERS,
        SM_NOTIFY,
        |x| xdr::put_string(x, mon_name, SM_MAXSTRLEN as u32) && x.put_long(state as u32),
        "nsm_xmit_notify: can't encode NSMPROC_NOTIFY call",
    )
}

/// `nsm_xmit_nlmcall()`: the callback a monitor record asked for, with `struct status`.
pub fn nsm_xmit_nlmcall(sock: sys::Fd, sa: &[u8], m_: &Mon, state: i32) -> u32 {
    xlog(D_CALL, &bfmt!("Sending NLM downcall for {}", crate::xlog::c_str(&m_.mon_name)));
    xmit(
        sock,
        sa,
        m_.my_prog,
        m_.my_vers,
        m_.my_proc,
        |x| {
            xdr::put_string(x, crate::xlog::c_str(&m_.mon_name), SM_MAXSTRLEN as u32)
                && x.put_long(state as u32)
                && xdr::put_opaque(x, &m_.priv_)
        },
        "nsm_xmit_nlmcall: can't encode NLM downcall",
    )
}

/// `nsm_parse_reply()`: the reply header (with `xdr_void` results); the xid if it was
/// accepted and successful, else 0.
pub fn nsm_parse_reply(x: &mut dyn XdrDecode) -> u32 {
    let Some(r) = tirpc::clnt::decode_reply(x) else {
        xlog(L_ERROR, b"nsm_parse_reply: can't decode RPC reply");
        return 0;
    };
    if r.rp_stat != 0 {
        xlog(L_ERROR, &bfmt!("nsm_parse_reply: [0x{}] RPC status {}", format!("{:x}", r.xid), r.rp_stat));
        return 0;
    }
    if r.stat != 0 {
        xlog(L_ERROR, &bfmt!("nsm_parse_reply: [0x{}] RPC accept status {}", format!("{:x}", r.xid), r.stat));
        return 0;
    }
    r.xid
}

/// `nsm_recv_getport()`.
pub fn nsm_recv_getport(x: &mut dyn XdrDecode) -> u64 {
    let mut port: u64 = 0;
    match x.get_long() {
        Some(v) => port = u64::from(v),
        None => xlog(L_ERROR, b"nsm_recv_getport: can't decode pmap reply"),
    }
    if port > u64::from(u16::MAX) {
        xlog(L_ERROR, b"nsm_recv_getport: bad port number");
        port = 0;
    }
    xlog(D_CALL, &bfmt!("Received PMAP_GETPORT result: {}", port));
    port
}

/// `nsm_recv_getaddr()`.
pub fn nsm_recv_getaddr(x: &mut dyn XdrDecode) -> u16 {
    let uaddr = xdr::get_string(x, xdr::RPC_MAXDATASIZE);
    if uaddr.is_none() {
        xlog(L_ERROR, b"nsm_recv_getaddr: can't decode rpcb reply");
    }
    let uaddr = uaddr.map(|u| crate::xlog::c_str(&u).to_vec());
    let Some(uaddr) = uaddr.filter(|u| !u.is_empty()) else {
        xlog(D_CALL, b"Received RPCB_GETADDR result: program not registered");
        return 0;
    };
    let port = nfs_universal2port(&uaddr);
    if !(0..=i32::from(u16::MAX)).contains(&port) {
        xlog(L_ERROR, b"nsm_recv_getaddr: bad port number");
        return 0;
    }
    xlog(D_CALL, &bfmt!("Received RPCB_GETADDR result: {}", port));
    port as u16
}

/// `nsm_recv_rpcbind()`.
pub fn nsm_recv_rpcbind(af: i32, x: &mut dyn XdrDecode) -> u16 {
    match af {
        libc::AF_INET => nsm_recv_getport(x) as u16,
        libc::AF_INET6 => nsm_recv_getaddr(x),
        _ => 0,
    }
}
