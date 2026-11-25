//! The part of `support/nfs/getport.c` and `support/nfs/rpc_socket.c` that rpc.statd
//! reaches: `nfs_probe_statd()`, which asks the local rpcbind (version 2, over UDP)
//! where statd is and pings it there.

use tirpc::addr::Netbuf;
use tirpc::clnt::{self, Control, Lib, RPC_SUCCESS, Timeval};

use crate::sockaddr::{family, nfs_get_port, nfs_set_port};
use crate::sys;

const NSMPROG: u32 = 100024;
const RPCBPROG: u32 = 100000;
const RPCBVERS_4: u32 = 4;
const PMAPVERS: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const PMAPPORT: u16 = 111;
/// `NFSRPC_TIMEOUT_UDP`, for a timeout of -1.
const NFSRPC_TIMEOUT_UDP: i64 = 3;
const RPC_SYSTEMERROR: u32 = 12;
const RPC_UNKNOWNADDR: u32 = 19;
const RPC_PROGNOTREGISTERED: u32 = 15;

/// `nfs_getrpcbyname()`: the number of the first name in the rpc database, or `program`.
fn nfs_getrpcbyname(program: u32, table: &[&[u8]]) -> u32 {
    for name in table {
        if let Some(n) = sys::getrpcbyname_number(name) {
            return n as u32;
        }
    }
    program
}

/// `nfs_gp_getservbyname()`: the port (network order) of `service`, or 0.
fn nfs_gp_getservbyname(service: &[u8], protocol: i32) -> u16 {
    match sys::getaddrinfo(None, Some(service), libc::AI_PASSIVE, libc::AF_INET, 0, protocol) {
        Ok(ai) if !ai.is_empty() && ai[0].addr.len() >= 4 => u16::from_ne_bytes([ai[0].addr[2], ai[0].addr[3]]),
        _ => 0,
    }
}

/// `nfs_gp_get_rpcb_port()`: rpcbind's port (network order).
fn nfs_gp_get_rpcb_port(protocol: i32) -> u16 {
    for name in [&b"rpcbind"[..], b"portmapper", b"sunrpc"] {
        let port = nfs_gp_getservbyname(name, protocol);
        if port != 0 {
            return port;
        }
    }
    PMAPPORT.to_be()
}

/// `nfs_connect_nb()` for a datagram socket: `connect()` with `O_NONBLOCK` set for the
/// moment. Returns 0 or -1 (errno set).
fn nfs_connect_nb(fd: sys::Fd, sa: &[u8], timeout: &mut Timeval) -> i32 {
    let flags = sys::getfl(fd);
    if flags < 0 {
        return -1;
    }
    if sys::setfl(fd, flags | libc::O_NONBLOCK) < 0 {
        return -1;
    }
    let mut ret = sys::connect(fd, sa);
    'done: {
        if ret < 0 && sys::errno() != libc::EINPROGRESS && sys::errno() != libc::EINTR {
            ret = -1;
            break 'done;
        }
        if ret == 0 {
            break 'done;
        }
        let mut tv = (timeout.sec, timeout.usec);
        loop {
            ret = sys::select_write_one(fd, &mut tv);
            if ret >= 0 {
                break;
            }
            if sys::errno() != libc::EINTR {
                ret = -1;
                break 'done;
            }
        }
        (timeout.sec, timeout.usec) = tv;
        if ret == 0 {
            sys::set_errno(libc::ETIMEDOUT);
            ret = -1;
            break 'done;
        }
        match sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_ERROR) {
            None => ret = -1,
            Some(0) => ret = 0,
            Some(e) => {
                sys::set_errno(e);
                ret = -1;
            }
        }
    }
    sys::setfl(fd, flags);
    ret
}

/// `nfs_get_udpclient()` with an unprivileged source port: a connected UDP client.
fn nfs_get_udpclient(
    lib: &mut Lib,
    sa: &[u8],
    program: u32,
    version: u32,
    timeout: &mut Timeval,
) -> Option<clnt::Client> {
    let sock = sys::socket(family(sa), libc::SOCK_DGRAM, libc::IPPROTO_UDP);
    if sock == -1 {
        lib.createerr.stat = RPC_SYSTEMERROR;
        lib.createerr.error.set_errno(sys::errno());
        return None;
    }
    if timeout.sec == -1 {
        timeout.sec = NFSRPC_TIMEOUT_UDP;
    }
    if nfs_connect_nb(sock, sa, timeout) != 0 {
        lib.createerr.stat = RPC_SYSTEMERROR;
        lib.createerr.error.set_errno(sys::errno());
        sys::close(sock);
        return None;
    }
    let nbuf = Netbuf::from_bytes(sa);
    match clnt::clnt_dg_create(lib, sock, &nbuf, program, version, 0, 0) {
        Some(mut c) => {
            c.control(Control::SetRetryTimeout(Timeval::secs(1)));
            c.control(Control::SetFdClose);
            Some(c)
        }
        None => {
            sys::close(sock);
            None
        }
    }
}

/// `nfs_get_rpcclient()` for an IPv4 or IPv6 address over UDP (the only use here).
fn nfs_get_rpcclient(
    lib: &mut Lib,
    sa: &[u8],
    program: u32,
    version: u32,
    timeout: &mut Timeval,
) -> Option<clnt::Client> {
    lib.createerr = Default::default();
    match family(sa) {
        libc::AF_INET | libc::AF_INET6 => {
            if nfs_get_port(sa) == 0 {
                lib.createerr.stat = RPC_UNKNOWNADDR;
                return None;
            }
        }
        _ => {
            lib.createerr.stat = RPC_UNKNOWNADDR;
            return None;
        }
    }
    nfs_get_udpclient(lib, sa, program, version, timeout)
}

/// `nfs_gp_get_rpcbclient()`: a client for rpcbind at `sa` (whose port is set).
fn nfs_gp_get_rpcbclient(lib: &mut Lib, sa: &mut [u8], version: u32, timeout: &mut Timeval) -> Option<clnt::Client> {
    let rpcb_prog = nfs_getrpcbyname(RPCBPROG, &[b"rpcbind", b"portmap", b"portmapper", b"sunrpc"]);
    nfs_set_port(sa, u16::from_be(nfs_gp_get_rpcb_port(libc::IPPROTO_UDP)));
    nfs_get_rpcclient(lib, sa, rpcb_prog, version, timeout)
}

/// `nfs_gp_getport()` for `AF_INET`: portmap `GETPORT` (version 2). Returns the port,
/// or 0 (with `rpc_createerr` set).
fn nfs_gp_getport(
    lib: &mut Lib,
    client: &mut clnt::Client,
    sa: &[u8],
    program: u32,
    version: u32,
    timeout: Timeval,
) -> u16 {
    if family(sa) != libc::AF_INET {
        // AF_INET6 goes through rpcbind versions 4 and 3; statd only asks over IPv4.
        lib.createerr.stat = RPC_UNKNOWNADDR;
        return 0;
    }
    client.control(Control::SetVers(PMAPVERS));
    let mut port: u64 = 0;
    let status = client.call(
        PMAPPROC_GETPORT,
        &mut |x| x.put_long(program) && x.put_long(version) && x.put_long(libc::IPPROTO_UDP as u32) && x.put_long(0),
        &mut |x| match x.get_long() {
            Some(v) => {
                port = u64::from(v);
                true
            }
            None => false,
        },
        timeout,
    );
    if status != RPC_SUCCESS {
        lib.createerr.stat = status;
        lib.createerr.error = client.geterr();
        port = 0;
    } else if port == 0 {
        lib.createerr.stat = RPC_PROGNOTREGISTERED;
    }
    // The unsigned long is returned as unsigned short.
    port as u16
}

/// `nfs_gp_ping()`: a NULL call; true if it succeeded.
fn nfs_gp_ping(lib: &mut Lib, client: &mut clnt::Client, timeout: Timeval) -> bool {
    let status = client.call(0, &mut |_| true, &mut |_| true, timeout);
    if status != RPC_SUCCESS {
        lib.createerr.stat = status;
        lib.createerr.error = client.geterr();
    }
    status == RPC_SUCCESS
}

/// `nfs_getport_ping()` over UDP.
fn nfs_getport_ping(lib: &mut Lib, sa: &mut [u8], program: u32, version: u32) -> bool {
    let mut timeout = Timeval { sec: -1, usec: 0 };
    let mut port = 0;
    lib.createerr = Default::default();
    if let Some(mut client) = nfs_gp_get_rpcbclient(lib, sa, RPCBVERS_4, &mut timeout) {
        port = nfs_gp_getport(lib, &mut client, sa, program, version, timeout);
        client.destroy();
    }
    let mut result = false;
    if port != 0 {
        let mut saddr = sa.to_vec();
        nfs_set_port(&mut saddr, port);
        lib.createerr = Default::default();
        if let Some(mut client) = nfs_get_rpcclient(lib, &saddr, program, version, &mut timeout) {
            result = nfs_gp_ping(lib, &mut client, timeout);
            client.destroy();
        }
    }
    if result {
        nfs_set_port(sa, port);
    }
    result
}

/// `nfs_probe_statd()`: is statd (version 1, UDP) registered with the local rpcbind
/// and answering?
pub fn nfs_probe_statd(lib: &mut Lib) -> bool {
    let mut sin = [0u8; size_of::<libc::sockaddr_in>()];
    sin[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    sin[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let program = nfs_getrpcbyname(NSMPROG, &[b"status"]);
    nfs_getport_ping(lib, &mut sin, program, 1)
}
