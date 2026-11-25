//! `support/nfs/svc_create.c` (the TI-RPC version) and `svcsock_nonblock()` from
//! `support/nfs/svc_socket.c`: listeners on every visible transport in
//! `/etc/netconfig`, registered with the local rpcbind.

use std::sync::Mutex;

use tirpc::addr::Netbuf;
use tirpc::clnt::{Lib, RPC_ANYFD, spcreateerror};
use tirpc::netconfig::{NC_TPI_CLTS, NC_TPI_COTS_ORD, NC_VISIBLE, Netconfig};
use tirpc::svc::{RPC_MAXDATASIZE, Svc};

use crate::sockaddr::nfs_compare_sockaddr;
use crate::sys::{self, Fd};
use crate::xlog::{D_GENERAL, L_ERROR, m, xlog};

const SVC_CREATE_XPRT_CACHE_SIZE: usize = 8;

/// `svc_create_xprt_cache`, by descriptor.
static CACHE: Mutex<[Fd; SVC_CREATE_XPRT_CACHE_SIZE]> = Mutex::new([-1; SVC_CREATE_XPRT_CACHE_SIZE]);

/// `svcsock_nonblock()`: set `O_NONBLOCK`; on failure close the socket and return -1.
pub fn svcsock_nonblock(sock: Fd) -> Fd {
    if sock < 0 {
        return sock;
    }
    let flags = sys::getfl(sock);
    if flags < 0 {
        xlog(L_ERROR, &bfmt!("svc_socket: can't get socket flags: {}", m()));
    } else if sys::setfl(sock, flags | libc::O_NONBLOCK) < 0 {
        xlog(L_ERROR, &bfmt!("svc_socket: can't set socket flags: {}", m()));
    } else {
        return sock;
    }
    sys::close(sock);
    -1
}

/// `svc_create_cache_xprt()`.
fn svc_create_cache_xprt(fd: Fd) {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if c.contains(&fd) {
        return;
    }
    if let Some(slot) = c.iter_mut().find(|s| **s == -1) {
        *slot = fd;
        return;
    }
    drop(c);
    xlog(L_ERROR, b"svc_create_cache_xprt: Failed to cache an xprt");
}

/// `svc_create_find_xprt()`: a cached transport for `nconf`'s netid bound to `bindaddr`.
fn svc_create_find_xprt(svc: &Svc, bindaddr: &[u8], nconf: &Netconfig) -> Option<Fd> {
    let c = *CACHE.lock().unwrap_or_else(|e| e.into_inner());
    for fd in c {
        if fd == -1 {
            continue;
        }
        let Some(x) = svc.xprt(fd) else { continue };
        if x.netid.as_deref() != Some(&nconf.netid[..]) {
            continue;
        }
        if !nfs_compare_sockaddr(bindaddr, &x.ltaddr.buf) {
            continue;
        }
        return Some(fd);
    }
    None
}

/// `svc_create_bindaddr()`: the wildcard address of `nconf`'s family at `port`.
fn svc_create_bindaddr(nconf: &Netconfig, port: u16) -> Option<Vec<u8>> {
    let family = match &nconf.protofmly[..] {
        b"inet" => libc::AF_INET,
        b"inet6" => libc::AF_INET6,
        _ => {
            xlog(L_ERROR, &bfmt!("Unrecognized bind address family: {}", nconf.protofmly));
            return None;
        }
    };
    let protocol = match &nconf.proto[..] {
        b"udp" => libc::IPPROTO_UDP,
        b"tcp" => libc::IPPROTO_TCP,
        _ => {
            xlog(L_ERROR, &bfmt!("Unrecognized bind address protocol: {}", nconf.proto));
            return None;
        }
    };
    let buf = port.to_string().into_bytes();
    match sys::getaddrinfo(None, Some(&buf), libc::AI_PASSIVE | libc::AI_NUMERICSERV, family, 0, protocol) {
        Ok(ai) if !ai.is_empty() => Some(ai[0].addr.clone()),
        Ok(_) => None,
        Err(e) => {
            xlog(L_ERROR, &bfmt!("Failed to construct bind address: {}", sys::gai_strerror(e)));
            None
        }
    }
}

/// `svc_create_sock()`: a socket bound to `sap` with `SO_REUSEADDR` (and
/// `IPV6_V6ONLY`), listening if it's a stream.
fn svc_create_sock(sap: &[u8], nconf: &Netconfig) -> Fd {
    let ty = match nconf.semantics {
        NC_TPI_CLTS => libc::SOCK_DGRAM,
        NC_TPI_COTS_ORD => libc::SOCK_STREAM,
        s => {
            xlog(D_GENERAL, &bfmt!("svc_create_sock: Unrecognized bind address semantics: {}", u64::from(s)));
            return -1;
        }
    };
    let protocol = match &nconf.proto[..] {
        b"udp" => libc::IPPROTO_UDP,
        b"tcp" => libc::IPPROTO_TCP,
        _ => {
            xlog(D_GENERAL, &bfmt!("svc_create_sock: Unrecognized bind address protocol: {}", nconf.proto));
            return -1;
        }
    };
    let family = crate::sockaddr::family(sap);
    let fd = sys::socket(family, ty, protocol);
    if fd == -1 {
        xlog(L_ERROR, &bfmt!("Could not make a socket: ({}) {}", sys::errno(), m()));
        return -1;
    }
    if family == libc::AF_INET6 && sys::setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to set IPV6_V6ONLY: ({}) {}", sys::errno(), m()));
        sys::close(fd);
        return -1;
    }
    if sys::setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to set SO_REUSEADDR: ({}) {}", sys::errno(), m()));
        sys::close(fd);
        return -1;
    }
    if sys::bind(fd, sap) == -1 {
        xlog(L_ERROR, &bfmt!("Could not bind socket: ({}) {}", sys::errno(), m()));
        sys::close(fd);
        return -1;
    }
    if nconf.semantics == NC_TPI_COTS_ORD && sys::listen(fd, libc::SOMAXCONN) == -1 {
        xlog(L_ERROR, &bfmt!("Could not listen on socket: ({}) {}", sys::errno(), m()));
        sys::close(fd);
        return -1;
    }
    fd
}

/// What a listener is registered for.
#[derive(Debug, Clone, Copy)]
pub struct Program<'a> {
    pub name: &'a [u8],
    pub program: u32,
    pub version: u32,
    /// The number [`tirpc::svc::Service::dispatch`] gets.
    pub dispatch: u32,
}

/// `svc_create_nconf_rand_port()`: let the library make the socket, at port 0.
fn svc_create_nconf_rand_port(svc: &mut Svc, lib: &mut Lib, p: Program<'_>, nconf: &Netconfig) -> u32 {
    let Some(ai) = svc_create_bindaddr(nconf, 0) else {
        return 0;
    };
    let bindaddr = Netbuf::from_bytes(&ai);
    let Some(fd) = svc.svc_tli_create_bind(RPC_ANYFD, Some(nconf), Some((&bindaddr, libc::SOMAXCONN)), 0, 0) else {
        xlog(L_ERROR, &bfmt!("Failed to create listener xprt ({}, {}, {})", p.name, p.version, nconf.netid));
        return 0;
    };
    if svcsock_nonblock(fd) < 0 {
        // close() already done; SVC_DESTROY() of the transport, without closing again.
        svc.forget_xprt(fd);
        return 0;
    }
    lib.createerr.stat = 0;
    lib.createerr.error.set_errno(0);
    if !svc.svc_reg_nconf(lib, fd, p.program, p.version, p.dispatch, nconf) {
        let e = spcreateerror(lib, b"svc_reg() err");
        xlog(L_ERROR, &bfmt!("Failed to register ({}, {}, {}): {}", p.name, p.version, nconf.netid, e));
        return 0;
    }
    1
}

/// `svc_create_nconf_fixed_port()`: make and bind the socket here, sharing a cached
/// transport with the same address and netid.
fn svc_create_nconf_fixed_port(svc: &mut Svc, lib: &mut Lib, p: Program<'_>, port: u16, nconf: &Netconfig) -> u32 {
    let Some(ai) = svc_create_bindaddr(nconf, port) else {
        return 0;
    };
    let fd = match svc_create_find_xprt(svc, &ai, nconf) {
        Some(fd) => fd,
        None => {
            let fd = svc_create_sock(&ai, nconf);
            let fd = svcsock_nonblock(fd);
            if fd == -1 {
                return 0;
            }
            match svc.svc_tli_create(fd, Some(nconf), None, 0, 0) {
                Some(fd) => fd,
                None => {
                    xlog(
                        D_GENERAL,
                        &bfmt!("Failed to create listener xprt ({}, {}, {})", p.name, p.version, nconf.netid),
                    );
                    sys::close(fd);
                    return 0;
                }
            }
        }
    };
    if !svc.svc_reg_nconf(lib, fd, p.program, p.version, p.dispatch, nconf) {
        xlog(D_GENERAL, &bfmt!("Failed to register ({}, {}, {})", p.name, p.version, nconf.netid));
        return 0;
    }
    svc_create_cache_xprt(fd);
    1
}

/// `nfs_svc_create()`: listeners for `p` on each visible UDP and TCP transport, at
/// `port` (or the services database's port for the program, or a random one).
/// Returns how many were started.
pub fn nfs_svc_create(svc: &mut Svc, lib: &mut Lib, p: Program<'_>, port: u16) -> u32 {
    sys::sigaction_ignore(libc::SIGPIPE);
    svc.set_connmaxrec(RPC_MAXDATASIZE as i32);
    let Some(mut h) = lib.nc.setnetconfig() else {
        xlog(L_ERROR, &bfmt!("Failed to access local netconfig database: {}", lib.nc.nc_sperror()));
        return 0;
    };
    let mut visible = 0;
    let mut up = 0;
    while let Some(nconf) = lib.nc.getnetconfig(&mut h) {
        if nconf.flag & NC_VISIBLE == 0 {
            continue;
        }
        visible += 1;
        // _rpcprotobits has both UDP and TCP.
        let servport = if port == 0 { sys::getservport(u64::from(p.program), &nconf.proto) } else { port };
        up += if servport != 0 {
            svc_create_nconf_fixed_port(svc, lib, p, servport, &nconf)
        } else {
            svc_create_nconf_rand_port(svc, lib, p, &nconf)
        };
    }
    if visible == 0 {
        xlog(L_ERROR, b"Failed to find any visible netconfig entries");
    }
    if lib.nc.endnetconfig(h) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to close local netconfig database: {}", lib.nc.nc_sperror()));
    }
    up
}

/// `nfs_svc_unregister()`: remove every registration of (`program`, `version`).
pub fn nfs_svc_unregister(lib: &mut Lib, program: u32, version: u32) {
    if !tirpc::rpcb_clnt::rpcb_unset(lib, program, version, None) {
        xlog(D_GENERAL, &bfmt!("Failed to unregister program {}, version {}", u64::from(program), u64::from(version)));
    }
}
