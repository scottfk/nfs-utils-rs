//! `utils/statd/hostname.c`: presentation addresses, canonical names, and whether two
//! host names are the same host.

use support::bfmt;
use support::sockaddr::{nfs_compare_sockaddr, nfs_sockaddr_length};
use support::sys::{self, AddrInfo};
use support::xlog::{D_CALL, D_GENERAL, xlog};

/// `INET6_ADDRSTRLEN`.
pub const INET6_ADDRSTRLEN: usize = 46;
/// `NI_MAXHOST`.
const NI_MAXHOST: usize = 1025;

/// `statd_present_address()`: the numeric address of `sa`, or `None`.
pub fn statd_present_address(sa: &[u8], buflen: usize) -> Option<Vec<u8>> {
    let salen = nfs_sockaddr_length(sa);
    if salen == 0 {
        xlog(D_GENERAL, b"statd_present_address: unsupported address family");
        return None;
    }
    match sys::getnameinfo_len(sa, salen, buflen, libc::NI_NUMERICHOST) {
        Ok(h) => Some(h),
        Err(e) => {
            xlog(D_GENERAL, &bfmt!("statd_present_address: getnameinfo(3): {}", sys::gai_strerror(e)));
            None
        }
    }
}

/// `get_addrinfo()`: the results (and canonical name) for `hostname`, logging errors
/// other than "not found".
fn get_addrinfo(hostname: &[u8], flags: i32) -> Option<(Vec<AddrInfo>, Option<Vec<u8>>)> {
    match sys::getaddrinfo_canon(hostname, flags, libc::AF_UNSPEC, libc::IPPROTO_UDP) {
        Ok(r) => Some(r),
        Err(libc::EAI_NONAME) => None,
        Err(e) => {
            xlog(D_GENERAL, &bfmt!("get_addrinfo: failed to resolve host {}: {}", hostname, sys::gai_strerror(e)));
            None
        }
    }
}

/// `get_nameinfo()`: the name `sa` maps back to (`NI_NAMEREQD`), or `None`.
fn get_nameinfo(sa: &[u8]) -> Option<Vec<u8>> {
    match sys::getnameinfo_len(sa, sa.len(), NI_MAXHOST, libc::NI_NAMEREQD) {
        Ok(h) => Some(h),
        Err(e) => {
            xlog(D_GENERAL, &bfmt!("get_nameinfo: failed to resolve address: {}", sys::gai_strerror(e)));
            None
        }
    }
}

/// `strcpy()` into a `char buf[NI_MAXHOST]`, as far as this port can follow it: a
/// longer string would overflow the buffer in C.
fn nimaxhost(s: &[u8]) -> Vec<u8> {
    s.to_vec()
}

/// `statd_canonical_name()`: the name to file monitor records under: a presentation
/// address's reverse name (or the address itself), or a host name's canonical name.
pub fn statd_canonical_name(hostname: &[u8]) -> Option<Vec<u8>> {
    if let Some((ai, _)) = get_addrinfo(hostname, libc::AI_NUMERICHOST) {
        let name = get_nameinfo(&ai[0].addr);
        return match name {
            Some(n) if !n.is_empty() => Some(n),
            _ => Some(hostname.to_vec()),
        };
    }
    let (_, canon) = get_addrinfo(hostname, libc::AI_CANONNAME)?;
    Some(nimaxhost(&canon.unwrap_or_default()))
}

/// `statd_canonical_list()`: the addresses and canonical name of `hostname`, by way of
/// its reverse name when it's a presentation address that has one.
fn statd_canonical_list(hostname: &[u8]) -> Option<(Vec<AddrInfo>, Option<Vec<u8>>)> {
    let mut buf = None;
    if let Some((ai, _)) = get_addrinfo(hostname, libc::AI_NUMERICHOST) {
        buf = get_nameinfo(&ai[0].addr);
    }
    let buf = buf.unwrap_or_else(|| nimaxhost(hostname));
    get_addrinfo(&buf, libc::AI_CANONNAME)
}

/// `statd_matchhostname()`: the same name (ignoring case), the same canonical name, or
/// an address in common.
pub fn statd_matchhostname(hostname1: &[u8], hostname2: &[u8]) -> bool {
    let result = 'out: {
        if sys::strcaseeq(hostname1, hostname2) {
            break 'out true;
        }
        let Some((r1, c1)) = statd_canonical_list(hostname1) else {
            break 'out false;
        };
        let Some((r2, c2)) = statd_canonical_list(hostname2) else {
            break 'out false;
        };
        if sys::strcaseeq(&c1.unwrap_or_default(), &c2.unwrap_or_default()) {
            break 'out true;
        }
        r1.iter().any(|a1| r2.iter().any(|a2| nfs_compare_sockaddr(&a1.addr, &a2.addr)))
    };
    xlog(
        D_CALL,
        &bfmt!(
            "statd_matchhostname: hostnames {} and {} {}",
            hostname1,
            hostname2,
            if result { "matched" } else { "did not match" }
        ),
    );
    result
}
