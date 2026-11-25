//! `support/include/sockaddr.h` and the universal-address helpers of
//! `support/nfs/getport.c`, over `sockaddr` bytes.

use crate::sys;

/// `sa_family`.
pub fn family(sa: &[u8]) -> i32 {
    if sa.len() < 2 {
        return libc::AF_UNSPEC;
    }
    i32::from(u16::from_ne_bytes([sa[0], sa[1]]))
}

/// `nfs_get_port()`: the port, for `AF_INET` and `AF_INET6`; else 0.
pub fn nfs_get_port(sa: &[u8]) -> u16 {
    match family(sa) {
        libc::AF_INET | libc::AF_INET6 if sa.len() >= 4 => u16::from_be_bytes([sa[2], sa[3]]),
        _ => 0,
    }
}

/// `nfs_set_port()`.
pub fn nfs_set_port(sa: &mut [u8], port: u16) {
    if matches!(family(sa), libc::AF_INET | libc::AF_INET6) && sa.len() >= 4 {
        sa[2..4].copy_from_slice(&port.to_be_bytes());
    }
}

/// `strtoul(p, &end, 10)` with `*end == '\0'` required: the value, or `None`.
fn strtoul_all(s: &[u8]) -> Option<u64> {
    let (v, used) = sys::strtoul(s, 10);
    (used == s.len()).then_some(v)
}

/// `nfs_universal2port()`: the port at the end of a universal address, or -1.
pub fn nfs_universal2port(uaddr: &[u8]) -> i32 {
    let s = crate::xlog::c_str(uaddr);
    let Some(p) = s.iter().rposition(|&b| b == b'.') else {
        return -1;
    };
    let Some(lo) = strtoul_all(&s[p + 1..]).filter(|&v| v <= 255) else {
        return -1;
    };
    let s = &s[..p];
    let Some(p) = s.iter().rposition(|&b| b == b'.') else {
        return -1;
    };
    let Some(hi) = strtoul_all(&s[p + 1..]).filter(|&v| v <= 255) else {
        return -1;
    };
    ((hi << 8) | lo) as i32
}

/// `nfs_sockaddr2universal()` for `AF_INET` and `AF_INET6`.
pub fn nfs_sockaddr2universal(sa: &[u8]) -> Option<Vec<u8>> {
    let (mut buf, port) = match family(sa) {
        libc::AF_INET if sa.len() >= 8 => (tirpc::sys::ntop(libc::AF_INET, &sa[4..8])?, nfs_get_port(sa)),
        libc::AF_INET6 if sa.len() >= 24 => (tirpc::sys::ntop(libc::AF_INET6, &sa[8..24])?, nfs_get_port(sa)),
        _ => return None,
    };
    buf.extend_from_slice(bfmt!(".{}.{}", port >> 8, port & 0xff).as_slice());
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_ports() {
        assert_eq!(nfs_universal2port(b"127.0.0.1.3.1"), 769);
        assert_eq!(nfs_universal2port(b"::1.0.111"), 111);
        // strtoul("") uses nothing and leaves *end at the NUL: an empty part is 0.
        assert_eq!(nfs_universal2port(b"1.2."), 512);
        assert_eq!(nfs_universal2port(b"x.256.1"), -1);
        assert_eq!(nfs_universal2port(b"1"), -1);
        assert_eq!(nfs_universal2port(b"a. 1.+2"), 258);
    }
}
