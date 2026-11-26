//! `utils/nfsidmap/nfsidmap.c`: the `request-key` helper for the kernel's NFSv4 id
//! mapper, which answers one `uid:`/`gid:`/`user:`/`group:` key, and the keyring tools
//! (`-c`, `-l`, `-u`/`-g`/`-r`, `-d`).
//!
//! The key calls are libkeyutils' (1.6.3), made the same way: the same system calls,
//! in the same order, with the same `/proc/keys` parsing.

use support::bfmt;
use support::conffile;
use support::sys;
use support::xlog::{self, xlog_err, xlog_errno, xlog_warn};

use nfsidmap::NFS4_MAX_DOMAIN_LEN;

const USAGE: &str = "Usage: {} [-vh] [-c || [-u|-g|-r key] || -d || -l || [-t timeout] key desc]";
const IDMAP_NAMESZ: usize = 128;
const PROCKEYS: &[u8] = b"/proc/keys";
const DEFAULT_KEYRING: &[u8] = b".id_resolver";
const PATH_IDMAPDCONF: &[u8] = b"/etc/idmapd.conf";
const UIDKEYS: i32 = 0x1;
const GIDKEYS: i32 = 0x2;
const BUFSIZ: usize = 8192;

const KEYCTL_REVOKE: i32 = 3;
const KEYCTL_DESCRIBE: i32 = 6;
const KEYCTL_CLEAR: i32 = 7;
const KEYCTL_READ: i32 = 11;
const KEYCTL_INSTANTIATE: i32 = 12;
const KEYCTL_SET_TIMEOUT: i32 = 15;
const KEYCTL_INVALIDATE: i32 = 21;
const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const EKEYEXPIRED: i32 = 127;
const ENOKEY: i32 = 126;

/// `%m` now.
fn m() -> Vec<u8> {
    xlog::m()
}

/// `keyctl_describe(id, buf, len)`: the length of the whole description (with its
/// NUL), and what fit in `len` bytes.
fn keyctl_describe(id: i32, len: usize) -> (i64, Vec<u8>) {
    let mut buf = vec![0u8; len.max(1)];
    let p = if len == 0 { 0 } else { buf.as_mut_ptr() as u64 };
    let r = sys::keyctl(KEYCTL_DESCRIBE, id as u32 as u64, p, len as u64, 0);
    if r >= 0 {
        buf.truncate((r as usize).min(len));
    }
    (r, buf)
}

/// `keyctl_read(id, buf, len)`.
fn keyctl_read(id: i32, len: usize) -> (i64, Vec<u8>) {
    let mut buf = vec![0u8; len.max(1)];
    let p = if len == 0 { 0 } else { buf.as_mut_ptr() as u64 };
    let r = sys::keyctl(KEYCTL_READ, id as u32 as u64, p, len as u64, 0);
    if r >= 0 {
        buf.truncate((r as usize).min(len));
    }
    (r, buf)
}

/// `keyctl_describe_alloc()`: the description (without its NUL), or -1.
fn keyctl_describe_alloc(id: i32) -> Result<Vec<u8>, ()> {
    let (mut ret, _) = keyctl_describe(id, 0);
    if ret < 0 {
        return Err(());
    }
    loop {
        let buflen = ret;
        let (r, buf) = keyctl_describe(id, buflen as usize);
        if r < 0 {
            return Err(());
        }
        ret = r;
        if buflen >= ret {
            let mut b = buf;
            b.truncate((ret - 1).max(0) as usize);
            return Ok(xlog::c_str(&b).to_vec());
        }
    }
}

/// `keyctl_read_alloc()`: the contents, or -1.
fn keyctl_read_alloc(id: i32) -> Result<Vec<u8>, ()> {
    let (mut ret, _) = keyctl_read(id, 0);
    if ret < 0 {
        return Err(());
    }
    loop {
        let buflen = ret;
        let (r, buf) = keyctl_read(id, buflen as usize);
        if r < 0 {
            return Err(());
        }
        ret = r;
        if buflen >= ret {
            let mut b = buf;
            b.truncate(ret as usize);
            return Ok(b);
        }
    }
}

/// libkeyutils' `find_key_by_type_and_desc(type, desc, 0)`: `request_key()`, else a
/// search of `/proc/keys` with each candidate's description checked.
fn find_key_by_type_and_desc(ty: &[u8], desc: &[u8]) -> i32 {
    let mut error = ENOKEY;
    let id = sys::request_key(ty, desc, None, 0);
    if id >= 0 || sys::errno() == libc::ENOMEM {
        return id;
    }
    if sys::errno() != ENOKEY {
        error = sys::errno();
    }
    let dlen = desc.len();
    let lines = match sys::fgets_all(b"/proc/keys", 1024) {
        Ok(l) => l,
        Err(e) => {
            sys::stderr(&bfmt!("libkeyutils: Can't open /proc/keys: {}\n", sys::strerror(e)));
            return -1;
        }
    };
    for raw in lines {
        let Some(nl) = raw.iter().position(|&b| b == b'\n') else {
            // QUIRK: a line without a newline (the last, or one of 1023 bytes or more)
            // makes libkeyutils dereference NULL.
            sys::segfault();
        };
        let buf = xlog::c_str(&raw[..nl]).to_vec();
        let cp = buf.len();
        let (n, id, typebuf, ndesc) = sys::scan_proc_keys(&buf);
        if n == 2 && ndesc > 0 && ndesc as usize <= cp {
            if typebuf != ty {
                continue;
            }
            let kdesc = &buf[ndesc as usize..];
            if kdesc.len() < dlen || &kdesc[..dlen] != desc {
                continue;
            }
            let next = kdesc.get(dlen).copied().unwrap_or(0);
            if next != b':' && next != 0 && next != b' ' {
                continue;
            }
            let (n, rdesc) = keyctl_describe(id, 1023);
            if n == -1 {
                let e = sys::errno();
                if e != ENOKEY {
                    error = e;
                }
                if e == libc::ENOMEM {
                    break;
                }
            }
            // n is compared as unsigned: -1 is skipped too.
            if n as u64 >= 1023 {
                continue;
            }
            let rdesc = xlog::c_str(&rdesc[..(n as usize).min(rdesc.len())]).to_vec();
            let Some(semi) = rdesc.iter().rposition(|&b| b == b';') else {
                continue;
            };
            if &rdesc[semi + 1..] != desc {
                continue;
            }
            return id;
        }
    }
    sys::set_errno(error);
    -1
}

/// `keyring_clear()`.
fn keyring_clear(keyring: &[u8], verbose: i32) -> i32 {
    let key = find_key_by_type_and_desc(b"keyring", keyring);
    if key == -1 {
        if verbose != 0 {
            xlog_warn(&bfmt!("'{}' keyring was not found.", keyring));
        }
        return 0;
    }
    if sys::keyctl(KEYCTL_CLEAR, key as u32 as u64, 0, 0, 0) < 0 {
        xlog_err(&bfmt!("keyctl_clear(0x{}) failed: {}", format!("{:x}", key as u32), m()));
    }
    if verbose != 0 {
        xlog_warn(&bfmt!("'{}' cleared", keyring));
    }
    0
}

fn display_default_domain() -> i32 {
    let mut domain = Vec::new();
    let rc = nfsidmap::nfs4_get_default_domain(None, &mut domain, NFS4_MAX_DOMAIN_LEN);
    if rc != 0 {
        xlog_errno(rc, &bfmt!("nfs4_get_default_domain failed: {}", sys::strerror(rc)));
    }
    sys::c_stdout(&bfmt!("{}\n", domain));
    0
}

fn list_key(key: i32) {
    let buffer = match keyctl_describe_alloc(key) {
        Ok(b) => b,
        Err(()) => {
            if sys::errno() == EKEYEXPIRED {
                sys::c_stdout(b"Expired key not displayed\n");
            } else {
                xlog_err(&bfmt!("Failed to describe key: {}", m()));
            }
            return;
        }
    };
    let Some(c) = buffer.iter().rposition(|&b| b == b';') else {
        xlog_err(b"Unparsable key not displayed\n");
    };
    sys::c_stdout(&bfmt!("  {}\n", &buffer[c + 1..]));
}

fn list_keys(ring_name: &[u8], ring_id: i32) {
    let keylist = match keyctl_read_alloc(ring_id) {
        Ok(k) => k,
        Err(()) => xlog_err(&bfmt!("Failed to read keyring {}: {}", ring_name, m())),
    };
    let count = keylist.len() / 4;
    match count {
        0 => sys::c_stdout(&bfmt!("No {} keys found.\n", ring_name)),
        1 => sys::c_stdout(&bfmt!("1 {} key found:\n", ring_name)),
        n => sys::c_stdout(&bfmt!("{} {} keys found:\n", n as u32, ring_name)),
    }
    for k in keylist.as_chunks::<4>().0 {
        list_key(i32::from_ne_bytes(*k));
    }
}

fn list_keyring(keyring: &[u8]) -> i32 {
    let key = find_key_by_type_and_desc(b"keyring", keyring);
    if key == -1 {
        xlog_err(&bfmt!("'{}' keyring was not found.", keyring));
    }
    list_keys(keyring, key);
    0
}

fn instantiate(key: i32, payload: &[u8]) -> i64 {
    sys::keyctl(KEYCTL_INSTANTIATE, key as u32 as u64, payload.as_ptr() as u64, payload.len() as u64, 0)
}

/// `id_lookup()`: a `uid:`/`gid:` key, answered with the id as a C string.
fn id_lookup(name_at_domain: &[u8], key: i32, user: bool, verbose: i32) -> i32 {
    let mut id = 0u32;
    let rc = if user {
        nfsidmap::nfs4_owner_to_uid(name_at_domain, &mut id)
    } else {
        nfsidmap::nfs4_group_owner_to_gid(name_at_domain, &mut id)
    };
    let mut idstr = id.to_string().into_bytes();
    if rc < 0 {
        let f = if user { "nfs4_owner_to_uid" } else { "nfs4_group_owner_to_gid" };
        xlog_errno(rc, &bfmt!("id_lookup: {}: for {} failed: {}", f, name_at_domain, sys::strerror(rc)));
    }
    idstr.push(0);
    let mut rc = 0;
    if instantiate(key, &idstr) != 0 {
        match sys::errno() {
            libc::EDQUOT | libc::ENFILE | libc::ENOMEM => {
                // The keyring is full: clear it and try again.
                rc = keyring_clear(DEFAULT_KEYRING, verbose);
                if rc == 0 && instantiate(key, &idstr) != 0 {
                    xlog_err(&bfmt!("id_lookup: keyctl_instantiate failed: {}", m()));
                }
            }
            _ => rc = 1,
        }
    }
    rc
}

/// `name_lookup()`: a `user:`/`group:` key, answered with `name@domain` (no NUL).
fn name_lookup(id: &[u8], key: i32, user: bool) -> i32 {
    let mut domain = Vec::new();
    let rc = nfsidmap::nfs4_get_default_domain(None, &mut domain, NFS4_MAX_DOMAIN_LEN);
    if rc != 0 {
        xlog_errno(rc, &bfmt!("name_lookup: nfs4_get_default_domain failed: {}", sys::strerror(rc)));
    }
    let n = sys::atoi(id) as u32;
    // QUIRK: with no methods (an empty Method list) nothing is written and C sends its
    // uninitialized buffer; this sends nothing.
    let mut name = Vec::new();
    let rc = if user {
        nfsidmap::nfs4_uid_to_name(n, Some(&domain), &mut name, IDMAP_NAMESZ)
    } else {
        nfsidmap::nfs4_gid_to_name(n, Some(&domain), &mut name, IDMAP_NAMESZ)
    };
    if rc != 0 {
        let f = if user { "nfs4_uid_to_name" } else { "nfs4_gid_to_name" };
        xlog_errno(rc, &bfmt!("name_lookup: {}: for {} failed: {}", f, n, sys::strerror(rc)));
    }
    if instantiate(key, xlog::c_str(&name)) != 0 {
        xlog_err(&bfmt!("name_lookup: keyctl_instantiate failed: {}", m()));
    }
    0
}

/// `key_invalidate()`: the first `uid:`/`gid:` key (for `-r`, one of each) whose id
/// starts with `keystr`.
fn key_invalidate(keystr: &[u8], mut keymask: i32, verbose: i32) -> i32 {
    xlog::xlog_syslog(false);
    let lines = match sys::fgets_all(PROCKEYS, BUFSIZ) {
        Ok(l) => l,
        Err(e) => {
            sys::set_errno(e);
            xlog_err(&bfmt!("fopen({}) failed: {}", PROCKEYS, m()));
        }
    };
    let find = |buf: &[u8], pat: &[u8]| buf.windows(pat.len()).position(|w| w == pat);
    let mut key: u32 = 0;
    for raw in lines {
        let buf = xlog::c_str(&raw).to_vec();
        if find(&buf, b"keyring").is_some() {
            continue;
        }
        let (mask, ptr) = if let Some(p) = find(&buf, b"uid:") {
            (UIDKEYS, p)
        } else if let Some(p) = find(&buf, b"gid:") {
            (GIDKEYS, p)
        } else {
            continue;
        };
        if keymask & mask == 0 {
            continue;
        }
        let rest = &buf[ptr + 4..];
        if rest.len() < keystr.len() || &rest[..keystr.len()] != keystr {
            continue;
        }
        if verbose != 0 {
            let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
                // QUIRK: C writes through strchr()'s NULL.
                sys::segfault();
            };
            xlog_warn(&bfmt!("invalidating '{}'", &buf[..nl]));
        }
        // The key is the first field. QUIRK: C writes through strchr()'s NULL when the
        // line has no space.
        let Some(sp) = buf.iter().position(|&b| b == b' ') else {
            sys::segfault();
        };
        key = sys::scan_hex(&buf[..sp], key).1;
        if sys::keyctl(KEYCTL_INVALIDATE, key as u64, 0, 0, 0) < 0 {
            if sys::errno() != libc::EOPNOTSUPP {
                xlog_err(&bfmt!("keyctl_invalidate(0x{}) failed: {}", format!("{key:x}"), m()));
            } else if sys::keyctl(KEYCTL_REVOKE, key as u64, 0, 0, 0) < 0 {
                // Older kernels.
                xlog_err(&bfmt!("keyctl_revoke(0x{}) failed: {}", format!("{key:x}"), m()));
            }
        }
        keymask &= !mask;
        if keymask == 0 {
            return 0;
        }
    }
    xlog_err(&bfmt!("'{}' key was not found.", keystr));
}

/// `strtok()` over `s` from `*pos` with `:` as the delimiter.
fn strtok(s: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let mut i = *pos;
    while i < s.len() && s[i] == b':' {
        i += 1;
    }
    if i >= s.len() {
        *pos = s.len();
        return None;
    }
    let start = i;
    while i < s.len() && s[i] != b':' {
        i += 1;
    }
    let tok = s[start..i].to_vec();
    *pos = if i < s.len() { i + 1 } else { i };
    Some(tok)
}

fn main() {
    let mut args = sys::Args::from_env();
    let argv0 = args.argv0();
    let progname = match argv0.iter().rposition(|&b| b == b'/') {
        Some(p) => argv0[p + 1..].to_vec(),
        None => argv0.clone(),
    };
    xlog::xlog_open(&progname);

    let mut verbose = 0;
    let mut timeout = 600;
    let mut keystr: Option<Vec<u8>> = None;
    let (mut clearing, mut keymask, mut display, mut list) = (0, 0, 0, 0);
    loop {
        let (opt, optarg) = args.getopt(c"hdu:g:r:ct:vl");
        if opt == -1 {
            break;
        }
        let arg = optarg.unwrap_or_default();
        match opt as u8 {
            b'd' => display += 1,
            b'l' => list += 1,
            b'u' => {
                keymask = UIDKEYS;
                keystr = Some(arg);
            }
            b'g' => {
                keymask = GIDKEYS;
                keystr = Some(arg);
            }
            b'r' => {
                keymask = GIDKEYS | UIDKEYS;
                keystr = Some(arg);
            }
            b'c' => clearing += 1,
            b'v' => verbose += 1,
            b't' => timeout = sys::atoi(&arg),
            _ => {
                xlog_warn(&USAGE.replace("{}", &String::from_utf8_lossy(&progname)).into_bytes());
                sys::exit(if opt == b'h' as i32 { 0 } else { 1 });
            }
        }
    }

    if sys::geteuid() != 0 {
        xlog_err(b"Must be run as root.");
    }

    let rc = nfsidmap::nfs4_init_name_mapping(Some(PATH_IDMAPDCONF));
    if rc != 0 {
        xlog_errno(rc, b"Unable to create name to user id mappings.");
    }
    if verbose == 0 {
        // QUIRK: this is nfsidmap's own copy of the configuration database, which
        // nothing reads into (the library reads its own): Verbosity is never seen.
        verbose = conffile::conf_get_num(b"General", b"Verbosity", 0);
    }

    if display != 0 {
        sys::exit(display_default_domain());
    }
    if list != 0 {
        sys::exit(list_keyring(DEFAULT_KEYRING));
    }
    if let Some(k) = keystr {
        sys::exit(key_invalidate(&k, keymask, verbose));
    }
    if clearing != 0 {
        xlog::xlog_syslog(false);
        sys::exit(keyring_clear(DEFAULT_KEYRING, verbose));
    }

    xlog::xlog_stderr(verbose != 0);
    let optind = args.optind();
    let rest = args.rest(optind);
    if rest.len() != 2 {
        xlog_warn(b"Bad arg count. Check /etc/request-key.conf");
        xlog_warn(&USAGE.replace("{}", &String::from_utf8_lossy(&progname)).into_bytes());
        sys::exit(1);
    }

    if verbose != 0 {
        nfsidmap::nfs4_set_debug(verbose, None);
    }

    let key = sys::strtol10(&rest[0]).0 as i32;
    let arg = rest[1].clone();
    let mut pos = 0;
    let ty = strtok(&arg, &mut pos);
    let value = strtok(&arg, &mut pos);
    let Some(value) = value else {
        xlog_err(b"Error: Null uid/gid value.");
    };
    let ty = ty.unwrap_or_default();
    if verbose != 0 {
        xlog_warn(&bfmt!("key: 0x{} type: {} value: {} timeout {}", format!("{:x}", key as u32), ty, value, timeout));
    }

    // Become a possessor of the key to be instantiated, to set its timeout.
    sys::request_key(b"keyring", DEFAULT_KEYRING, None, KEY_SPEC_THREAD_KEYRING);

    // QUIRK: an unknown type leaves rc at 0 (the init's result): the key gets a
    // timeout but no answer, and nfsidmap exits 0.
    let rc = match &ty[..] {
        b"uid" => id_lookup(&value, key, true, verbose),
        b"gid" => id_lookup(&value, key, false, verbose),
        b"user" => name_lookup(&value, key, true),
        b"group" => name_lookup(&value, key, false),
        _ => 0,
    };
    if rc == 0 {
        sys::keyctl(KEYCTL_SET_TIMEOUT, key as u32 as u64, timeout as u32 as u64, 0, 0);
    }
    sys::exit(rc);
}
