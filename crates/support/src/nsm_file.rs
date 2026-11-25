//! `support/nsm/file.c`: NSM's on-disk state under the state directory: the `state`
//! file, the monitor records in `sm/` and the notify list in `sm.bak/`, and the privilege
//! drop to the owner of `sm/`.
//!
//! A monitor record is one line per (mon_name, my_name) pair:
//! `ADDR PROG VERS PROC PRIV MON_NAME MY_NAME`, the first four as `%08x`, the 16-byte
//! cookie as 32 hex digits.

use std::sync::Mutex;

use crate::misc::{PATH_MAX, generic_make_pathname, generic_setup_basedir};
use crate::sys;
use crate::xlog::{D_CALL, D_GENERAL, L_ERROR, L_NOTICE, m, xlog, xlog_warn};

/// `SM_MAXSTRLEN`.
pub const SM_MAXSTRLEN: usize = 1024;
/// `SM_PRIV_SIZE`.
pub const SM_PRIV_SIZE: usize = 16;
/// `NSM_DEFAULT_STATEDIR`.
pub const NSM_DEFAULT_STATEDIR: &[u8] = b"/var/lib/nfs";
const RPCARGSLEN: usize = 4 * (8 + 1);
const LINELEN: usize = RPCARGSLEN + SM_PRIV_SIZE * 2 + 1;
/// The line buffers' size: `LINELEN + 1 + SM_MAXSTRLEN + 2`.
const BUFLEN: usize = LINELEN + 1 + SM_MAXSTRLEN + 2;
const NSM_KERNEL_STATE_FILE: &[u8] = b"/proc/sys/fs/nfs/nsm_local_state";
const NSM_MONITOR_DIR: &[u8] = b"sm";
const NSM_NOTIFY_DIR: &[u8] = b"sm.bak";
const NSM_STATE_FILE: &[u8] = b"state";

/// `struct mon`, with the callback address (`sin_addr.s_addr` as the host reads it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mon {
    pub mon_name: Vec<u8>,
    pub my_name: Vec<u8>,
    pub my_prog: u32,
    pub my_vers: u32,
    pub my_proc: u32,
    pub priv_: [u8; SM_PRIV_SIZE],
}

/// `nsm_base_dirname`.
static BASE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn base() -> Vec<u8> {
    BASE.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| NSM_DEFAULT_STATEDIR.to_vec())
}

/// `nsm_make_record_pathname()`: `base/directory/hostname`, refusing names with `/` or
/// white space.
fn nsm_make_record_pathname(directory: &[u8], hostname: &[u8]) -> Option<Vec<u8>> {
    let hostname = crate::xlog::c_str(hostname);
    if hostname.iter().any(|&c| c == b'/' || sys::isspace(c)) {
        xlog(D_GENERAL, b"Hostname contains invalid characters");
        return None;
    }
    let base = base();
    let size = base.len() + directory.len() + hostname.len() + 3;
    if size > PATH_MAX {
        xlog(D_GENERAL, b"Hostname results in pathname that is too long");
        return None;
    }
    Some(bfmt!("{}/{}/{}", base, directory, hostname))
}

/// `nsm_make_pathname()`.
fn nsm_make_pathname(directory: &[u8]) -> Option<Vec<u8>> {
    generic_make_pathname(&base(), directory)
}

/// `nsm_make_temp_pathname()`: `dir/.base.new`.
fn nsm_make_temp_pathname(pathname: &[u8]) -> Option<Vec<u8>> {
    let size = pathname.len() + b".new\0".len() + 1;
    if size > PATH_MAX {
        return None;
    }
    // Every caller's path has a slash (C reads garbage without one).
    let slash = pathname.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    let (dir, base) = pathname.split_at(slash);
    Some(bfmt!("{}.{}.new", dir, base))
}

/// `nsm_atomic_write()`: write a temporary file, then rename it over `path`.
fn nsm_atomic_write(path: &[u8], buf: &[u8]) -> bool {
    let Some(temp) = nsm_make_temp_pathname(path) else {
        xlog(L_ERROR, &bfmt!("Failed to create new path for {}", path));
        return false;
    };
    let fd = sys::open(&temp, libc::O_CREAT | libc::O_TRUNC | libc::O_SYNC | libc::O_WRONLY, 0o644);
    if fd == -1 {
        xlog(L_ERROR, &bfmt!("Failed to create {}: {}", temp, m()));
        return false;
    }
    let len = sys::write(fd, buf);
    if len < 0 || len as usize != buf.len() {
        xlog(L_ERROR, &bfmt!("Failed to write {}: {}", temp, m()));
        sys::close(fd);
        sys::unlink(&temp);
        return false;
    }
    if sys::close(fd) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to close {}: {}", temp, m()));
        sys::unlink(&temp);
        return false;
    }
    if sys::rename(&temp, path) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to rename {} -> {}: {}", temp, path, m()));
        sys::unlink(&temp);
        return false;
    }
    true
}

/// `nsm_setup_pathnames()`.
pub fn nsm_setup_pathnames(progname: &[u8], parentdir: &[u8]) -> bool {
    let mut b = base();
    let ok = generic_setup_basedir(progname, parentdir, &mut b, PATH_MAX);
    if ok {
        *BASE.lock().unwrap_or_else(|e| e.into_inner()) = Some(b);
    }
    ok
}

/// `nsm_is_default_parentdir()`.
pub fn nsm_is_default_parentdir() -> bool {
    base() == NSM_DEFAULT_STATEDIR
}

/// The state directory (`nsm_base_dirname`).
pub fn nsm_base_dirname() -> Vec<u8> {
    base()
}

/// `nsm_drop_privileges()`: become the owner of `sm/`, after chown'ing the pid file
/// (`pidfd`, if any) to it.
pub fn nsm_drop_privileges(pidfd: i32) -> bool {
    sys::umask(libc::S_IRWXO);
    let base = base();
    if sys::chdir(&base) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to change working directory to {}: {}", base, m()));
        return false;
    }
    let Some(st) = sys::lstat(NSM_MONITOR_DIR) else {
        xlog(L_ERROR, &bfmt!("Failed to stat {}/{}: {}", base, NSM_MONITOR_DIR, m()));
        return false;
    };
    let uid = sys::getuid();
    if uid != 0 && uid == st.uid {
        return true;
    }
    // prune_bounding_set() and nsm_clear_capabilities() do nothing without libcap.
    if st.uid == 0 {
        xlog_warn(&bfmt!("Running as root.  chown {} to choose different user", base));
        return true;
    }
    if pidfd >= 0 && sys::fchown(pidfd, st.uid, st.gid) == -1 {
        xlog_warn(&bfmt!("Failed to change owner of pidfile: {}", m()));
    }
    if sys::keepcaps() == -1 {
        xlog(L_ERROR, &bfmt!("prctl(PR_SET_KEEPCAPS) failed: {}", m()));
        return false;
    }
    if sys::setgroups_none() == -1 {
        xlog(L_ERROR, &bfmt!("Failed to drop supplementary groups: {}", m()));
        return false;
    }
    if sys::setgid(st.gid) == -1 || sys::setuid(st.uid) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to drop privileges: {}", m()));
        return false;
    }
    xlog(D_CALL, &bfmt!("Effective UID, GID: {}, {}", st.uid, st.gid));
    true
}

/// `nsm_get_state()`: the odd state number from disk (plus 2 when `update`), or an
/// initial one; 0 on error.
pub fn nsm_get_state(mut update: bool) -> i32 {
    let Some(path) = nsm_make_pathname(NSM_STATE_FILE) else {
        xlog(L_ERROR, b"Failed to allocate path for state");
        return 0;
    };
    let mut state: i32;
    let fd = sys::open(&path, libc::O_RDONLY, 0);
    if fd == -1 {
        if sys::errno() != libc::ENOENT {
            xlog(L_ERROR, &bfmt!("Failed to open {}: {}", path, m()));
            return 0;
        }
        xlog(L_NOTICE, b"Initializing NSM state");
        state = 1;
        update = true;
    } else {
        let mut b = [0u8; 4];
        let n = sys::read(fd, &mut b);
        if n != 4 {
            // QUIRK: after a short read, %m prints whatever errno was before.
            xlog_warn(&bfmt!("Failed to read {}: {}", path, m()));
            xlog(L_NOTICE, b"Initializing NSM state");
            state = 1;
            update = true;
        } else {
            state = i32::from_ne_bytes(b);
            if state & 1 == 0 {
                state = state.wrapping_add(1);
            }
        }
        sys::close(fd);
    }
    if update {
        state = state.wrapping_add(2);
        if !nsm_atomic_write(&path, &state.to_ne_bytes()) {
            state = 0;
        }
    }
    state
}

/// `nsm_update_kernel_state()`: tell the kernel's lockd the new state number.
pub fn nsm_update_kernel_state(state: i32) {
    let fd = sys::open(NSM_KERNEL_STATE_FILE, libc::O_WRONLY, 0);
    if fd == -1 {
        xlog(D_GENERAL, &bfmt!("Failed to open /proc/sys/fs/nfs/nsm_local_state: {}", m()));
        return;
    }
    let buf = state.to_string().into_bytes();
    let r = sys::write(fd, &buf);
    if r < 0 || r as usize != buf.len() {
        xlog_warn(&bfmt!("Failed to write NSM state number: {}", m()));
    }
    if sys::close(fd) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to close NSM state file /proc/sys/fs/nfs/nsm_local_state: {}", m()));
    }
}

/// `nsm_retire_monitored_hosts()`: move every record from `sm/` to `sm.bak/`.
pub fn nsm_retire_monitored_hosts() -> u32 {
    let mut count = 0;
    let Some(path) = nsm_make_pathname(NSM_MONITOR_DIR) else {
        xlog(L_ERROR, b"Failed to allocate path for sm");
        return count;
    };
    let Some(mut dir) = sys::Dir::open(&path) else {
        xlog_warn(&bfmt!("Failed to open sm: {}", m()));
        return count;
    };
    while let Some((name, _)) = dir.next_entry() {
        if name.first() == Some(&b'.') {
            continue;
        }
        let Some(src) = nsm_make_record_pathname(NSM_MONITOR_DIR, &name) else {
            xlog_warn(b"Bad monitor file name, skipping");
            continue;
        };
        let Some(st) = sys::lstat(&src) else {
            xlog_warn(&bfmt!("Bad monitor file {}, skipping: {}", name, m()));
            continue;
        };
        if !st.is_reg() {
            xlog(D_GENERAL, &bfmt!("Skipping non-regular file {}", name));
            continue;
        }
        let Some(dst) = nsm_make_record_pathname(NSM_NOTIFY_DIR, &name) else {
            xlog_warn(b"Bad notify file name, skipping");
            continue;
        };
        if sys::rename(&src, &dst) == -1 {
            xlog_warn(&bfmt!("Failed to rename {} -> {}: {}", src, dst, m()));
        } else {
            xlog(D_GENERAL, &bfmt!("Retired record for mon_name {}", name));
            count += 1;
        }
    }
    count
}

/// `nsm_priv_to_hex()`.
pub fn nsm_priv_to_hex(priv_: &[u8; SM_PRIV_SIZE]) -> Vec<u8> {
    priv_.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// `nsm_create_monitor_record()`: the record line, or `None` if it doesn't fit in
/// `buflen` bytes (with its NUL).
fn nsm_create_monitor_record(buflen: usize, s_addr: u32, m: &Mon) -> Option<Vec<u8>> {
    let mut out = format!("{:08x} {:08x} {:08x} {:08x} ", s_addr, m.my_prog, m.my_vers, m.my_proc).into_bytes();
    if out.len() >= buflen {
        return None;
    }
    // Each "%02x" must fit with its NUL in what is left.
    for b in &m.priv_ {
        if out.len() + 2 >= buflen {
            return None;
        }
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    let tail = bfmt!(" {} {}\n", crate::xlog::c_str(&m.mon_name), crate::xlog::c_str(&m.my_name));
    if out.len() + tail.len() >= buflen {
        return None;
    }
    out.extend_from_slice(&tail);
    Some(out)
}

/// `nsm_append_monitored_host()`: rewrite `path` with `line` added. QUIRK: as C uses
/// `strcat()`, a NUL in the file puts the new line there, and the bytes after it are
/// written as zeros.
fn nsm_append_monitored_host(path: &[u8], line: &[u8]) -> bool {
    let Some(st) = sys::stat(path) else {
        xlog(L_ERROR, &bfmt!("Failed to insert: could not stat original file {}: {}", path, m()));
        return false;
    };
    let size = st.size.max(0) as usize;
    let buflen = size + line.len();
    let mut buf = vec![0u8; buflen + 1];
    let fd = sys::open(path, libc::O_RDONLY, 0);
    if fd == -1 {
        xlog(L_ERROR, &bfmt!("Failed to insert: could not open original file {}: {}", path, m()));
        return false;
    }
    let n = sys::read(fd, &mut buf[..size]);
    if n < 0 || n as usize != size {
        xlog(L_ERROR, &bfmt!("Failed to insert: could not read original file {}: {}", path, m()));
        sys::close(fd);
        return false;
    }
    sys::close(fd);
    let at = buf.iter().position(|&b| b == 0).unwrap_or(buflen);
    buf[at..at + line.len()].copy_from_slice(line);
    buf[at + line.len()] = 0;
    nsm_atomic_write(path, &buf[..buflen])
}

/// `nsm_insert_monitored_host()`: add a record for `hostname` (the callback address is
/// `s_addr`, as stored).
pub fn nsm_insert_monitored_host(hostname: &[u8], s_addr: u32, mon: &Mon) -> bool {
    let Some(path) = nsm_make_record_pathname(NSM_MONITOR_DIR, hostname) else {
        xlog(L_ERROR, &bfmt!("Failed to insert: bad monitor hostname '{}'", crate::xlog::c_str(hostname)));
        return false;
    };
    let Some(rec) = nsm_create_monitor_record(BUFLEN, s_addr, mon) else {
        xlog(L_ERROR, b"Failed to insert: record too long");
        return false;
    };
    let fd =
        sys::open(&path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_SYNC, libc::S_IRUSR | libc::S_IWUSR);
    if fd == -1 {
        if sys::errno() != libc::EEXIST {
            xlog(L_ERROR, &bfmt!("Failed to insert: creating {}: {}", path, m()));
            return false;
        }
        return nsm_append_monitored_host(&path, &rec);
    }
    let mut result = true;
    let len = sys::write(fd, &rec);
    if len < 0 || len as usize != rec.len() {
        xlog_warn(&bfmt!("Failed to insert: writing {}: {}", path, m()));
        sys::unlink(&path);
        result = false;
    }
    if sys::close(fd) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to insert: closing {}: {}", path, m()));
        sys::unlink(&path);
        result = false;
    }
    result
}

/// glibc `scanf`'s `%Nx` at `buf[*pos..]` (the string ends at the first NUL): skip white
/// space, an optional sign, an optional `0x`, then up to `width` (all of it counted)
/// hex digits. The value is `strtoul()`'s, truncated to `unsigned int`.
fn scan_hex(buf: &[u8], pos: &mut usize, width: usize) -> Option<u32> {
    let get = |i: usize| buf.get(i).copied().unwrap_or(0);
    while get(*pos) != 0 && sys::isspace(get(*pos)) {
        *pos += 1;
    }
    if get(*pos) == 0 {
        return None;
    }
    let mut width = width;
    let mut work = Vec::new();
    let mut c = get(*pos);
    if c == b'-' || c == b'+' {
        work.push(c);
        width -= 1;
        *pos += 1;
        c = get(*pos);
    }
    if width != 0 && c == b'0' {
        width -= 1;
        work.push(c);
        *pos += 1;
        c = get(*pos);
        if width != 0 && sys::tolower(c) == b'x' {
            width -= 1;
            *pos += 1;
            c = get(*pos);
        }
    }
    while c != 0 && width != 0 && c.is_ascii_hexdigit() {
        work.push(c);
        width -= 1;
        *pos += 1;
        c = get(*pos);
    }
    if work.is_empty() || (work.len() == 1 && (work[0] == b'+' || work[0] == b'-')) {
        return None;
    }
    let (v, _) = sys::strtoul(&work, 16);
    Some(v as u32)
}

/// `nsm_parse_line()` on a line buffer (as `fgets()` left it: the bytes after the line's
/// NUL are whatever an earlier line put there). QUIRK: the cookie is read from a fixed
/// offset, so a short line's cookie comes from those leftovers.
fn nsm_parse_line(buf: &mut [u8]) -> Option<(u32, Mon)> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if let Some(nl) = buf[..end].iter().position(|&b| b == b'\n') {
        buf[nl] = 0;
    }
    let mut pos = 0;
    let mut f = [0u32; 4];
    for (i, v) in f.iter_mut().enumerate() {
        if i > 0 {
            // The " " between conversions skips white space (the conversion would too).
        }
        *v = scan_hex(buf, &mut pos, 8)?;
    }
    let mut m = Mon { my_prog: f[1], my_vers: f[2], my_proc: f[3], ..Mon::default() };
    let mut c = RPCARGSLEN;
    for b in &mut m.priv_ {
        let mut p = c;
        *b = scan_hex(buf, &mut p, 2)? as u8;
        c += 2;
    }
    c += 1;
    let get = |b: &[u8], i: usize| b.get(i).copied().unwrap_or(0);
    let start = c;
    while get(buf, c) != 0 && get(buf, c) != b' ' {
        c += 1;
    }
    m.mon_name = buf[start.min(buf.len())..c.min(buf.len())].to_vec();
    if get(buf, c) != 0 {
        // *c++ = '\0': the NUL stays in the buffer for the next line to find.
        buf[c] = 0;
        c += 1;
    }
    while get(buf, c) == b' ' {
        c += 1;
    }
    m.my_name = crate::xlog::c_str(&buf[c.min(buf.len())..]).to_vec();
    Some((f[0], m))
}

/// `fgets(buf, buf.len(), f)` over `data` from `*off`: false at end of file.
fn fgets(buf: &mut [u8], data: &[u8], off: &mut usize) -> bool {
    if *off >= data.len() {
        return false;
    }
    let max = buf.len() - 1;
    let rest = &data[*off..];
    let n = match rest.iter().take(max).position(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => rest.len().min(max),
    };
    buf[..n].copy_from_slice(&rest[..n]);
    buf[n] = 0;
    *off += n;
    true
}

/// The contents of `path` as `fopen()` + `fgets()` see them, or `None` with `errno` set
/// when `fopen()` fails.
fn read_all(path: &[u8]) -> Option<Vec<u8>> {
    let fd = sys::open(path, libc::O_RDONLY, 0);
    if fd == -1 {
        return None;
    }
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        let n = sys::read(fd, &mut b);
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&b[..n as usize]);
    }
    sys::close(fd);
    Some(out)
}

/// What `nsm_load_*_list()` calls for each record: (hostname, callback address, record,
/// the file's mtime) → how many in-core entries it made.
pub type Populate<'a> = dyn FnMut(&[u8], u32, &Mon, i64) -> u32 + 'a;

/// `nsm_load_host()`.
fn nsm_load_host(directory: &[u8], filename: &[u8], func: &mut Populate<'_>) -> u32 {
    let mut result = 0;
    let Some(path) = nsm_make_record_pathname(directory, filename) else {
        return 0;
    };
    let Some(st) = sys::lstat(&path) else {
        xlog(L_ERROR, &bfmt!("Failed to stat {}: {}", path, m()));
        return 0;
    };
    if !st.is_reg() {
        xlog(D_GENERAL, &bfmt!("Skipping non-regular file {}", path));
        return 0;
    }
    let Some(data) = read_all(&path) else {
        xlog(L_ERROR, &bfmt!("Failed to open {}: {}", path, m()));
        return 0;
    };
    // QUIRK: C's buffer starts uninitialized; this one starts zeroed.
    let mut buf = vec![0u8; BUFLEN];
    let mut off = 0;
    while fgets(&mut buf, &data, &mut off) {
        buf[BUFLEN - 1] = 0;
        // nsm_parse_line() writes NULs into the buffer, which later lines see.
        if let Some((addr, mon)) = nsm_parse_line(&mut buf) {
            result += func(filename, addr, &mon, st.mtime);
        }
    }
    if result == 0 {
        xlog(L_ERROR, &bfmt!("Failed to read monitor data from {}", path));
    }
    result
}

/// `nsm_load_dir()`.
fn nsm_load_dir(directory: &[u8], func: &mut Populate<'_>) -> u32 {
    let mut count = 0;
    let Some(path) = nsm_make_pathname(directory) else {
        xlog(L_ERROR, &bfmt!("Failed to allocate path for directory {}", directory));
        return 0;
    };
    let Some(mut dir) = sys::Dir::open(&path) else {
        xlog(L_ERROR, &bfmt!("Failed to open directory {}: {}", directory, m()));
        return 0;
    };
    while let Some((name, _)) = dir.next_entry() {
        if name.first() == Some(&b'.') {
            continue;
        }
        count += nsm_load_host(directory, &name, func);
    }
    count
}

/// `nsm_load_monitor_list()`.
pub fn nsm_load_monitor_list(func: &mut Populate<'_>) -> u32 {
    nsm_load_dir(NSM_MONITOR_DIR, func)
}

/// `nsm_load_notify_list()`.
pub fn nsm_load_notify_list(func: &mut Populate<'_>) -> u32 {
    nsm_load_dir(NSM_NOTIFY_DIR, func)
}

/// `nsm_delete_host()`: rewrite the record file without the (mon_name, my_name) lines,
/// or remove it if none are left.
fn nsm_delete_host(directory: &[u8], hostname: &[u8], mon_name: &[u8], my_name: &[u8], chatty: bool) {
    let Some(path) = nsm_make_record_pathname(directory, hostname) else {
        xlog(L_ERROR, b"Bad filename, not deleting");
        return;
    };
    let Some(st) = sys::stat(&path) else {
        if chatty {
            xlog(L_ERROR, &bfmt!("Failed to delete: could not stat original file {}: {}", path, m()));
        }
        return;
    };
    let mut remaining = st.size.max(0) as usize + 1;
    let Some(data) = read_all(&path) else {
        xlog(L_ERROR, &bfmt!("Failed to delete: could not open original file {}: {}", path, m()));
        return;
    };
    let mut out: Vec<u8> = Vec::new();
    // QUIRK: as in nsm_load_host(), C's line buffer starts uninitialized.
    let mut line = vec![0u8; BUFLEN];
    let mut off = 0;
    while fgets(&mut line, &data, &mut off) {
        let Some((addr, mon)) = nsm_parse_line(&mut line) else {
            xlog(L_ERROR, &bfmt!("Failed to delete: could not parse original file {}", path));
            return;
        };
        if crate::xlog::c_str(mon_name) == &mon.mon_name[..] && crate::xlog::c_str(my_name) == &mon.my_name[..] {
            continue;
        }
        let Some(rec) = nsm_create_monitor_record(remaining, addr, &mon) else {
            xlog(L_ERROR, b"Failed to delete: could not construct output record");
            return;
        };
        remaining -= rec.len();
        out.extend_from_slice(&rec);
    }
    if !out.is_empty() {
        if !nsm_atomic_write(&path, &out) {
            xlog(L_ERROR, &bfmt!("Failed to delete: could not write new file {}: {}", path, m()));
        }
    } else if sys::unlink(&path) == -1 {
        xlog(L_ERROR, &bfmt!("Failed to delete: could not unlink file {}: {}", path, m()));
    }
}

/// `nsm_delete_monitored_host()`.
pub fn nsm_delete_monitored_host(hostname: &[u8], mon_name: &[u8], my_name: &[u8], chatty: bool) {
    nsm_delete_host(NSM_MONITOR_DIR, hostname, mon_name, my_name, chatty);
}

/// `nsm_delete_notified_host()`.
pub fn nsm_delete_notified_host(hostname: &[u8], mon_name: &[u8], my_name: &[u8]) {
    nsm_delete_host(NSM_NOTIFY_DIR, hostname, mon_name, my_name, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &[u8]) -> Option<(u32, Mon)> {
        let mut b = vec![0u8; BUFLEN];
        b[..s.len()].copy_from_slice(s);
        nsm_parse_line(&mut b)
    }

    #[test]
    fn record_round_trip() {
        let m = Mon {
            mon_name: b"peer".to_vec(),
            my_name: b"me".to_vec(),
            my_prog: 100021,
            my_vers: 4,
            my_proc: 16,
            priv_: [0xab; 16],
        };
        let rec = nsm_create_monitor_record(BUFLEN, 0x0100007f, &m).unwrap();
        assert_eq!(rec, b"0100007f 000186b5 00000004 00000010 abababababababababababababababab peer me\n".to_vec());
        assert_eq!(parse(&rec), Some((0x0100007f, m)));
    }

    #[test]
    fn scanf_hex_edges() {
        let h = |s: &[u8], w| {
            let mut p = 0;
            scan_hex(s, &mut p, w).map(|v| (v, p))
        };
        assert_eq!(h(b"  0x1f", 8), Some((0x1f, 6)));
        assert_eq!(h(b"0xzz", 8), Some((0, 2)));
        assert_eq!(h(b"-1", 8), Some((0xffff_ffff, 2)));
        assert_eq!(h(b"+", 8), None);
        assert_eq!(h(b"123456789", 8), Some((0x1234_5678, 8)));
        assert_eq!(h(b"g", 2), None);
        assert_eq!(h(b"0x", 2), Some((0, 2)));
    }
}
