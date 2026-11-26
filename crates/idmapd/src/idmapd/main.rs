//! rpc.idmapd from nfs-utils 2.8.5 (`utils/idmapd/idmapd.c`): the NFSv4 id-mapping
//! daemon.
//!
//! It answers two kinds of requests:
//!
//! - nfsd's, as text lines on `/proc/net/rpc/nfs4.nametoid/channel` and
//!   `nfs4.idtoname/channel` (an upcall in, a cache entry with an expiry time written
//!   back);
//! - the NFS client's, as binary `struct idmap_msg`s on the `idmap` pipe in each
//!   `clnt*` directory of `rpc_pipefs/nfs`, which it finds with inotify and rescans
//!   on `SIGUSR1`.
//!
//! The loop is libevent's ([`ev`]), with its descriptors and ordering. As in C, the
//! `SIGUSR1` event passes the signal number (10) where the scan expects the inotify
//! descriptor, so a rescan by signal reads from descriptor 10, whatever it is (see
//! QUIRKS.md).

mod ev;

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use support::bfmt;
use support::conffile::{conf_get_bool, conf_get_num, conf_get_str, conf_init_file};
use support::mydaemon::{daemon_init, daemon_ready};
use support::sys::{self, Fd};
use support::xlog::{c_str, xlog_err, xlog_open, xlog_warn};

use ev::{Base, Done, EV_READ, EvId};

const PATH_MAX: usize = 4096;
const PIPEFS_DIR: &[u8] = b"/var/lib/nfs/rpc_pipefs/";
const NFS_CONFFILE: &[u8] = b"/etc/nfs.conf";
const PATH_IDMAPDCONF: &[u8] = b"/etc/idmapd.conf";
const CLIENT_CACHE_TIMEOUT_FILE: &[u8] = b"/proc/sys/fs/nfs/idmap_cache_timeout";
const NFS4NOBODY_USER: &[u8] = b"nobody";
const NFS4NOBODY_GROUP: &[u8] = b"nobody";

const IC_IDNAME: usize = 0;
const IC_IDNAME_CHAN: &[u8] = b"/proc/net/rpc/nfs4.idtoname/channel";
const IC_IDNAME_FLUSH: &[u8] = b"/proc/net/rpc/nfs4.idtoname/flush";
const IC_NAMEID: usize = 1;
const IC_NAMEID_CHAN: &[u8] = b"/proc/net/rpc/nfs4.nametoid/channel";
const IC_NAMEID_FLUSH: &[u8] = b"/proc/net/rpc/nfs4.nametoid/flush";

const DEFAULT_IDMAP_CACHE_EXPIRY: i32 = 600;
const GETOPTSTR: &CStr = c"hvfd:p:U:G:c:CS";

// nfs_idmap.h
const IDMAP_NAMESZ: usize = 128;
const IDMAP_TYPE_USER: u8 = 0;
const IDMAP_TYPE_GROUP: u8 = 1;
const IDMAP_CONV_IDTONAME: u8 = 0;
const IDMAP_CONV_NAMETOID: u8 = 1;
const IDMAP_STATUS_INVALIDMSG: u8 = 0x01;
const IDMAP_STATUS_LOOKUPFAIL: u8 = 0x04;
const IDMAP_STATUS_SUCCESS: u8 = 0x08;
const IDMAP_MAXMSGSZ: usize = 256;

/// `struct idmap_msg` as bytes: `im_type` at 0, `im_conv` at 1, `im_name[128]` at 2,
/// `im_id` at 132 (after two bytes of padding), `im_status` at 136, three bytes of
/// padding: 140 bytes.
const MSG_SIZE: usize = 140;
const NAME_AT: usize = 2;
const ID_AT: usize = 132;
const STATUS_AT: usize = 136;

#[derive(Debug, Clone)]
struct Msg([u8; MSG_SIZE]);

impl Msg {
    fn ty(&self) -> u8 {
        self.0[0]
    }
    fn conv(&self) -> u8 {
        self.0[1]
    }
    fn id(&self) -> u32 {
        u32::from_ne_bytes(self.0[ID_AT..ID_AT + 4].try_into().unwrap())
    }
    fn set_id(&mut self, id: u32) {
        self.0[ID_AT..ID_AT + 4].copy_from_slice(&id.to_ne_bytes());
    }
    fn status(&self) -> u8 {
        self.0[STATUS_AT]
    }
    fn set_status(&mut self, s: u8) {
        self.0[STATUS_AT] = s;
    }
    /// `im_name[i]` (C reads past the array into the padding for `i == 128`).
    fn name_byte(&self, i: usize) -> u8 {
        self.0[NAME_AT + i]
    }
    /// `im_name` as a string: up to its NUL, which may be the padding after it.
    fn name(&self) -> &[u8] {
        c_str(&self.0[NAME_AT..])
    }
    /// `strcpy(im_name, s)`.
    fn set_name(&mut self, s: &[u8]) {
        self.0[NAME_AT..NAME_AT + s.len()].copy_from_slice(s);
        self.0[NAME_AT + s.len()] = 0;
    }
    fn type_str(&self) -> &'static [u8] {
        if self.ty() == IDMAP_TYPE_USER { b"user" } else { b"group" }
    }
}

/// `struct idmap_client`.
#[derive(Debug)]
struct Client {
    /// The key events refer to it by.
    key: usize,
    /// `ic_clid[30]`.
    clid: Vec<u8>,
    id: &'static [u8],
    path: Vec<u8>,
    fd: Fd,
    dirfd: Fd,
    scanned: bool,
    event: Option<EvId>,
}

/// What an event's callback is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    /// `nfsdcb` for `nfsd_ic[i]`.
    Nfsd(usize),
    /// `nfscb` for the client with this key.
    Client(usize),
    /// `dirscancb` (the `SIGUSR1` event, the inotify descriptor, the first scan).
    DirScan,
    /// `clntscancb` (`SIGUSR2`).
    ClntScan,
    /// `svrreopen` (`SIGHUP`).
    SvrReopen,
}

static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

/// `sig_die()`, for `SIGINT` and `SIGTERM`.
extern "C" fn sig_die(signal: libc::c_int) {
    if SIGNAL_RECEIVED.load(Relaxed) {
        xlog_warn(&bfmt!("forced exiting on signal {}\n", signal));
        sys::exit(0);
    }
    SIGNAL_RECEIVED.store(true, Relaxed);
    xlog_warn(&bfmt!("exiting on signal {}\n", signal));
    ev::loopexit();
}

/// `strlcpy(dst, src, size)`: `src` cut to `size - 1` bytes.
fn strlcpy(src: &[u8], size: usize) -> Vec<u8> {
    let s = c_str(src);
    s[..s.len().min(size - 1)].to_vec()
}

/// `atomicio(read or write, fd, buf, n)`.
fn atomicio(write: bool, fd: Fd, buf: &mut [u8]) -> isize {
    let n = buf.len();
    let mut pos = 0usize;
    while n > pos {
        let res = if write { sys::write(fd, &buf[pos..]) } else { sys::read(fd, &mut buf[pos..]) };
        match res {
            -1 => {
                let e = sys::errno();
                if e == libc::EINTR || e == libc::EAGAIN {
                    continue;
                }
                return if pos != 0 { pos as isize } else { -1 };
            }
            0 => return if pos != 0 { pos as isize } else { 0 },
            r => pos += r as usize,
        }
    }
    pos as isize
}

/// `flush_nfsd_cache()`.
fn flush_nfsd_cache(path: &[u8], now: i64) -> i32 {
    let stime = bfmt!("{}\n", now);
    let fd = sys::open(path, libc::O_RDWR, 0);
    if fd == -1 {
        return -1;
    }
    if sys::write(fd, &stime) != stime.len() as isize {
        let e = sys::errno();
        sys::errx_msg(1, &bfmt!("Flushing nfsd cache failed: errno {} ({})", e, sys::strerror(e)));
    }
    sys::close(fd);
    0
}

/// `flush_nfsd_idmap_cache()`.
fn flush_nfsd_idmap_cache() -> i32 {
    let now = sys::time();
    let ret = flush_nfsd_cache(IC_IDNAME_FLUSH, now);
    if ret != 0 {
        return ret;
    }
    flush_nfsd_cache(IC_NAMEID_FLUSH, now)
}

/// `usage()`: with POSIX `basename()`, an empty name is `.`.
fn usage(progname: &[u8]) {
    let base: &[u8] = if progname.is_empty() { b"." } else { progname };
    sys::stderr(&bfmt!("Usage: {} [-hfvCS] [-p path] [-c path]\n", base));
}

/// The daemon's state: `main()`'s locals and the file's statics.
struct Idmapd {
    base: Base<Tok>,
    verbose: i32,
    cache_entry_expiration: i32,
    pipefsdir: Vec<u8>,
    nobodyuser: Vec<u8>,
    nobodygroup: Vec<u8>,
    nobodyuid: u32,
    nobodygid: u32,
    inotify_fd: Fd,
    nfsd_ic: [Client; 2],
    /// `icq`, in order.
    icq: Vec<Client>,
    next_key: usize,
}

fn main() {
    let mut args = sys::Args::from_env();
    let mut nobodyuser = NFS4NOBODY_USER.to_vec();
    let mut nobodygroup = NFS4NOBODY_GROUP.to_vec();
    let mut pipefsdir = PIPEFS_DIR.to_vec();
    let mut verbose = 0;
    let mut cache_entry_expiration = 0;
    let mut fg = false;
    let (mut serverstart, mut clientstart) = (true, true);

    let argv0 = args.argv0();
    let progname = match argv0.iter().rposition(|&b| b == b'/') {
        Some(p) => argv0[p + 1..].to_vec(),
        None => argv0.clone(),
    };
    xlog_open(&progname);

    sys::set_opterr(0);
    let mut conf_path: Option<Vec<u8>> = None;
    loop {
        let (opt, optarg) = args.getopt(GETOPTSTR);
        if opt == -1 {
            break;
        }
        if opt == i32::from(b'c') {
            sys::warnx_msg(b"-c is deprecated and may be removed in the future.  See idmapd(8).");
            conf_path = optarg;
        }
        if opt == i32::from(b'?') {
            let o = sys::optopt();
            let oc = [o as u8];
            // strchr(GETOPTSTR, optopt), which finds the terminating NUL too.
            if o == 0 || GETOPTSTR.to_bytes().contains(&(o as u8)) {
                sys::warnx_msg(&bfmt!("'-{}' option requires an argument.", oc.as_slice()));
            } else {
                sys::warnx_msg(&bfmt!("'-{}' is an invalid argument.", oc.as_slice()));
            }
            usage(&progname);
            sys::exit(1);
        }
    }
    sys::set_optind(1);

    if let Some(cp) = conf_path.clone() {
        // The deprecated -c.
        if sys::stat(&cp).is_none() && matches!(sys::errno(), libc::ENOENT | libc::EACCES) {
            sys::warn_msg(&bfmt!("Skipping configuration file \"{}\"", cp));
            conf_path = None;
        } else {
            conf_init_file(Some(&cp));
            verbose = conf_get_num(b"General", b"Verbosity", 0);
            cache_entry_expiration = conf_get_num(b"General", b"Cache-Expiration", DEFAULT_IDMAP_CACHE_EXPIRY);
            if let Some(x) = conf_get_str(b"General", b"Pipefs-Directory") {
                pipefsdir = strlcpy(&x, PATH_MAX);
            }
            if let Some(u) = conf_get_str(b"Mapping", b"Nobody-User") {
                nobodyuser = u;
            }
            if let Some(g) = conf_get_str(b"Mapping", b"Nobody-Group") {
                nobodygroup = g;
            }
            if conf_get_bool(b"General", b"server-only", false) {
                clientstart = false;
            }
            if conf_get_bool(b"General", b"client-only", false) {
                serverstart = false;
            }
        }
    } else {
        conf_init_file(Some(NFS_CONFFILE));
        if let Some(x) = conf_get_str(b"General", b"Pipefs-Directory") {
            pipefsdir = strlcpy(&x, PATH_MAX);
        }
        conf_path = Some(PATH_IDMAPDCONF.to_vec());
        conf_init_file(Some(PATH_IDMAPDCONF));
        verbose = conf_get_num(b"General", b"Verbosity", 0);
        cache_entry_expiration = conf_get_num(b"General", b"cache-expiration", DEFAULT_IDMAP_CACHE_EXPIRY);
        if let Some(u) = conf_get_str(b"Mapping", b"Nobody-User") {
            nobodyuser = u;
        }
        if let Some(g) = conf_get_str(b"Mapping", b"Nobody-Group") {
            nobodygroup = g;
        }
        if conf_get_bool(b"General", b"server-only", false) {
            clientstart = false;
        }
        if conf_get_bool(b"General", b"client-only", false) {
            serverstart = false;
        }
    }

    loop {
        let (opt, optarg) = args.getopt(GETOPTSTR);
        if opt == -1 {
            break;
        }
        match opt as u8 {
            b'v' => verbose += 1,
            b'f' => fg = true,
            b'p' => pipefsdir = strlcpy(&optarg.unwrap_or_default(), PATH_MAX),
            b'd' | b'U' | b'G' => sys::errx_msg(
                1,
                b"the -d, -U, and -G options have been removed; please use the configuration file instead.",
            ),
            b'C' => serverstart = false,
            b'S' => clientstart = false,
            b'h' => {
                usage(&progname);
                sys::exit(0);
            }
            _ => {}
        }
    }

    if !serverstart && !clientstart {
        sys::errx_msg(1, b"it is illegal to specify both -C and -S");
    }

    // strncat(pipefsdir, "/nfs", sizeof(pipefsdir)-1), which doesn't check for room:
    // the fortified build (__strcat_chk) aborts when it doesn't fit.
    if pipefsdir.len() + b"/nfs".len() + 1 > PATH_MAX {
        sys::chk_fail();
    }
    pipefsdir.extend_from_slice(b"/nfs");

    daemon_init(fg);

    let Some(nobodyuid) = sys::getpwnam_uid(&nobodyuser) else {
        sys::errx_msg(1, &bfmt!("Could not find user \"{}\"", nobodyuser));
    };
    let Some(nobodygid) = sys::getgrnam_gid(&nobodygroup) else {
        sys::errx_msg(1, &bfmt!("Could not find group \"{}\"", nobodygroup));
    };

    nfsidmap::nfs4_set_debug(verbose, Some(xlog_warn));
    let conf_path = conf_path.unwrap_or_else(|| PATH_IDMAPDCONF.to_vec());
    if nfsidmap::nfs4_init_name_mapping(Some(&conf_path)) != 0 {
        sys::errx_msg(1, b"Unable to create name to user id mappings.");
    }

    let base = Base::new();
    let server = |path: &[u8]| Client {
        key: usize::MAX,
        clid: Vec::new(),
        id: b"Server",
        path: path.to_vec(),
        fd: -1,
        dirfd: -1,
        scanned: false,
        event: None,
    };
    let mut d = Idmapd {
        base,
        verbose,
        cache_entry_expiration,
        pipefsdir,
        nobodyuser,
        nobodygroup,
        nobodyuid,
        nobodygid,
        inotify_fd: -1,
        nfsd_ic: [server(IC_IDNAME_CHAN), server(IC_NAMEID_CHAN)],
        icq: Vec::new(),
        next_key: 0,
    };

    if d.verbose > 1 {
        xlog_warn(&bfmt!("Expiration time is {} seconds.", d.cache_entry_expiration));
    }
    let mut nfsdret = -1;
    if serverstart {
        nfsdret = d.nfsdopen();
        if nfsdret == 0 && flush_nfsd_idmap_cache() != 0 {
            xlog_err(&bfmt!("main: Failed to flush nfsd idmap cache\n: {}", sys::strerror(sys::errno())));
        }
    }

    let mut wd = -1;
    if clientstart {
        if d.cache_entry_expiration != DEFAULT_IDMAP_CACHE_EXPIRY {
            d.set_client_cache_timeout();
        }
        d.inotify_fd = sys::inotify_init1(libc::IN_NONBLOCK);
        if d.inotify_fd == -1 {
            xlog_err(&bfmt!("Unable to initialise inotify_init1: {}\n", sys::strerror(sys::errno())));
        }
        wd = sys::inotify_add_watch(d.inotify_fd, &d.pipefsdir, libc::IN_CREATE | libc::IN_DELETE);
        if wd < 0 {
            xlog_err(&bfmt!("Unable to inotify_add_watch({}): {}\n", d.pipefsdir, sys::strerror(sys::errno())));
        }

        sys::signal(libc::SIGINT, sys::Handler::Func(sig_die));
        sys::signal(libc::SIGTERM, sys::Handler::Func(sig_die));

        for (sig, tok) in
            [(libc::SIGUSR1, Tok::DirScan), (libc::SIGUSR2, Tok::ClntScan), (libc::SIGHUP, Tok::SvrReopen)]
        {
            let e = d.base.new_signal(sig, tok);
            d.base.add(e);
        }
        if wd >= 0 {
            let e = d.base.new_read(d.inotify_fd, Tok::DirScan);
            d.base.add(e);
        }
        // The first scan, from the loop (a SIGUSR1 before it would be lost).
        let e = d.base.new_timer(Tok::DirScan);
        d.base.add(e);
    }

    if nfsdret != 0 && wd < 0 {
        xlog_err(b"main: Neither NFS client nor NFSd found");
    }

    daemon_ready();

    let done = loop {
        if let Some(done) = d.base.wait() {
            break done;
        }
        while let Some((tok, fd, res)) = d.base.next() {
            d.callback(tok, fd, res);
        }
    };
    if done == Done::Failed {
        let e = sys::errno();
        xlog_err(&bfmt!("main: event_dispatch returns errno {} ({})", e, sys::strerror(e)));
    }

    nfsidmap::nfs4_term_name_mapping();
    d.nfsdclose();
    sys::exit(0);
}

impl Idmapd {
    fn callback(&mut self, tok: Tok, fd: Fd, res: i16) {
        match tok {
            Tok::Nfsd(i) => {
                if res == EV_READ {
                    self.nfsdcb(i);
                }
            }
            Tok::Client(key) => {
                if res == EV_READ {
                    self.nfscb(key);
                }
            }
            Tok::DirScan => self.dirscancb(fd),
            Tok::ClntScan => self.clntscancb(),
            Tok::SvrReopen => self.nfsdreopen(),
        }
    }

    /// The client cache expiry, when it isn't the default.
    fn set_client_cache_timeout(&self) {
        let fd = sys::open(CLIENT_CACHE_TIMEOUT_FILE, libc::O_RDWR, 0);
        if fd == -1 {
            xlog_warn(&bfmt!(
                "Unable to open '{}' to set client cache expiration time to {} seconds\n",
                CLIENT_CACHE_TIMEOUT_FILE,
                self.cache_entry_expiration
            ));
            return;
        }
        let buf = bfmt!("{}", self.cache_entry_expiration);
        if sys::write(fd, &buf) != buf.len() as isize {
            xlog_warn(&bfmt!(
                "Error writing '{}' to '{}' to set client cache expiration time\n",
                buf,
                CLIENT_CACHE_TIMEOUT_FILE
            ));
        }
        sys::close(fd);
    }

    /// `flush_inotify()`: read the descriptor dry, logging what it parses as inotify
    /// events.
    fn flush_inotify(&self, fd: Fd) {
        loop {
            let mut buf = vec![0u8; 4096];
            let len = sys::read(fd, &mut buf);
            if len == -1 && sys::errno() == libc::EINTR {
                continue;
            }
            if len <= 0 {
                break;
            }
            let len = len as usize;
            let mut ptr = 0usize;
            while ptr < len {
                let word = |at: usize| {
                    let mut w = [0u8; 4];
                    for (i, b) in w.iter_mut().enumerate() {
                        *b = buf.get(ptr + at + i).copied().unwrap_or(0);
                    }
                    u32::from_ne_bytes(w)
                };
                let (wd, mask, evlen) = (word(0) as i32, word(4), word(12));
                if self.verbose > 2 {
                    let name: &[u8] = if evlen != 0 { c_str(buf.get(ptr + 16..).unwrap_or(&[])) } else { b"" };
                    xlog_warn(&bfmt!(
                        "pipefs inotify: wd={}, mask=0x{}, len={}, name={}",
                        wd,
                        format!("{mask:08x}"),
                        evlen as i32,
                        name
                    ));
                }
                ptr = ptr.saturating_add(16).saturating_add(evlen as usize);
            }
        }
    }

    /// `dirscancb()`: find new `clnt*` directories and drop the ones that went away.
    fn dirscancb(&mut self, fd: Fd) {
        if fd != -1 {
            self.flush_inotify(fd);
        }
        for ic in &mut self.icq {
            ic.scanned = false;
        }
        let ents = match sys::scandir_alphasort(&self.pipefsdir) {
            Ok(e) => e,
            Err(e) => {
                xlog_warn(&bfmt!("dirscancb: scandir({}): {}", self.pipefsdir, sys::strerror(e)));
                return;
            }
        };
        for name in &ents {
            // d_reclen > 4 always holds.
            if !name.starts_with(b"clnt") {
                continue;
            }
            let rest = &name[4..];
            if let Some(ic) = self.icq.iter_mut().find(|ic| ic.clid == rest) {
                ic.scanned = true;
                continue;
            }
            // char path[PATH_MAX+256], snprintf'ed.
            let mut path = bfmt!("{}/{}", self.pipefsdir, name.as_slice());
            path.truncate(PATH_MAX + 255);
            let dirfd = sys::open(&path, libc::O_RDONLY, 0);
            if dirfd == -1 {
                if self.verbose > 0 {
                    xlog_warn(&bfmt!("dirscancb: open({}): {}", path, sys::strerror(sys::errno())));
                }
                // goto out: no stale-client pass.
                return;
            }
            path.extend_from_slice(b"/idmap");
            path.truncate(PATH_MAX + 255);
            let key = self.next_key;
            self.next_key += 1;
            let mut ic = Client {
                key,
                clid: strlcpy(rest, 30),
                id: b"",
                path: strlcpy(&path, PATH_MAX),
                fd: 0,
                dirfd,
                scanned: false,
                event: None,
            };
            if self.nfsopen(&mut ic) == -1 {
                sys::close(ic.dirfd);
                continue;
            }
            if self.verbose > 2 {
                xlog_warn(&bfmt!("New client: {}", ic.clid));
            }
            ic.id = b"Client";
            ic.scanned = true;
            self.icq.push(ic);
        }
        let mut i = 0;
        while i < self.icq.len() {
            if self.icq[i].scanned {
                i += 1;
                continue;
            }
            let ic = self.icq.remove(i);
            if let Some(e) = ic.event {
                self.base.free(e);
            }
            if ic.fd != -1 {
                sys::close(ic.fd);
            }
            if ic.dirfd != -1 {
                sys::close(ic.dirfd);
            }
            if self.verbose > 2 {
                xlog_warn(&bfmt!("Stale client: {}", ic.clid));
                xlog_warn(&bfmt!("\t-> closed {}", ic.path));
            }
        }
    }

    /// `clntscancb()`: reopen clients whose pipe is closed (none ever is).
    fn clntscancb(&mut self) {
        let mut i = 0;
        while i < self.icq.len() {
            if self.icq[i].fd == -1 {
                let mut ic = self.icq.remove(i);
                if self.nfsopen(&mut ic) == -1 {
                    sys::close(ic.dirfd);
                    continue;
                }
                self.icq.insert(i, ic);
            }
            i += 1;
        }
    }

    /// `nfsdcb()`: one upcall from nfsd, answered with a cache entry.
    fn nfsdcb(&mut self, which: usize) {
        let mut buf = [0u8; IDMAP_MAXMSGSZ + 1];
        let fd = self.nfsd_ic[which].fd;
        let len = sys::read(fd, &mut buf);
        if len == 0 {
            // No upcall to read; not necessarily a problem.
            return;
        }
        if len < 0 {
            let e = sys::errno();
            xlog_warn(&bfmt!("nfsdcb: read({}) failed: errno {} ({})", self.nfsd_ic[which].path, e, sys::strerror(e)));
            self.nfsdreopen_one(which);
            return;
        }
        buf[len as usize - 1] = 0;
        let mut bp = Some(0usize);
        let mut im = Msg([0u8; MSG_SIZE]);

        let Some(authbuf) = getfield(&mut buf, &mut bp, IDMAP_MAXMSGSZ) else {
            xlog_warn(b"nfsdcb: bad authentication name in upcall\n");
            return;
        };
        let Some(typebuf) = getfield(&mut buf, &mut bp, IDMAP_MAXMSGSZ) else {
            xlog_warn(b"nfsdcb: bad type in upcall\n");
            return;
        };
        let (authbuf, typebuf) = (c_str(&authbuf).to_vec(), c_str(&typebuf).to_vec());
        if self.verbose > 2 {
            xlog_warn(&bfmt!("nfsdcb: authbuf={} authtype={}", authbuf, typebuf));
        }
        im.0[0] = if typebuf == b"user" { IDMAP_TYPE_USER } else { IDMAP_TYPE_GROUP };

        match which {
            IC_NAMEID => {
                im.0[1] = IDMAP_CONV_NAMETOID;
                let Some(name) = getfield(&mut buf, &mut bp, IDMAP_NAMESZ) else {
                    xlog_warn(b"nfsdcb: bad name in upcall\n");
                    return;
                };
                im.0[NAME_AT..NAME_AT + name.len()].copy_from_slice(&name);
            }
            _ => {
                im.0[1] = IDMAP_CONV_IDTONAME;
                let Some(buf1) = getfield(&mut buf, &mut bp, IDMAP_MAXMSGSZ) else {
                    xlog_warn(b"nfsdcb: bad id in upcall\n");
                    return;
                };
                let (tmp, _) = sys::strtoul_errno(&buf1);
                im.set_id(tmp as u32);
                if tmp > u64::from(u32::MAX) {
                    xlog_warn(&bfmt!("nfsdcb: id '{}' too big!\n", c_str(&buf1)));
                    return;
                }
            }
        }

        let (id, clid) = (self.nfsd_ic[which].id, self.nfsd_ic[which].clid.clone());
        self.imconv(id, &clid, &mut im);

        let mut out = [0u8; IDMAP_MAXMSGSZ + 1];
        let mut bp = 0usize;
        let mut bsiz = out.len() as isize;
        addfield(&mut out, &mut bp, &mut bsiz, &authbuf);
        let expiry = bfmt!("{}", sys::time() + i64::from(self.cache_entry_expiration));
        let ty = im.type_str();
        match which {
            IC_NAMEID => {
                addfield(&mut out, &mut bp, &mut bsiz, ty);
                addfield(&mut out, &mut bp, &mut bsiz, im.name());
                addfield(&mut out, &mut bp, &mut bsiz, &expiry);
                // No id when the mapping failed: a negative cache entry, so an unknown
                // user gets an error rather than nobody's permissions.
                if im.status() == IDMAP_STATUS_SUCCESS {
                    addfield(&mut out, &mut bp, &mut bsiz, &bfmt!("{}", im.id()));
                }
            }
            _ => {
                addfield(&mut out, &mut bp, &mut bsiz, ty);
                addfield(&mut out, &mut bp, &mut bsiz, &bfmt!("{}", im.id()));
                addfield(&mut out, &mut bp, &mut bsiz, &expiry);
                // The status is ignored: a failed mapping is nobody.
                addfield(&mut out, &mut bp, &mut bsiz, im.name());
            }
        }
        // bp[-1] = '\n'. (At least the first field always fits.)
        if bp > 0 {
            out[bp - 1] = b'\n';
        }
        let n = out.len() - bsiz as usize;
        if atomicio(true, fd, &mut out[..n]) != n as isize {
            let e = sys::errno();
            xlog_warn(&bfmt!("nfsdcb: write({}) failed: errno {} ({})", self.nfsd_ic[which].path, e, sys::strerror(e)));
        }
    }

    /// `imconv()`.
    fn imconv(&self, ic_id: &[u8], ic_clid: &[u8], im: &mut Msg) {
        match im.conv() {
            IDMAP_CONV_IDTONAME => {
                self.idtonameres(im);
                if self.verbose > 1 {
                    xlog_warn(&bfmt!(
                        "{} {}: ({}) id \"{}\" -> name \"{}\"",
                        ic_id,
                        ic_clid,
                        im.type_str(),
                        im.id() as i32,
                        im.name()
                    ));
                }
            }
            IDMAP_CONV_NAMETOID => {
                let len = (0..IDMAP_NAMESZ - 1).find(|&i| im.name_byte(i) == 0).unwrap_or(IDMAP_NAMESZ - 1);
                // "Check for NULL termination just to be careful": the byte after it.
                if im.name_byte(len + 1) != 0 {
                    return;
                }
                self.nametoidres(im);
                if self.verbose > 1 {
                    xlog_warn(&bfmt!(
                        "{} {}: ({}) name \"{}\" -> id \"{}\"",
                        ic_id,
                        ic_clid,
                        im.type_str(),
                        im.name(),
                        im.id() as i32
                    ));
                }
            }
            c => {
                xlog_warn(&bfmt!("imconv: Invalid conversion type ({}) in message", i32::from(c)));
                im.set_status(im.status() | IDMAP_STATUS_INVALIDMSG);
            }
        }
    }

    /// `nfscb()`: one request from the NFS client, answered in place.
    fn nfscb(&mut self, key: usize) {
        let Some(ic) = self.icq.iter().find(|c| c.key == key) else { return };
        let (fd, path, id, clid) = (ic.fd, ic.path.clone(), ic.id, ic.clid.clone());
        let mut im = Msg([0u8; MSG_SIZE]);
        if atomicio(false, fd, &mut im.0) != MSG_SIZE as isize {
            if self.verbose > 0 {
                xlog_warn(&bfmt!("nfscb: read({}): {}", path, sys::strerror(sys::errno())));
            }
            return;
        }
        self.imconv(id, &clid, &mut im);
        // Never returned as an error to the client (an XXX in C).
        if im.status() == IDMAP_STATUS_LOOKUPFAIL {
            im.set_status(IDMAP_STATUS_SUCCESS);
        }
        if atomicio(true, fd, &mut im.0) != MSG_SIZE as isize {
            xlog_warn(&bfmt!("nfscb: write({}): {}", path, sys::strerror(sys::errno())));
        }
    }

    /// `nfsdclose_one()`.
    fn nfsdclose_one(&mut self, which: usize) {
        if let Some(e) = self.nfsd_ic[which].event.take() {
            self.base.free(e);
        }
        if self.nfsd_ic[which].fd != -1 {
            sys::close(self.nfsd_ic[which].fd);
            self.nfsd_ic[which].fd = -1;
        }
    }

    /// `nfsdreopen_one()`: a new descriptor first, then the old one closed.
    fn nfsdreopen_one(&mut self, which: usize) {
        if self.verbose > 2 {
            xlog_warn(&bfmt!("ReOpening {}", self.nfsd_ic[which].path));
        }
        let fd = sys::open(&self.nfsd_ic[which].path, libc::O_RDWR, 0);
        if fd != -1 {
            self.nfsdclose_one(which);
            self.nfsd_ic[which].fd = fd;
            let e = self.base.new_read(fd, Tok::Nfsd(which));
            self.nfsd_ic[which].event = Some(e);
            self.base.add(e);
        } else {
            let e = sys::errno();
            xlog_warn(&bfmt!(
                "nfsdreopen: Opening '{}' failed: errno {} ({})",
                self.nfsd_ic[which].path,
                e,
                sys::strerror(e)
            ));
        }
    }

    /// `nfsdreopen()`, on `SIGHUP`.
    fn nfsdreopen(&mut self) {
        self.nfsdreopen_one(IC_NAMEID);
        self.nfsdreopen_one(IC_IDNAME);
    }

    /// `nfsdopen()`: name-to-id first; id-to-name only if that opened.
    fn nfsdopen(&mut self) -> i32 {
        if self.nfsdopenone(IC_NAMEID) == 0 && self.nfsdopenone(IC_IDNAME) == 0 { 0 } else { -1 }
    }

    /// `nfsdclose()`.
    fn nfsdclose(&mut self) {
        self.nfsdclose_one(IC_NAMEID);
        self.nfsdclose_one(IC_IDNAME);
    }

    /// `nfsdopenone()`.
    fn nfsdopenone(&mut self, which: usize) -> i32 {
        let fd = sys::open(&self.nfsd_ic[which].path, libc::O_RDWR, 0);
        self.nfsd_ic[which].fd = fd;
        if fd == -1 {
            if self.verbose > 0 {
                let e = sys::errno();
                xlog_warn(&bfmt!(
                    "nfsdopenone: Opening {} failed: errno {} ({})",
                    self.nfsd_ic[which].path,
                    e,
                    sys::strerror(e)
                ));
            }
            return -1;
        }
        let e = self.base.new_read(fd, Tok::Nfsd(which));
        self.nfsd_ic[which].event = Some(e);
        self.base.add(e);
        if self.verbose > 2 {
            xlog_warn(&bfmt!("Opened {}", self.nfsd_ic[which].path));
        }
        0
    }

    /// `nfsopen()`: a client's pipe; when it isn't there yet, a one-shot watch on its
    /// directory.
    fn nfsopen(&mut self, ic: &mut Client) -> i32 {
        ic.fd = sys::open(&ic.path, libc::O_RDWR, 0);
        if ic.fd == -1 {
            if sys::errno() == libc::ENOENT {
                let Some(slash) = ic.path.iter().rposition(|&b| b == b'/') else { return -1 };
                sys::inotify_add_watch(
                    self.inotify_fd,
                    &ic.path[..slash],
                    libc::IN_CREATE | libc::IN_ONLYDIR | libc::IN_ONESHOT,
                );
                if self.verbose > 2 {
                    xlog_warn(&bfmt!("Path {} not available. waiting...", ic.path));
                }
                return -1;
            }
            xlog_warn(&bfmt!("nfsopen: open({}): {}", ic.path, sys::strerror(sys::errno())));
            return -1;
        }
        let e = self.base.new_read(ic.fd, Tok::Client(ic.key));
        ic.event = Some(e);
        self.base.add(e);
        if self.verbose > 2 {
            xlog_warn(&bfmt!("Opened {}", ic.path));
        }
        0
    }

    /// `idtonameres()`.
    fn idtonameres(&self, im: &mut Msg) {
        let mut domain = Vec::new();
        let mut ret = nfsidmap::nfs4_get_default_domain(None, &mut domain, nfsidmap::NFS4_MAX_DOMAIN_LEN);
        let mut name = Vec::new();
        match im.ty() {
            IDMAP_TYPE_USER => {
                ret = nfsidmap::nfs4_uid_to_name(im.id(), Some(&domain), &mut name, IDMAP_NAMESZ);
                if ret != 0 {
                    name = if self.nobodyuser.len() < IDMAP_NAMESZ {
                        self.nobodyuser.clone()
                    } else {
                        NFS4NOBODY_USER.to_vec()
                    };
                }
                im.set_name(&name);
            }
            IDMAP_TYPE_GROUP => {
                ret = nfsidmap::nfs4_gid_to_name(im.id(), Some(&domain), &mut name, IDMAP_NAMESZ);
                if ret != 0 {
                    name = if self.nobodygroup.len() < IDMAP_NAMESZ {
                        self.nobodygroup.clone()
                    } else {
                        NFS4NOBODY_GROUP.to_vec()
                    };
                }
                im.set_name(&name);
            }
            _ => {}
        }
        im.set_status(if ret != 0 { IDMAP_STATUS_LOOKUPFAIL } else { IDMAP_STATUS_SUCCESS });
    }

    /// `nametoidres()`.
    fn nametoidres(&self, im: &mut Msg) {
        im.set_status(IDMAP_STATUS_SUCCESS);
        let name = im.name().to_vec();
        match im.ty() {
            IDMAP_TYPE_USER => {
                let mut uid = 0;
                let ret = nfsidmap::nfs4_name_to_uid(&name, &mut uid);
                im.set_id(uid);
                if ret != 0 {
                    im.set_status(IDMAP_STATUS_LOOKUPFAIL);
                    im.set_id(self.nobodyuid);
                }
            }
            IDMAP_TYPE_GROUP => {
                let mut gid = 0;
                let ret = nfsidmap::nfs4_name_to_gid(&name, &mut gid);
                im.set_id(gid);
                if ret != 0 {
                    im.set_status(IDMAP_STATUS_LOOKUPFAIL);
                    im.set_id(self.nobodygid);
                }
            }
            _ => {}
        }
    }
}

/// `strsep(bpp, " ")` over `buf`, a C string from `*bpp`: the token's start; the
/// space after it becomes a NUL.
fn strsep(buf: &mut [u8], bpp: &mut Option<usize>) -> Option<usize> {
    let start = (*bpp)?;
    let mut i = start;
    loop {
        match buf.get(i).copied().unwrap_or(0) {
            0 => {
                *bpp = None;
                return Some(start);
            }
            b' ' => {
                buf[i] = 0;
                *bpp = Some(i + 1);
                return Some(start);
            }
            _ => i += 1,
        }
    }
}

/// `getfield()`: the next space-separated field, with `\ooo` escapes decoded, at most
/// `fldsz - 1` bytes (`None` for C's -1). An escape always moves on four bytes, even
/// when `sscanf()` took fewer digits: past the field's end, into the next one.
fn getfield(buf: &mut [u8], bpp: &mut Option<usize>, fldsz: usize) -> Option<Vec<u8>> {
    let at = |buf: &[u8], i: usize| buf.get(i).copied().unwrap_or(0);
    let bp = loop {
        match strsep(buf, bpp) {
            Some(i) if at(buf, i) == 0 => continue,
            other => break other,
        }
    };
    let mut p = bp?;
    if at(buf, p) == 0 || at(buf, p) == b'\n' {
        return None;
    }
    let mut fld = Vec::new();
    let mut fldsz = fldsz;
    while at(buf, p) != 0 && fldsz > 1 {
        if at(buf, p) == b'\\' {
            let (n, val) = sys::scan_escape(buf.get(p..).unwrap_or(&[]), 0);
            if n != 1 || val > u32::from(u8::MAX) {
                return None;
            }
            fld.push(val as u8);
            p += 4;
        } else {
            fld.push(at(buf, p));
            p += 1;
        }
        fldsz -= 1;
    }
    if at(buf, p) != 0 {
        return None;
    }
    Some(fld)
}

/// `addfield()`: `fld` (a C string) with spaces, tabs, newlines and backslashes as
/// `\ooo`, then a space. -1 when it doesn't fit; `*bp` and `*bsiz` then stay where
/// they were, though part of it was written.
fn addfield(buf: &mut [u8], bp: &mut usize, bsiz: &mut isize, fld: &[u8]) -> i32 {
    let fld = c_str(fld);
    let (mut p, mut b) = (*bp, *bsiz);
    let mut i = 0;
    let mut ch;
    loop {
        ch = fld.get(i).copied().unwrap_or(0);
        i += 1;
        if ch == 0 || b <= 0 {
            break;
        }
        match ch {
            b' ' | b'\t' | b'\n' | b'\\' => {
                if b >= 4 {
                    // snprintf(bp, bsiz, "\\%03o", ch): four characters, or three and
                    // the NUL when bsiz is 4; it returns 4 either way.
                    let s = format!("\\{ch:03o}");
                    let room = (b as usize - 1).min(4);
                    buf[p..p + room].copy_from_slice(&s.as_bytes()[..room]);
                    buf[p + room] = 0;
                    p += 4;
                    b -= 4;
                }
            }
            _ => {
                buf[p] = ch;
                p += 1;
                b -= 1;
            }
        }
    }
    if b < 1 || ch != 0 {
        return -1;
    }
    buf[p] = b' ';
    p += 1;
    b -= 1;
    *bp = p;
    *bsiz = b;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(s: &[u8], sizes: &[usize]) -> Vec<Option<Vec<u8>>> {
        let mut buf = s.to_vec();
        buf.push(0);
        let mut bp = Some(0);
        sizes.iter().map(|&n| getfield(&mut buf, &mut bp, n)).collect()
    }

    #[test]
    fn getfield_escapes() {
        let f = fields(b"a\\040b  user x", &[256, 256, 256]);
        assert_eq!(f, vec![Some(b"a b".to_vec()), Some(b"user".to_vec()), Some(b"x".to_vec())]);
        // A short escape still moves on four bytes, into the next field.
        let f = fields(b"a\\7 bc", &[256, 256]);
        assert_eq!(f, vec![Some(b"a\x07c".to_vec()), Some(b"bc".to_vec())]);
        assert_eq!(fields(b"\\400", &[256]), vec![None]);
        assert_eq!(fields(b"abcd", &[4]), vec![None]);
        assert_eq!(fields(b"abc", &[4]), vec![Some(b"abc".to_vec())]);
    }

    #[test]
    fn addfield_room() {
        let mut buf = [0u8; 12];
        let (mut bp, mut bsiz) = (0, 12isize);
        assert_eq!(addfield(&mut buf, &mut bp, &mut bsiz, b"a b"), 0);
        assert_eq!(&buf[..bp], b"a\\040b ");
        assert_eq!(addfield(&mut buf, &mut bp, &mut bsiz, b"cdefg"), -1);
        assert_eq!((bp, bsiz), (7, 5));
        assert_eq!(addfield(&mut buf, &mut bp, &mut bsiz, b"cdef"), 0);
        assert_eq!(bsiz, 0);
    }
}
