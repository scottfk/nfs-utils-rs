//! rpc.statd: the NSM status monitor, a port of nfs-utils 2.8.5's `utils/statd/statd.c`
//! and `svc_run.c`, with the rest of `utils/statd` in the submodules.
//!
//! lockd asks statd (`SM_MON`, over loopback) to watch a peer; statd records it in
//! `sm/`, and when the peer says it rebooted (`SM_NOTIFY`), calls lockd back. At start
//! statd runs sm-notify to tell its own peers it rebooted.

mod hostname;
mod monitor;
mod notlist;
mod rmtcall;

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::Relaxed};

use support::bfmt;
use support::conffile::{NFS_CONFFILE, conf_get_bool, conf_get_num, conf_get_str, conf_init_file};
use support::mydaemon::{daemon_init, daemon_ready};
use support::nsm_file::{nsm_drop_privileges, nsm_get_state, nsm_setup_pathnames, nsm_update_kernel_state};
use support::nsm_rpc::{SM_PROG, SM_VERS};
use support::svc_create::{Program, nfs_svc_create, nfs_svc_unregister};
use support::sys::{self, Fd};
use support::xlog::{self, D_ALL, D_GENERAL, L_ERROR, L_NOTICE, m, xlog, xlog_err, xlog_warn};
use tirpc::clnt::Lib;
use tirpc::svc::{Request, Service, Svc};
use tirpc::xdr::{self, XdrDecode, XdrEncode};

use monitor::MonArg;
use notlist::Lists;

const VERSION: &str = "2.8.5";

/// `run_mode` bits.
const MODE_NODAEMON: i32 = 1;
const MODE_LOG_STDERR: i32 = 2;
const MODE_NOTIFY_ONLY: i32 = 4;
const STATIC_HOSTNAME: i32 = 8;
const MODE_NO_NOTIFY: i32 = 16;

const SM_MAXSTRLEN: u32 = 1024;
const SM_PRIV_SIZE: usize = 16;
const PIDFILE: &[u8] = b"/run/rpc.statd.pid";

/// `MY_STATE` (`SM_stat_chge.state`), read by the signal handler too.
static MY_STATE: AtomicI32 = AtomicI32::new(0);
/// `svc_stop`.
static SVC_STOP: AtomicBool = AtomicBool::new(false);
/// `pidfd`.
static PIDFD: AtomicI32 = AtomicI32::new(-1);

fn my_state() -> i32 {
    MY_STATE.load(Relaxed)
}

/// `my_svc_exit()`.
fn my_svc_exit() {
    SVC_STOP.store(true, Relaxed);
}

/// The program's globals other than the transports.
#[derive(Debug)]
pub struct State {
    l: Lists,
    run_mode: i32,
    /// `MY_NAME` (`SM_stat_chge.mon_name`).
    my_name: Option<Vec<u8>>,
    ha_callout_prog: Option<Vec<u8>>,
    /// The callback socket (`rmtcall.c`'s `sockfd`).
    sockfd: Fd,
    lib: Lib,
    /// The procedures' static results.
    mon_res: (u32, i32),
    unmon_state: i32,
    unmon_all_state: i32,
    stat_res: (u32, i32),
}

/// `statd_unregister()`. The signal handler and the exit handler use a fresh library
/// state; only the local rpcbind socket is involved.
fn statd_unregister() {
    let mut lib = Lib::default();
    nfs_svc_unregister(&mut lib, SM_PROG, SM_VERS);
}

extern "C" fn atexit_unregister() {
    statd_unregister();
}

/// `killer()`: `SIGHUP`, `SIGINT`, `SIGTERM`.
extern "C" fn killer(sig: libc::c_int) {
    statd_unregister();
    xlog(D_GENERAL, &bfmt!("Caught signal {}, un-registering and exiting", sig));
    sys::exit(0);
}

/// `sigusr()`: `SIGUSR1`.
extern "C" fn sigusr(sig: libc::c_int) {
    xlog(D_GENERAL, &bfmt!("Caught signal {}, re-notifying (state {})", sig, my_state()));
    my_svc_exit();
}

/// `truncate_pidfile()`, at exit.
extern "C" fn truncate_pidfile() {
    let fd = PIDFD.load(Relaxed);
    if fd >= 0 && sys::ftruncate(fd, 0) < 0 {
        xlog_warn(&bfmt!("truncating pid file failed: errno {} ({})\n", sys::errno(), m()));
    }
}

/// `log_modes()`.
fn log_modes(run_mode: i32) {
    if run_mode == 0 {
        return;
    }
    let mut buf = b"Flags: ".to_vec();
    if run_mode & MODE_NODAEMON != 0 {
        buf.extend_from_slice(b"No-Daemon ");
    }
    if run_mode & MODE_LOG_STDERR != 0 {
        buf.extend_from_slice(b"Log-STDERR ");
    }
    buf.extend_from_slice(b"TI-RPC ");
    xlog_warn(&buf);
}

/// `usage()`.
fn usage(name_p: &[u8]) {
    sys::stderr(&bfmt!("usage: {} [options]\n", name_p));
    for l in [
        "      -h, -?, --help       Print this help screen.\n",
        "      -F, --foreground     Foreground (no-daemon mode)\n",
        "      -d, --no-syslog      Verbose logging to stderr.  Foreground mode only.\n",
        "      -p, --port           Port to listen on\n",
        "      -o, --outgoing-port  Port for outgoing connections\n",
        "      -V, -v, --version    Display version information and exit.\n",
        "      -n, --name           Specify a local hostname.\n",
        "      -P                   State directory path.\n",
        "      -N                   Run in notify only mode.\n",
        "      -L, --no-notify      Do not perform any notification.\n",
        "      -H                   Specify a high-availability callout program.\n",
    ] {
        sys::stderr(l.as_bytes());
    }
}

/// `create_pidfile()`: `fopen("w")`, the pid, a `dup()` of the descriptor kept, and
/// `fclose()` (which writes it).
fn create_pidfile() {
    sys::unlink(PIDFILE);
    let fd = sys::open(PIDFILE, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o666);
    if fd < 0 {
        xlog_err(&bfmt!("Opening {} failed: {}\n", PIDFILE, m()));
    }
    PIDFD.store(sys::dup(fd), Relaxed);
    let line = format!("{}\n", sys::getpid()).into_bytes();
    // fclose(): the buffered write, then close(); either failing fails it.
    let written = sys::write(fd, &line) == line.len() as isize;
    let closed = sys::close(fd) >= 0;
    if !written || !closed {
        xlog_warn(&bfmt!("Flushing pid file failed: errno {} ({})\n", sys::errno(), m()));
    }
}

/// `run_sm_notify()`: exec sm-notify (in a child of statd, or for `-N`).
fn run_sm_notify(st: &State, name_p: &[u8], outport: i32) -> ! {
    let mut av: Vec<Vec<u8>> = vec![b"/usr/sbin/sm-notify".to_vec()];
    if st.run_mode & MODE_NODAEMON != 0 {
        av.push(b"-d".to_vec());
    }
    if outport != 0 {
        av.push(format!("-p{outport}").into_bytes());
    }
    if st.run_mode & STATIC_HOSTNAME != 0 {
        av.push(b"-v".to_vec());
        av.push(st.my_name.clone().unwrap_or_default());
    }
    sys::execv(&av[0], &av);
    sys::stderr(&bfmt!("{}: failed to run {}\n", name_p, av[0]));
    sys::exit(2);
}

/// Fork sm-notify and wait for it (`SIGCHLD` is ignored, so it's reaped for us).
fn fork_sm_notify(st: &State, name_p: &[u8], outport: i32) {
    match sys::fork() {
        0 => run_sm_notify(st, name_p, outport),
        -1 => {}
        pid => {
            sys::waitpid(pid);
        }
    }
}

/// `set_nlm_port()`: lockd's port for `type`, through `/proc`.
fn set_nlm_port(name_p: &[u8], ty: &str, port: i32) {
    if port == 0 {
        return;
    }
    let nbuf = port.to_string().into_bytes();
    let pathbuf = format!("/proc/sys/fs/nfs/nlm_{ty}port").into_bytes();
    let mut fd = sys::open(&pathbuf, libc::O_WRONLY, 0);
    if fd < 0 && sys::errno() == libc::ENOENT {
        sys::system(b"modprobe lockd");
        fd = sys::open(&pathbuf, libc::O_WRONLY, 0);
    }
    if fd >= 0 {
        if sys::write(fd, &nbuf) != nbuf.len() as isize {
            sys::stderr(&bfmt!("{}: fail to set NLM {} port: {}\n", name_p, ty, sys::strerror(sys::errno())));
        }
        sys::close(fd);
    } else {
        sys::stderr(&bfmt!("{}: failed to open {}: {}\n", name_p, pathbuf, sys::strerror(sys::errno())));
    }
}

/// The options and `nfs.conf` settings `main()` keeps in locals or globals.
#[derive(Debug, Default)]
struct Ports {
    port: i32,
    out_port: i32,
    nlm_udp: i32,
    nlm_tcp: i32,
}

/// `read_statd_conf()`.
fn read_statd_conf(st: &mut State, p: &mut Ports, argv0: &[u8]) {
    conf_init_file(Some(NFS_CONFFILE));
    xlog::xlog_set_debug(b"statd");
    p.out_port = conf_get_num(b"statd", b"outgoing-port", p.out_port);
    p.port = conf_get_num(b"statd", b"port", p.port);
    st.my_name = conf_get_str(b"statd", b"name");
    if st.my_name.is_some() {
        st.run_mode |= STATIC_HOSTNAME;
    }
    if let Some(s) = conf_get_str(b"statd", b"state-directory-path")
        && !nsm_setup_pathnames(argv0, &s)
    {
        sys::exit(1);
    }
    if let Some(s) = conf_get_str(b"statd", b"ha-callout") {
        st.ha_callout_prog = Some(s);
    }
    p.nlm_tcp = conf_get_num(b"lockd", b"port", p.nlm_tcp);
    p.nlm_udp = conf_get_num(b"lockd", b"udp-port", p.nlm_tcp);
    if conf_get_bool(b"statd", b"no-notify", false) {
        st.run_mode |= MODE_NO_NOTIFY;
    }
}

// ---------------------------------------------------------------------------
// sm_prog_1(): the rpcgen dispatcher

/// A decoded `xdr_string(SM_MAXSTRLEN)`, as C then reads it (up to a NUL).
fn get_name(x: &mut dyn XdrDecode) -> Option<Vec<u8>> {
    xdr::get_string(x, SM_MAXSTRLEN).map(|s| xlog::c_str(&s).to_vec())
}

/// `xdr_my_id()`.
fn get_my_id(x: &mut dyn XdrDecode, a: &mut MonArg) -> Option<()> {
    a.my_name = get_name(x)?;
    a.my_prog = xdr::get_i32(x)?;
    a.my_vers = xdr::get_i32(x)?;
    a.my_proc = xdr::get_i32(x)?;
    Some(())
}

/// `xdr_mon_id()`.
fn get_mon_id(x: &mut dyn XdrDecode, a: &mut MonArg) -> Option<()> {
    a.mon_name = get_name(x)?;
    get_my_id(x, a)
}

/// `xdr_mon()`.
fn get_mon(x: &mut dyn XdrDecode, a: &mut MonArg) -> Option<()> {
    get_mon_id(x, a)?;
    let p = xdr::get_opaque(x, SM_PRIV_SIZE)?;
    a.priv_.copy_from_slice(&p);
    Some(())
}

fn put_stat_res(x: &mut dyn XdrEncode, r: (u32, i32)) -> bool {
    x.put_long(r.0) && x.put_long(r.1 as u32)
}

impl Service for State {
    fn dispatch(&mut self, _dispatch: u32, req: &mut Request<'_>) {
        let caller = req.caller().buf.clone();
        let proc_ = req.call.proc_;
        if proc_ == 0 {
            req.sendreply(&mut |_| true);
            return;
        }
        if !(1..=6).contains(&proc_) {
            req.svcerr_noproc();
            return;
        }
        let mut a = MonArg::default();
        let mut state = 0i32;
        let ok = req.getargs(|x| match proc_ {
            1 => get_name(x).map(|n| a.mon_name = n),
            2 => get_mon(x, &mut a),
            3 => get_mon_id(x, &mut a),
            4 => get_my_id(x, &mut a),
            5 => Some(()),
            _ => {
                a.mon_name = get_name(x)?;
                state = xdr::get_i32(x)?;
                Some(())
            }
        });
        if ok.is_none() {
            req.svcerr_decode();
            return;
        }
        let sent = match proc_ {
            1 => {
                let r = self.sm_stat(&a.mon_name);
                req.sendreply(&mut |x| put_stat_res(x, r))
            }
            2 => {
                let r = self.sm_mon(&mut a, &caller);
                req.sendreply(&mut |x| put_stat_res(x, r))
            }
            3 => {
                let r = self.sm_unmon(&mut a, &caller);
                req.sendreply(&mut |x| x.put_long(r as u32))
            }
            4 => {
                let r = self.sm_unmon_all(&a, &caller);
                req.sendreply(&mut |x| x.put_long(r as u32))
            }
            5 => {
                self.sm_simu_crash(&caller);
                req.sendreply(&mut |_| true)
            }
            _ => {
                self.sm_notify(&a.mon_name, state, &caller);
                req.sendreply(&mut |_| true)
            }
        };
        if !sent {
            req.svcerr_systemerr();
        }
    }
}

// ---------------------------------------------------------------------------
// svc_run.c

/// `my_svc_run()`: serve requests and callback replies, and send callbacks when due,
/// until `my_svc_exit()` or a `select()` error.
fn my_svc_run(svc: &mut Svc, st: &mut State, sockfd: Fd) {
    SVC_STOP.store(false, Relaxed);
    let mut now: i64 = 0;
    loop {
        if SVC_STOP.load(Relaxed) {
            return;
        }
        // QUIRK: this runs while a callback is due at or before now, but
        // process_notify_list() only sends those due strictly before now: one due this
        // very second spins here until the clock moves on.
        while let Some(n) = st.l.notify {
            now = sys::time();
            if st.l.nodes[n].when > now {
                break;
            }
            st.process_notify_list();
        }
        let mut readfds = svc.fdset();
        sys::fd_set(sockfd, &mut readfds);
        let selret = if let Some(n) = st.l.notify {
            let tv = st.l.nodes[n].when - now;
            xlog(D_GENERAL, &bfmt!("Waiting for reply... (timeo {})", tv));
            sys::select_read(libc::FD_SETSIZE as i32, &mut readfds, Some(tv))
        } else {
            xlog(D_GENERAL, b"Waiting for client connections");
            sys::select_read(libc::FD_SETSIZE as i32, &mut readfds, None)
        };
        match selret {
            -1 => {
                let e = sys::errno();
                if matches!(e, libc::EINTR | libc::ECONNREFUSED | libc::ENETUNREACH | libc::EHOSTUNREACH) {
                    continue;
                }
                xlog(L_ERROR, &bfmt!("my_svc_run() - select: {}", m()));
                return;
            }
            0 => continue,
            mut n => {
                n -= st.process_reply(&mut readfds);
                if n != 0 {
                    sys::fd_clr(sockfd, &mut readfds);
                    let mut out = Vec::new();
                    svc.getreqset(st, &readfds, &mut out);
                    if !out.is_empty() {
                        sys::c_stdout(&out);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

fn bad_port(argv0: &[u8], what: &str, optarg: &[u8], name_p: &[u8]) -> ! {
    sys::stderr(&bfmt!("{}: bad {}: {}\n", argv0, what, optarg));
    usage(name_p);
    sys::exit(1);
}

fn main() {
    // A fresh process's state, as C starts: SIGPIPE as inherited (Rust's runtime
    // ignores it), and errno 0.
    sys::signal(libc::SIGPIPE, sys::Handler::Default);
    sys::set_errno(0);

    let mut st = State {
        l: Lists::default(),
        run_mode: 0,
        my_name: None,
        ha_callout_prog: None,
        sockfd: -1,
        lib: Lib::default(),
        mon_res: (0, 0),
        unmon_state: 0,
        unmon_all_state: 0,
        stat_res: (0, 0),
    };
    let mut p = Ports::default();

    if let Some(env) = sys::getenv(b"RPC_STATD_NO_NOTIFY")
        && sys::atoi(&env) > 0
    {
        st.run_mode |= MODE_NO_NOTIFY;
    }

    xlog::xlog_stderr(true);
    xlog::xlog_syslog(false);

    let mut args = sys::Args::from_env();
    let argv0 = args.argv0();
    let name_p = match argv0.iter().rposition(|&b| b == b'/') {
        Some(i) => argv0[i + 1..].to_vec(),
        None => argv0.clone(),
    };

    read_statd_conf(&mut st, &mut p, &argv0);

    let longopts: &[(&std::ffi::CStr, i32, i32)] = &[
        (c"foreground", 0, b'F' as i32),
        (c"no-syslog", 0, b'd' as i32),
        (c"help", 0, b'h' as i32),
        (c"version", 0, b'v' as i32),
        (c"outgoing-port", 1, b'o' as i32),
        (c"port", 1, b'p' as i32),
        (c"name", 1, b'n' as i32),
        (c"state-directory-path", 1, b'P' as i32),
        (c"notify-mode", 0, b'N' as i32),
        (c"ha-callout", 1, b'H' as i32),
        (c"no-notify", 0, b'L' as i32),
        (c"nlm-port", 1, b'T' as i32),
        (c"nlm-udp-port", 1, b'U' as i32),
    ];
    loop {
        let (c, optarg) = args.getopt_long(c"h?vVFNH:dn:p:o:P:LT:U:", longopts);
        if c == -1 {
            break;
        }
        let optarg = optarg.unwrap_or_default();
        match c as u8 {
            b'V' | b'v' => {
                sys::c_stdout(&bfmt!("{} version {}\n", name_p, VERSION));
                sys::exit(0);
            }
            b'F' => st.run_mode |= MODE_NODAEMON,
            b'N' => st.run_mode |= MODE_NOTIFY_ONLY,
            b'L' => st.run_mode |= MODE_NO_NOTIFY,
            b'd' => st.run_mode |= MODE_LOG_STDERR,
            b'o' => {
                p.out_port = sys::atoi(&optarg);
                if !(1..=65535).contains(&p.out_port) {
                    bad_port(&argv0, "port number", &optarg, &name_p);
                }
            }
            b'p' => {
                p.port = sys::atoi(&optarg);
                if !(1..=65535).contains(&p.port) {
                    bad_port(&argv0, "port number", &optarg, &name_p);
                }
            }
            b'T' => {
                p.nlm_tcp = sys::atoi(&optarg);
                if !(1..=65535).contains(&p.nlm_tcp) {
                    bad_port(&argv0, "nlm port number", &optarg, &name_p);
                }
                if p.nlm_udp == 0 {
                    p.nlm_udp = p.nlm_tcp;
                }
            }
            b'U' => {
                p.nlm_udp = sys::atoi(&optarg);
                if !(1..=65535).contains(&p.nlm_udp) {
                    bad_port(&argv0, "nlm UDP port number", &optarg, &name_p);
                }
            }
            b'n' => {
                st.run_mode |= STATIC_HOSTNAME;
                st.my_name = Some(optarg);
            }
            b'P' => {
                if !nsm_setup_pathnames(&argv0, &optarg) {
                    sys::exit(1);
                }
            }
            b'H' => st.ha_callout_prog = Some(optarg),
            b'?' | b'h' => {
                usage(&name_p);
                sys::exit(0);
            }
            _ => {
                usage(&name_p);
                sys::exit(-1);
            }
        }
    }

    if support::getport::nfs_probe_statd(&mut st.lib) {
        sys::stderr(b"Statd service already running!\n");
        sys::exit(1);
    }

    if p.port == p.out_port && p.port != 0 {
        sys::stderr(b"Listening and outgoing ports cannot be the same!\n");
        sys::exit(-1);
    }

    if st.run_mode & MODE_NOTIFY_ONLY != 0 {
        sys::stderr(&bfmt!("{}: -N deprecated, consider using /usr/sbin/sm-notify directly\n", name_p));
        run_sm_notify(&st, &name_p, p.out_port);
    }

    if st.run_mode & MODE_NODAEMON == 0 {
        st.run_mode &= !MODE_LOG_STDERR;
    }

    match sys::getrlimit_nofile() {
        None => sys::stderr(&bfmt!("{}: getrlimit (RLIMIT_NOFILE) failed: {}\n", argv0, sys::strerror(sys::errno()))),
        Some((cur, max)) => {
            if cur > libc::FD_SETSIZE as u64 && sys::setrlimit_nofile(libc::FD_SETSIZE as u64, max) != 0 {
                sys::stderr(&bfmt!("{}: setrlimit (RLIMIT_NOFILE) failed: {}\n", argv0, sys::strerror(sys::errno())));
            }
        }
    }

    set_nlm_port(&name_p, "tcp", p.nlm_tcp);
    set_nlm_port(&name_p, "udp", p.nlm_udp);

    daemon_init(st.run_mode & MODE_NODAEMON != 0);

    if st.run_mode & MODE_LOG_STDERR != 0 {
        xlog::xlog_syslog(false);
        xlog::xlog_stderr(true);
        xlog::xlog_config(D_ALL, true);
    } else {
        xlog::xlog_syslog(true);
        xlog::xlog_stderr(false);
    }

    xlog::xlog_open(&name_p);
    xlog(L_NOTICE, &bfmt!("Version {} starting", VERSION));

    log_modes(st.run_mode);

    sys::signal(libc::SIGHUP, sys::Handler::Func(killer));
    sys::signal(libc::SIGINT, sys::Handler::Func(killer));
    sys::signal(libc::SIGTERM, sys::Handler::Func(killer));
    sys::signal(libc::SIGUSR1, sys::Handler::Func(sigusr));
    sys::signal(libc::SIGCHLD, sys::Handler::Ignore);
    sys::signal(libc::SIGPIPE, sys::Handler::Ignore);

    create_pidfile();
    sys::atexit(truncate_pidfile);

    if st.run_mode & MODE_NO_NOTIFY == 0 {
        fork_sm_notify(&st, &name_p, p.out_port);
    }

    let notify_sockfd = st.statd_get_socket();
    if notify_sockfd < 0 {
        sys::exit(1);
    }

    st.load_state();

    MY_STATE.store(nsm_get_state(false), Relaxed);
    if my_state() == 0 {
        sys::exit(1);
    }
    xlog(D_GENERAL, &bfmt!("Local NSM state number: {}", my_state()));
    nsm_update_kernel_state(my_state());

    // ORDER: clear old listeners while still root.
    statd_unregister();

    if !nsm_drop_privileges(PIDFD.load(Relaxed)) {
        sys::exit(1);
    }

    // The transport table is sized after the descriptor limit was lowered, as
    // libtirpc sizes it at the first registration.
    let mut svc = Svc::default();
    let prog = Program { name: b"statd", program: SM_PROG, version: SM_VERS, dispatch: 0 };
    if nfs_svc_create(&mut svc, &mut st.lib, prog, p.port as u16) == 0 {
        xlog(L_ERROR, b"failed to create RPC listeners, exiting");
        sys::exit(1);
    }
    sys::atexit(atexit_unregister);

    daemon_ready();

    loop {
        my_svc_run(&mut svc, &mut st, notify_sockfd);
        if st.run_mode & MODE_NO_NOTIFY == 0 {
            fork_sm_notify(&st, &name_p, p.out_port);
        }
    }
}
