//! sm-notify: tell every host in `sm.bak/` that this host rebooted (`SM_NOTIFY`), a
//! port of nfs-utils 2.8.5's `utils/statd/sm-notify.c`.

use support::bfmt;
use support::conffile::{NFS_CONFFILE, conf_get_bool, conf_get_num, conf_get_str, conf_init_file};
use support::nsm_file::{
    Mon, SM_MAXSTRLEN, nsm_delete_notified_host, nsm_drop_privileges, nsm_get_state, nsm_is_default_parentdir,
    nsm_load_notify_list, nsm_retire_monitored_hosts, nsm_setup_pathnames, nsm_update_kernel_state,
};
use support::nsm_rpc::{
    NSM_MAXMSGSIZE, SM_PROG, SM_VERS, nsm_parse_reply, nsm_recv_rpcbind, nsm_xmit_notify, nsm_xmit_rpcbind,
};
use support::sockaddr::{family, nfs_get_port, nfs_set_port};
use support::sys::{self, AddrInfo};
use support::xlog::{
    self, D_ALL, D_CALL, D_GENERAL, L_ERROR, L_NOTICE, L_WARNING, c_str, m, xlog, xlog_set_debug, xlog_warn,
};
use tirpc::xdr::XdrMem;

const NSM_TIMEOUT: u32 = 2;
const NSM_MAX_TIMEOUT: u32 = 120;
const NLM_END_GRACE_FILE: &[u8] = b"/proc/fs/lockd/nlm_end_grace";
const VERSION: &str = "2.8.5";

/// `struct nsm_host`.
#[derive(Debug)]
struct Host {
    name: Vec<u8>,
    mon_name: Vec<u8>,
    my_name: Vec<u8>,
    notify_arg: Vec<u8>,
    /// `ai`: the addresses, each as a mutable `sockaddr` (the port is set in place).
    ai: Option<Vec<AddrInfo>>,
    last_used: i64,
    send_next: i64,
    timeout: u32,
    retries: u32,
    xid: u32,
}

/// The program's globals.
#[derive(Debug)]
struct Smn {
    lift_grace: bool,
    force: bool,
    nsm_hostname: Vec<u8>,
    nsm_state: i32,
    nsm_family: i32,
    opt_debug: i32,
    opt_update_state: bool,
    opt_max_retry: u32,
    opt_srcaddr: Option<Vec<u8>>,
    opt_srcport: Option<Vec<u8>>,
    /// `hosts`: the notify list, sorted by `send_next`.
    hosts: Vec<Host>,
    lib: tirpc::clnt::Lib,
}

impl Smn {
    /// `smn_lookup()`.
    fn smn_lookup(&self, name: &[u8]) -> Option<Vec<AddrInfo>> {
        let fam = if self.nsm_family == libc::AF_INET { libc::AF_INET } else { libc::AF_UNSPEC };
        sys::res_init();
        match sys::getaddrinfo(Some(name), None, 0, fam, 0, libc::IPPROTO_UDP) {
            Ok(ai) => Some(ai),
            Err(e) => {
                xlog(D_GENERAL, &bfmt!("getaddrinfo(3): {}", sys::gai_strerror(e)));
                None
            }
        }
    }

    /// `smn_forget_host()`.
    fn smn_forget_host(&mut self, host: Host) {
        xlog(D_CALL, &bfmt!("Removing {} ({}, {}) from notify list", host.name, host.mon_name, host.my_name));
        nsm_delete_notified_host(&host.name, &host.mon_name, &host.my_name);
    }

    /// `insert_host()`.
    fn insert_host(&mut self, host: Host) {
        insert_host(&mut self.hosts, host);
    }

    /// `find_host()`: take the host waiting for `xid` off the list.
    fn find_host(&mut self, xid: u32) -> Option<Host> {
        let i = self.hosts.iter().position(|h| h.xid == xid)?;
        Some(self.hosts.remove(i))
    }

    /// `smn_socket()`: an IPv6 datagram socket that takes IPv4 too, or IPv4 if the
    /// system has no IPv6.
    fn smn_socket(&mut self) -> sys::Fd {
        let mut sock = sys::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if sock == -1 {
            if sys::errno() != libc::EAFNOSUPPORT {
                xlog(L_ERROR, &bfmt!("Failed to create RPC socket: {}", m()));
                return -1;
            }
            sock = sys::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                xlog(L_ERROR, &bfmt!("Failed to create RPC socket: {}", m()));
                return -1;
            }
        } else {
            self.nsm_family = libc::AF_INET6;
        }
        if sys::setfl(sock, libc::O_NONBLOCK) == -1 {
            xlog(L_ERROR, &bfmt!("fcntl(3) on RPC socket failed: {}", m()));
            sys::close(sock);
            return -1;
        }
        if self.nsm_family == libc::AF_INET6 && sys::setsockopt_int(sock, libc::SOL_IPV6, libc::IPV6_V6ONLY, 0) == -1 {
            xlog(L_ERROR, &bfmt!("setsockopt(3) on RPC socket failed: {}", m()));
            sys::close(sock);
            return -1;
        }
        sock
    }

    /// `smn_bind_address()`.
    fn smn_bind_address(&self, srcaddr: Option<&[u8]>, srcport: Option<&[u8]>) -> Option<Vec<AddrInfo>> {
        let mut flags = libc::AI_NUMERICSERV | libc::AI_V4MAPPED;
        if srcaddr.is_none() {
            flags |= libc::AI_PASSIVE;
        }
        let service: &[u8] = srcport.unwrap_or(b"");
        match sys::getaddrinfo(srcaddr, Some(service), flags, self.nsm_family, 0, libc::IPPROTO_UDP) {
            Ok(ai) => Some(ai),
            Err(e) => {
                xlog(L_ERROR, &bfmt!("Invalid bind address or port for RPC socket: {}", sys::gai_strerror(e)));
                None
            }
        }
    }

    /// `smn_create_socket()`: bound to `-p`'s port, or to a reserved port that
    /// `/etc/services` doesn't name.
    fn smn_create_socket(&mut self, srcaddr: Option<&[u8]>, srcport: Option<&[u8]>) -> sys::Fd {
        let mut retry_cnt = 0;
        loop {
            let sock = self.smn_socket();
            if sock == -1 {
                return -1;
            }
            let Some(ai) = self.smn_bind_address(srcaddr, srcport) else {
                sys::close(sock);
                return -1;
            };
            let mut addr = ai[0].addr.clone();
            if srcport.is_some() {
                if sys::bind(sock, &addr) == -1 {
                    xlog(L_ERROR, &bfmt!("Failed to bind RPC socket: {}", m()));
                    sys::close(sock);
                    return -1;
                }
            } else {
                if tirpc::clnt::bindresvport_sa(&mut self.lib, sock, Some(&mut addr)) == -1 {
                    xlog(L_ERROR, &bfmt!("bindresvport on RPC socket failed: {}", m()));
                    sys::close(sock);
                    return -1;
                }
                // QUIRK: getservbyport() wants the port in network order but gets it
                // in host order, so the port looked up is the byte-swapped one. And
                // the retry binds the same port again (the pid picks it).
                let known = sys::getservbyport_raw(i32::from(nfs_get_port(&addr)), b"udp");
                if known && retry_cnt < 100 {
                    retry_cnt += 1;
                    sys::close(sock);
                    continue;
                }
            }
            return sock;
        }
    }

    /// `notify()`.
    fn notify(&mut self, sock: sys::Fd) {
        let mut failtime: i64 = 0;
        if self.opt_max_retry != 0 {
            failtime = sys::time() + i64::from(self.opt_max_retry);
        }
        while !self.hosts.is_empty() {
            let now = sys::time();
            let mut sent = 0;
            let mut wait: i64;
            if failtime != 0 && now >= failtime {
                break;
            }
            loop {
                wait = self.hosts[0].send_next - now;
                if wait > 0 {
                    break;
                }
                // Never send more than 10 packets at once.
                let s = sent;
                sent += 1;
                if s >= 10 {
                    break;
                }
                let mut hp = self.hosts.remove(0);
                self.notify_host(sock, &mut hp);
                wait = i64::from(hp.timeout);
                hp.timeout <<= 1;
                if hp.timeout > NSM_MAX_TIMEOUT {
                    hp.timeout = NSM_MAX_TIMEOUT;
                }
                hp.send_next = now + wait;
                hp.retries += 1;
                self.insert_host(hp);
            }
            xlog(D_GENERAL, &bfmt!("Host {} due in {} seconds", self.hosts[0].name, wait));
            let mut ms = wait.wrapping_mul(1000);
            if ms < 100 {
                ms = 100;
            }
            if sys::poll_in(sock, ms as i32) != 1 {
                continue;
            }
            self.recv_reply(sock);
        }
    }

    /// `notify_host()`.
    fn notify_host(&mut self, sock: sys::Fd, host: &mut Host) {
        if host.ai.is_none() {
            host.ai = self.smn_lookup(&host.name);
            if host.ai.is_none() {
                xlog_warn(&bfmt!("DNS resolution of {} failed; retrying later", host.name));
                return;
            }
        }
        let ai = host.ai.as_mut().unwrap();
        // After four retransmissions, look the port up again (statd may have
        // restarted), rotating through the addresses. QUIRK: C's rotation searches for
        // the list's end from the removed entry's own link, so it links that entry to
        // itself instead: the first address is dropped, not moved to the end.
        if host.retries >= 4 {
            if ai.len() > 1 {
                ai.remove(0);
            }
            nfs_set_port(&mut ai[0].addr, 0);
            host.retries = 0;
        }
        let sa = &ai[0].addr;
        host.xid = if nfs_get_port(sa) == 0 {
            nsm_xmit_rpcbind(sock, sa, SM_PROG, SM_VERS)
        } else {
            nsm_xmit_notify(sock, sa, SM_PROG, &host.notify_arg, self.nsm_state)
        };
    }

    /// `smn_defer()`.
    fn smn_defer(&mut self, mut host: Host) {
        host.xid = 0;
        host.send_next = sys::time() + i64::from(NSM_MAX_TIMEOUT);
        host.timeout = NSM_MAX_TIMEOUT;
        self.insert_host(host);
    }

    /// `smn_schedule()`.
    fn smn_schedule(&mut self, mut host: Host) {
        host.retries = 0;
        host.xid = 0;
        host.send_next = sys::time();
        host.timeout = NSM_TIMEOUT;
        self.insert_host(host);
    }

    /// `recv_reply()`.
    fn recv_reply(&mut self, sock: sys::Fd) {
        let mut msgbuf = [0u8; NSM_MAXMSGSIZE];
        let msglen = sys::recv(sock, &mut msgbuf);
        if msglen < 0 {
            return;
        }
        xlog(D_GENERAL, b"Received packet...");
        let mut x = XdrMem::new(&mut msgbuf[..msglen as usize]);
        let xid = nsm_parse_reply(&mut x);
        if xid == 0 {
            return;
        }
        let Some(mut hp) = self.find_host(xid) else {
            return;
        };
        let sa = &mut hp.ai.as_mut().unwrap()[0].addr;
        if nfs_get_port(sa) == 0 {
            // recv_rpcbind_reply()
            let port = nsm_recv_rpcbind(family(sa), &mut x);
            if port == 0 {
                xlog(D_GENERAL, &bfmt!("No statd on host {}", hp.name));
                self.smn_defer(hp);
            } else {
                xlog(D_GENERAL, &bfmt!("Processing rpcbind reply for {} (port {})", hp.name, port));
                nfs_set_port(sa, port);
                self.smn_schedule(hp);
            }
        } else {
            // recv_notify_reply(): try again with the unqualified name, if this one had
            // a dot.
            if let Some(dot) = hp.notify_arg.iter().position(|&b| b == b'.') {
                hp.notify_arg.truncate(dot);
                self.smn_schedule(hp);
            } else {
                xlog(D_GENERAL, &bfmt!("Host {} notified successfully", hp.name));
                self.smn_forget_host(hp);
            }
        }
    }
}

/// `smn_alloc_host()`: `nsm_hostname` is the `-v` name, if there was one.
fn smn_alloc_host(
    nsm_hostname: Option<&[u8]>,
    hostname: &[u8],
    mon_name: &[u8],
    my_name: &[u8],
    timestamp: i64,
) -> Host {
    Host {
        name: c_str(hostname).to_vec(),
        mon_name: c_str(mon_name).to_vec(),
        my_name: c_str(my_name).to_vec(),
        notify_arg: c_str(nsm_hostname.unwrap_or(my_name)).to_vec(),
        ai: None,
        last_used: timestamp,
        send_next: 0,
        timeout: NSM_TIMEOUT,
        // Force an address lookup.
        retries: 100,
        xid: 0,
    }
}

/// `insert_host()`: by `send_next`, the most recently used first among equals.
fn insert_host(hosts: &mut Vec<Host>, host: Host) {
    let mut at = hosts.len();
    for (i, p) in hosts.iter().enumerate() {
        if host.send_next < p.send_next || (host.send_next == p.send_next && host.last_used > p.last_used) {
            at = i;
            break;
        }
    }
    xlog(D_GENERAL, &bfmt!("Added host {} to notify list", host.name));
    hosts.insert(at, host);
}

/// `smn_get_hostname()`.
fn smn_get_hostname(sa: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    match sys::getnameinfo_host(sa, libc::NI_NAMEREQD) {
        Ok(h) => Some(h),
        Err(e) => {
            xlog(L_ERROR, &bfmt!("my_name '{}' is unusable: {}", name, sys::gai_strerror(e)));
            None
        }
    }
}

/// `smn_verify_my_name()`: an address becomes its canonical name; any other name is kept.
fn smn_verify_my_name(name: &[u8]) -> Option<Vec<u8>> {
    let retval = match sys::getaddrinfo(Some(name), None, libc::AI_NUMERICHOST, libc::AF_UNSPEC, 0, 0) {
        Ok(ai) => smn_get_hostname(&ai[0].addr, name)?,
        Err(libc::EAI_NONAME) => c_str(name).to_vec(),
        Err(e) => {
            xlog(L_ERROR, &bfmt!("my_name '{}' is unusable: {}", name, sys::gai_strerror(e)));
            return None;
        }
    };
    xlog(D_GENERAL, &bfmt!("Canonical name for my_name '{}': {}", name, retval));
    Some(retval)
}

/// `nsm_lift_grace_period()`.
fn nsm_lift_grace_period() {
    let fd = sys::open(NLM_END_GRACE_FILE, libc::O_WRONLY, 0);
    if fd < 0 {
        if sys::errno() != libc::ENOENT {
            xlog(L_WARNING, &bfmt!("Unable to open /proc/fs/lockd/nlm_end_grace: {}", m()));
        }
        return;
    }
    if sys::write(fd, b"Y") < 0 {
        xlog(L_WARNING, &bfmt!("Unable to write to /proc/fs/lockd/nlm_end_grace: {}", m()));
    }
    sys::close(fd);
}

/// `record_pid()`: create `/run/sm-notify.pid`; false if it already exists.
fn record_pid() -> bool {
    let pid = bfmt!("{}\n", sys::getpid());
    let fd = sys::open(b"/run/sm-notify.pid", libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o600);
    if fd < 0 {
        return false;
    }
    let len = sys::write(fd, &pid);
    if len < 0 || len as usize != pid.len() {
        let e = sys::errno();
        xlog_warn(&bfmt!("Writing to pid file failed: errno {} ({})", e, sys::strerror(e)));
    }
    sys::close(fd);
    true
}

/// `read_smnotify_conf()`.
fn read_smnotify_conf(s: &mut Smn, argv0: &[u8]) {
    conf_init_file(Some(NFS_CONFFILE));
    xlog_set_debug(b"sm-notify");
    s.opt_max_retry =
        (conf_get_num(b"sm-notify", b"retry-time", (s.opt_max_retry / 60) as i32).wrapping_mul(60)) as u32;
    s.opt_srcport = conf_get_str(b"sm-notify", b"outgoing-port");
    s.opt_srcaddr = conf_get_str(b"sm-notify", b"outgoing-addr");
    s.lift_grace = conf_get_bool(b"sm-notify", b"lift-grace", s.lift_grace);
    if let Some(dir) = conf_get_str(b"statd", b"state-directory-path")
        && !nsm_setup_pathnames(argv0, &dir)
    {
        sys::exit(1);
    }
    s.opt_update_state = conf_get_bool(b"sm-notify", b"update-state", s.opt_update_state);
    s.force = conf_get_bool(b"sm-notify", b"force", s.force);
}

fn main() {
    // A fresh process's state, as C starts: SIGPIPE as inherited (Rust's runtime
    // ignores it), and errno 0 (messages print it after unrelated calls).
    sys::signal(libc::SIGPIPE, sys::Handler::Default);
    sys::set_errno(0);

    let mut args = sys::Args::from_env();
    let argv0 = args.argv0();
    let progname = match argv0.iter().rposition(|&b| b == b'/') {
        Some(i) => argv0[i + 1..].to_vec(),
        None => argv0.clone(),
    };
    let mut s = Smn {
        lift_grace: true,
        force: false,
        nsm_hostname: vec![0; SM_MAXSTRLEN + 1],
        nsm_state: 0,
        nsm_family: libc::AF_INET,
        opt_debug: 0,
        opt_update_state: true,
        opt_max_retry: 15 * 60,
        opt_srcaddr: None,
        opt_srcport: None,
        hosts: Vec::new(),
        lib: tirpc::clnt::Lib::default(),
    };

    read_smnotify_conf(&mut s, &argv0);

    let mut usage = false;
    loop {
        let (c, optarg) = args.getopt(c"dm:np:v:P:f");
        if c == -1 {
            break;
        }
        match c as u8 {
            b'f' => s.force = true,
            b'd' => s.opt_debug += 1,
            b'm' => s.opt_max_retry = sys::atoi(&optarg.unwrap_or_default()).wrapping_mul(60) as u32,
            b'n' => s.opt_update_state = false,
            b'p' => s.opt_srcport = optarg,
            b'v' => s.opt_srcaddr = optarg,
            b'P' => {
                if !nsm_setup_pathnames(&argv0, &optarg.unwrap_or_default()) {
                    sys::exit(1);
                }
            }
            _ => {
                usage = true;
                break;
            }
        }
    }
    if usage || args.optind() < args.argc() {
        sys::stderr(&bfmt!(
            "Usage: {} -notify [-dfq] [-m max-retry-minutes] [-p srcport]\n            [-P /path/to/state/directory] [-v my_host_name]\n",
            progname
        ));
        sys::exit(1);
    }

    if s.opt_debug != 0 {
        xlog::xlog_syslog(false);
        xlog::xlog_stderr(true);
        xlog::xlog_config(D_ALL, true);
    } else {
        xlog::xlog_syslog(true);
        xlog::xlog_stderr(false);
    }
    xlog::xlog_open(&progname);
    xlog(L_NOTICE, &bfmt!("Version {} starting", VERSION));

    if nsm_is_default_parentdir() && !record_pid() && !s.force && s.opt_update_state {
        xlog(L_NOTICE, b"Already notifying clients; Exiting!");
        sys::exit(0);
    }

    if let Some(src) = s.opt_srcaddr.clone() {
        let Some(name) = smn_verify_my_name(&src) else {
            sys::exit(1);
        };
        // strncpy(nsm_hostname, name, sizeof(nsm_hostname) - 1)
        let n = c_str(&name);
        let n = &n[..n.len().min(SM_MAXSTRLEN)];
        s.nsm_hostname = n.to_vec();
    }

    nsm_retire_monitored_hosts();
    let srcname = s.opt_srcaddr.is_some().then(|| s.nsm_hostname.clone());
    let mut hosts = std::mem::take(&mut s.hosts);
    let loaded = nsm_load_notify_list(&mut |hostname: &[u8], _addr: u32, m: &Mon, timestamp: i64| -> u32 {
        // smn_get_host()
        insert_host(&mut hosts, smn_alloc_host(srcname.as_deref(), hostname, &m.mon_name, &m.my_name, timestamp));
        1
    });
    s.hosts = hosts;
    if loaded == 0 {
        xlog(D_GENERAL, b"No hosts to notify; exiting");
        if s.lift_grace {
            nsm_lift_grace_period();
        }
        sys::exit(0);
    }

    s.nsm_state = nsm_get_state(s.opt_update_state);
    if s.nsm_state == 0 {
        sys::exit(1);
    }
    nsm_update_kernel_state(s.nsm_state);

    if s.opt_debug == 0 {
        xlog(L_NOTICE, b"Backgrounding to notify hosts...\n");
        if sys::daemon() < 0 {
            xlog(L_ERROR, &bfmt!("unable to background: {}", m()));
            sys::exit(1);
        }
        sys::close(0);
        sys::close(1);
        sys::close(2);
    }

    let (srcaddr, srcport) = (s.opt_srcaddr.clone(), s.opt_srcport.clone());
    let sock = s.smn_create_socket(srcaddr.as_deref(), srcport.as_deref());
    if sock == -1 {
        sys::exit(1);
    }
    if !nsm_drop_privileges(-1) {
        sys::exit(1);
    }

    s.notify(sock);

    if !s.hosts.is_empty() {
        let hosts = std::mem::take(&mut s.hosts);
        for hp in hosts {
            xlog(L_NOTICE, &bfmt!("Unable to notify {}, giving up", hp.name));
        }
        sys::exit(1);
    }
    sys::exit(0);
}
