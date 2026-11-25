//! The NSM procedures: `utils/statd/monitor.c` (`SM_MON`, `SM_UNMON`, `SM_UNMON_ALL`,
//! and loading the monitor list), `stat.c` (`SM_STAT`), `simu.c` (`SM_SIMU_CRASH`),
//! `callback.c` (`SM_NOTIFY`), and `support/include/ha-callout.h`.

use support::bfmt;
use support::nsm_file::{
    Mon, SM_MAXSTRLEN, nsm_delete_monitored_host, nsm_insert_monitored_host, nsm_load_monitor_list,
};
use support::sockaddr::{nfs_get_port, nfs_is_v4_loopback};
use support::sys;
use support::xlog::{D_CALL, D_GENERAL, L_ERROR, L_WARNING, xlog, xlog_warn};

use super::hostname::{INET6_ADDRSTRLEN, statd_canonical_name, statd_matchhostname, statd_present_address};
use super::notlist::{nlist_clone, nlist_free, nlist_gethost, nlist_insert, nlist_kill, nlist_new};
use super::{State, my_state, my_svc_exit};

pub const STAT_SUCC: u32 = 0;
pub const STAT_FAIL: u32 = 1;
const IPPORT_RESERVED: i32 = 1024;

/// `struct mon` as decoded (`mon_name` and `my_name` cut at a NUL, as C reads them).
#[derive(Debug, Clone, Default)]
pub struct MonArg {
    pub mon_name: Vec<u8>,
    pub my_name: Vec<u8>,
    pub my_prog: i32,
    pub my_vers: i32,
    pub my_proc: i32,
    pub priv_: [u8; 16],
}

/// `my_name must not have white space`: blanks, tabs, CR and LF become `_`.
fn underscore_white_space(name: &mut [u8]) {
    for c in name.iter_mut() {
        if matches!(*c, b' ' | b'\t' | b'\r' | b'\n') {
            *c = b'_';
        }
    }
}

/// `htonl(INADDR_LOOPBACK)` as the host reads it (the record's callback address).
fn loopback_s_addr() -> u32 {
    u32::from_ne_bytes([127, 0, 0, 1])
}

impl State {
    /// `caller_is_localhost()`.
    fn caller_is_localhost(&self, caller: &[u8]) -> bool {
        if nfs_is_v4_loopback(caller) {
            return true;
        }
        let buf = statd_present_address(caller, INET6_ADDRSTRLEN).unwrap_or_default();
        xlog_warn(&bfmt!("SM_MON/SM_UNMON call from non-local host {}", buf));
        false
    }

    /// `ha_callout(event, arg1, arg2, arg3)`: run the `-H` program and wait for it
    /// (with `SIGCHLD` at its default meanwhile).
    pub fn ha_callout(&self, event: &[u8], arg1: &[u8], arg2: &[u8], arg3: i32) {
        let Some(prog) = &self.ha_callout_prog else {
            return;
        };
        let buf = arg3.to_string().into_bytes();
        let mut ret: i32 = -1;
        let old = sys::sigaction_default(libc::SIGCHLD);
        let pid = sys::fork();
        match pid {
            0 => {
                let mut argv = vec![prog.clone(), event.to_vec(), arg1.to_vec(), arg2.to_vec()];
                if arg3 >= 0 {
                    argv.push(buf);
                }
                sys::execl(prog, &argv);
                sys::perror(b"execl");
                sys::_exit(2);
            }
            -1 => sys::perror(b"fork"),
            _ => {
                let (r, st) = sys::waitpid(pid);
                if r >= 0 {
                    ret = st;
                }
            }
        }
        sys::sigaction_restore(libc::SIGCHLD, &old);
        xlog(D_GENERAL, &bfmt!("ha callout returned {}\n", libc::WEXITSTATUS(ret)));
    }

    /// `sm_mon_1_svc()`: the (static) `sm_stat_res`.
    pub fn sm_mon(&mut self, argp: &mut MonArg, caller: &[u8]) -> (u32, i32) {
        xlog(D_CALL, &bfmt!("Received SM_MON for {} from {}", argp.mon_name, argp.my_name));
        self.mon_res = (STAT_FAIL, -1);
        let mut clnt = None;
        'failure: {
            if !self.caller_is_localhost(caller) {
                break 'failure;
            }
            if argp.my_prog != 100021 || (argp.my_proc != 16 && argp.my_proc != 24) {
                xlog_warn(&bfmt!("Attempt to register callback to {}/{}", argp.my_prog, argp.my_proc));
                break 'failure;
            }
            let mon_name = argp.mon_name.clone();
            if mon_name.contains(&b'/') || mon_name.first() == Some(&b'.') {
                xlog(L_ERROR, &bfmt!("SM_MON request for hostname containing '/' or starting '.': {}", mon_name));
                xlog(L_ERROR, b"POSSIBLE SPOOF/ATTACK ATTEMPT!");
                break 'failure;
            }
            underscore_white_space(&mut argp.my_name);
            let my_name = argp.my_name.clone();
            let Some(dnsname) = statd_canonical_name(&mon_name) else {
                xlog(L_WARNING, &bfmt!("No canonical hostname found for {}", mon_name));
                break 'failure;
            };
            let mut existing = false;
            let mut c = self.l.rtnl;
            loop {
                c = nlist_gethost(&self.l.nodes, c, &mon_name, false);
                let Some(i) = c else { break };
                let n = &self.l.nodes[i];
                let name = n.my_name.clone();
                if statd_matchhostname(&name, &my_name)
                    && n.my_proc == argp.my_proc
                    && n.my_prog == argp.my_prog
                    && n.my_vers == argp.my_vers
                {
                    if n.priv_ != argp.priv_ {
                        xlog(
                            D_GENERAL,
                            &bfmt!(
                                "Received SM_MON request with new cookie for {} from procedure on {}",
                                mon_name,
                                my_name
                            ),
                        );
                        existing = true;
                        break;
                    }
                    xlog(D_GENERAL, &bfmt!("Duplicate SM_MON request for {} from procedure on {}", mon_name, my_name));
                    return self.mon_success();
                }
                c = self.l.nodes[i].next;
            }
            let i = match (existing, c) {
                (true, Some(i)) => i,
                _ => nlist_new(&mut self.l.nodes, &my_name, &mon_name, 0),
            };
            clnt = Some(i);
            let n = &mut self.l.nodes[i];
            n.my_prog = argp.my_prog;
            n.my_vers = argp.my_vers;
            n.my_proc = argp.my_proc;
            n.priv_ = argp.priv_;
            n.dns_name = Some(dnsname.clone());

            nsm_delete_monitored_host(&dnsname, &mon_name, &my_name, false);
            let m = Mon {
                mon_name: mon_name.clone(),
                my_name: my_name.clone(),
                my_prog: argp.my_prog as u32,
                my_vers: argp.my_vers as u32,
                my_proc: argp.my_proc as u32,
                priv_: argp.priv_,
            };
            if !nsm_insert_monitored_host(&dnsname, loopback_s_addr(), &m) {
                let head = if existing { Some(&mut self.l.rtnl) } else { None };
                nlist_free(&mut self.l.nodes, head, i);
                break 'failure;
            }
            self.ha_callout(b"add-client", &mon_name, &my_name, -1);
            if !existing {
                nlist_insert(&mut self.l.nodes, &mut self.l.rtnl, i);
            }
            xlog(D_GENERAL, &bfmt!("MONITORING {} for {}", mon_name, my_name));
            return self.mon_success();
        }
        xlog_warn(&bfmt!("STAT_FAIL to {} for SM_MON of {}", argp.my_name, argp.mon_name));
        // free(clnt): the entry is gone.
        let _ = clnt;
        self.mon_res
    }

    fn mon_success(&mut self) -> (u32, i32) {
        self.mon_res = (STAT_SUCC, my_state());
        self.mon_res
    }

    /// `load_state()`: the monitor list from `sm/`.
    pub fn load_state(&mut self) {
        let l = &mut self.l;
        let count = nsm_load_monitor_list(&mut |hostname: &[u8], _sap: u32, m: &Mon, _ts: i64| -> u32 {
            // load_one_host()
            let i = nlist_new(&mut l.nodes, &m.my_name, &m.mon_name, 0);
            l.nodes[i].dns_name = Some(hostname.to_vec());
            xlog(D_GENERAL, &bfmt!("Adding record for {} to the monitor list...", hostname));
            l.nodes[i].my_prog = m.my_prog as i32;
            l.nodes[i].my_vers = m.my_vers as i32;
            l.nodes[i].my_proc = m.my_proc as i32;
            l.nodes[i].priv_ = m.priv_;
            nlist_insert(&mut l.nodes, &mut l.rtnl, i);
            1
        });
        if count != 0 {
            xlog(D_GENERAL, &bfmt!("Loaded {} previously monitored hosts", count));
        }
    }

    /// `sm_unmon_1_svc()`: the (static) `sm_stat`.
    pub fn sm_unmon(&mut self, argp: &mut MonArg, caller: &[u8]) -> i32 {
        xlog(D_CALL, &bfmt!("Received SM_UNMON for {} from {}", argp.mon_name, argp.my_name));
        self.unmon_state = my_state();
        'failure: {
            if !self.caller_is_localhost(caller) {
                break 'failure;
            }
            underscore_white_space(&mut argp.my_name);
            let (mon_name, my_name) = (argp.mon_name.clone(), argp.my_name.clone());
            if self.l.rtnl.is_none() {
                xlog_warn(&bfmt!(
                    "Received SM_UNMON request from {} for {} while not monitoring any hosts",
                    my_name,
                    mon_name
                ));
                return self.unmon_state;
            }
            let mut c = self.l.rtnl;
            loop {
                c = nlist_gethost(&self.l.nodes, c, &mon_name, false);
                let Some(i) = c else { break };
                let name = self.l.nodes[i].my_name.clone();
                let n = &self.l.nodes[i];
                if statd_matchhostname(&name, &my_name)
                    && n.my_proc == argp.my_proc
                    && n.my_prog == argp.my_prog
                    && n.my_vers == argp.my_vers
                {
                    xlog(D_GENERAL, &bfmt!("UNMONITORING {} for {}", mon_name, my_name));
                    self.ha_callout(b"del-client", &mon_name, &my_name, -1);
                    let dns = self.l.nodes[i].dns_name.clone().unwrap_or_default();
                    nsm_delete_monitored_host(&dns, &mon_name, &my_name, true);
                    nlist_free(&mut self.l.nodes, Some(&mut self.l.rtnl), i);
                    return self.unmon_state;
                }
                c = self.l.nodes[i].next;
            }
        }
        xlog_warn(&bfmt!("Received erroneous SM_UNMON request from {} for {}", argp.my_name, argp.mon_name));
        self.unmon_state
    }

    /// `sm_unmon_all_1_svc()`: the (static) `sm_stat`, which a remote caller gets as
    /// the last call left it.
    pub fn sm_unmon_all(&mut self, argp: &MonArg, caller: &[u8]) -> i32 {
        let my_name = argp.my_name.clone();
        xlog(D_CALL, &bfmt!("Received SM_UNMON_ALL for {}", my_name));
        if !self.caller_is_localhost(caller) {
            return self.unmon_all_state;
        }
        self.unmon_all_state = my_state();
        if self.l.rtnl.is_none() {
            xlog_warn(&bfmt!("Received SM_UNMON_ALL request from {} while not monitoring any hosts", my_name));
            return self.unmon_all_state;
        }
        let mut count: i16 = 0;
        let mut c = self.l.rtnl;
        loop {
            c = nlist_gethost(&self.l.nodes, c, &my_name, true);
            let Some(i) = c else { break };
            let n = &self.l.nodes[i];
            if n.my_proc == argp.my_proc && n.my_prog == argp.my_prog && n.my_vers == argp.my_vers {
                xlog(D_GENERAL, &bfmt!("UNMONITORING (SM_UNMON_ALL) {} for {}", n.mon_name, n.my_name));
                let mut mon_name = n.mon_name.clone();
                mon_name.truncate(SM_MAXSTRLEN);
                let temp = n.next;
                self.ha_callout(b"del-client", &mon_name, &my_name, -1);
                let dns = self.l.nodes[i].dns_name.clone().unwrap_or_default();
                nsm_delete_monitored_host(&dns, &mon_name, &my_name, true);
                nlist_free(&mut self.l.nodes, Some(&mut self.l.rtnl), i);
                count = count.wrapping_add(1);
                c = temp;
            } else {
                c = n.next;
            }
        }
        if count == 0 {
            xlog(D_GENERAL, &bfmt!("SM_UNMON_ALL request from {} with no SM_MON requests from it", my_name));
        }
        self.unmon_all_state
    }

    /// `sm_stat_1_svc()`: the (static) `sm_stat_res`.
    pub fn sm_stat(&mut self, mon_name: &[u8]) -> (u32, i32) {
        xlog(D_CALL, &bfmt!("Received SM_STAT from {}", mon_name));
        if statd_canonical_name(mon_name).is_none() {
            self.stat_res.0 = STAT_FAIL;
            xlog(D_GENERAL, &bfmt!("STAT_FAIL for {}", mon_name));
        } else {
            self.stat_res.0 = STAT_SUCC;
            xlog(D_GENERAL, &bfmt!("STAT_SUCC for {}", mon_name));
        }
        self.stat_res.1 = my_state();
        self.stat_res
    }

    /// `sm_simu_crash_1_svc()`.
    pub fn sm_simu_crash(&mut self, caller: &[u8]) {
        xlog(D_CALL, b"Received SM_SIMU_CRASH");
        if !nfs_is_v4_loopback(caller) {
            let buf = statd_present_address(caller, INET6_ADDRSTRLEN).unwrap_or_default();
            xlog_warn(&bfmt!("SM_SIMU_CRASH call from non-local host {}", buf));
            return;
        }
        if i32::from(nfs_get_port(caller)) >= IPPORT_RESERVED {
            xlog_warn(b"SM_SIMU_CRASH call from unprivileged port");
            return;
        }
        my_svc_exit();
        if self.l.rtnl.is_some() {
            nlist_kill(&mut self.l.nodes, &mut self.l.rtnl);
        }
    }

    /// `sm_notify_1_svc()`: queue a callback for each monitored host the notifying
    /// host matches (by name or address), whose state changed.
    pub fn sm_notify(&mut self, mon_name: &[u8], state: i32, caller: &[u8]) {
        xlog(D_CALL, &bfmt!("Received SM_NOTIFY from {}, state: {}", mon_name, state));
        let Some(ip_addr) = statd_present_address(caller, INET6_ADDRSTRLEN) else {
            xlog_warn(b"Unrecognized sender address");
            return;
        };
        self.ha_callout(b"sm-notify", mon_name, &ip_addr, state);
        if self.l.rtnl.is_none() {
            xlog_warn(&bfmt!("SM_NOTIFY from {} while not monitoring any hosts", mon_name));
            return;
        }
        let mut lp = self.l.rtnl;
        while let Some(i) = lp {
            let dns = self.l.nodes[i].dns_name.clone().unwrap_or_default();
            if self.l.nodes[i].state != state
                && (statd_matchhostname(mon_name, &dns) || statd_matchhostname(&ip_addr, &dns))
            {
                self.l.nodes[i].state = state;
                let call = nlist_clone(&mut self.l.nodes, i);
                nlist_insert(&mut self.l.nodes, &mut self.l.notify, call);
            }
            lp = self.l.nodes[i].next;
        }
    }
}
