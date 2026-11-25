//! Differential tests for rpc.statd: options and `nfs.conf`, starting up (the pid file,
//! the state, registering with rpcbind, daemon mode, sm-notify), the NSM procedures
//! from lockd and from peers, callbacks to lockd, odd calls, and signals.

mod common;

use common::statd::*;
use common::{check, record};

// ---------------------------------------------------------------------------
// options

#[test]
fn version() {
    check(case("version", &["-v"]));
}

#[test]
fn version_long() {
    check(case("version_long", &["--version"]));
}

#[test]
fn help() {
    check(case("help", &["-h"]));
}

#[test]
fn help_question_mark() {
    check(case("help_question_mark", &["-?"]));
}

#[test]
fn usage_bad_option() {
    check(case("usage_bad_option", &["-x"]));
}

#[test]
fn usage_missing_argument() {
    check(case("usage_missing_argument", &["-F", "-p"]));
}

#[test]
fn bad_port() {
    check(case("bad_port", &["-p", "70000"]));
}

#[test]
fn bad_outgoing_port() {
    check(case("bad_outgoing_port", &["-o", "0"]));
}

#[test]
fn bad_nlm_port() {
    check(case("bad_nlm_port", &["-T", "x"]));
}

#[test]
fn bad_nlm_udp_port() {
    check(case("bad_nlm_udp_port", &["--nlm-udp-port", "65536"]));
}

#[test]
fn same_ports() {
    check(case("same_ports", &["-F", "-p", "32765", "-o", "32765"]));
}

#[test]
fn state_dir_missing() {
    check(case("state_dir_missing", &["-F", "-d", "-P", "/nonexistent"]));
}

#[test]
fn notify_only() {
    // -N runs sm-notify in place of statd (with -F, in the foreground).
    check(
        case("notify_only", &["-N", "-F", "-n", "client"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 port:32766")
            .peer("statd-a 127.0.0.2 32766 void"),
    );
}

#[test]
fn nlm_ports() {
    // -T sets both of lockd's ports unless -U came first.
    let c = check(stop(case("nlm_ports", &["-F", "-d", "-L", "-p", "32765", "-T", "4045"])));
    assert!(c.kernel.contains("nlm_tcpport=\"4045\" nlm_udpport=\"4045\""), "{c:#?}");
}

#[test]
fn nlm_ports_udp_first() {
    check(stop(case("nlm_ports_udp_first", &["-F", "-d", "-L", "-p", "32765", "-U", "4046", "-T", "4045"])));
}

#[test]
fn nfs_conf() {
    let conf = "[statd]\nport = 32765\nname = client.example.net\nno-notify = 1\n\
                ha-callout = /run/ha\noutgoing-port = 870\n[lockd]\nport = 4045\n";
    check(stop(
        case("nfs_conf", &["-F", "-d"])
            .etc("nfs.conf", conf.as_bytes())
            .setup("printf '#!/bin/sh\\necho \"$@\" >>/run/ha.log\\n' >/run/ha && chmod 755 /run/ha")
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

#[test]
fn nfs_conf_debug() {
    // `debug` in [statd]: without -d the messages go to syslog.
    check(stop(
        case("nfs_conf_debug", &["-F", "-L", "-p", "32765"])
            .etc("nfs.conf", b"[statd]\ndebug = general\n")
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

#[test]
fn nfs_conf_state_dir() {
    check(stop(
        case("nfs_conf_state_dir", &["-F", "-d", "-L", "-p", "32765"])
            .etc("nfs.conf", b"[statd]\nstate-directory-path = /run/alt\n")
            .setup("mkdir -p /run/alt/sm /run/alt/sm.bak && chown nobody:nobody /run/alt/sm /run/alt/sm.bak")
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

#[test]
fn env_no_notify() {
    check(stop(case("env_no_notify", &["-F", "-d", "-p", "32765"]).env("RPC_STATD_NO_NOTIFY=1")));
}

// ---------------------------------------------------------------------------
// starting and stopping

#[test]
fn start_stop() {
    let c = check(stop(fg("start_stop").probe("dump")));
    assert!(c.peers.contains("rpcb 100024 1 udp 0.0.0.0.127.253 65534"), "{c:#?}");
}

#[test]
fn random_port() {
    check(stop(case("random_port", &["-F", "-d", "-L"]).probe("dump")));
}

#[test]
fn privileged_port() {
    // The listeners are made after dropping privileges (to the owner of sm/): without
    // capabilities, a port below 1024 can't be bound.
    check(case("privileged_port", &["-F", "-d", "-L", "-p", "662"]));
}

#[test]
fn no_rpcbind() {
    let mut c = fg("no_rpcbind");
    c.rpcbind = false;
    check(c);
}

#[test]
fn already_running() {
    check(stop(fg("already_running").peer("other 127.0.0.1 32700 void").before("register 100024 1 17 32700")));
}

#[test]
fn stale_registration() {
    // Registered, but nothing answers there: statd starts, and replaces it.
    check(stop(fg("stale_registration").before("register 100024 1 17 32700").probe("dump")));
}

#[test]
fn daemon_mode() {
    // Not -F: statd backgrounds, logs to syslog, and the parent exits once it's up.
    check(stop(case("daemon_mode", &["-L", "-p", "32765"]).probe(&sm_mon("mon", "peer-a", "client"))));
}

#[test]
fn daemon_mode_debug_ignored() {
    // -d without -F is ignored.
    check(stop(case("daemon_mode_debug_ignored", &["-d", "-L", "-p", "32765"])));
}

#[test]
fn state_file() {
    check(stop(fg("state_file").state("state", &[7, 0, 0, 0])));
}

#[test]
fn not_root_owner() {
    // sm/ owned by root: statd keeps running as root, and says so.
    check(stop(fg("not_root_owner").setup("chown root:root /var/lib/nfs/sm")));
}

#[test]
fn load_state() {
    let c = check(stop(
        fg("load_state")
            .state("sm/peer-a", format!("{}\n", mon_record("peer-a", "client")).as_bytes())
            .state("sm/peer-b", format!("{}\n", mon_record("peer-b", "client")).as_bytes())
            .setup("chown nobody:nobody /var/lib/nfs/sm/peer-a /var/lib/nfs/sm/peer-b"),
    ));
    assert!(c.stderr.contains("Loaded 2 previously monitored hosts"), "{c:#?}");
}

#[test]
fn runs_sm_notify() {
    // Without -L statd runs sm-notify first (here -d, as statd has -F), with -p and -v
    // from -o and -n.
    check(stop(
        case("runs_sm_notify", &["-F", "-d", "-p", "32765", "-o", "870", "-n", "client"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 port:32766")
            .peer("statd-a 127.0.0.2 32766 void"),
    ));
}

#[test]
fn sm_notify_missing() {
    // sm-notify can't run: the child says so and exits 2, and its exit handlers empty
    // the pid file.
    check(stop(
        case("sm_notify_missing", &["-F", "-d", "-p", "32765"]).setup("mount --bind /dev/null /usr/sbin/sm-notify"),
    ));
}

// ---------------------------------------------------------------------------
// SM_MON, SM_UNMON, SM_UNMON_ALL, SM_STAT

#[test]
fn mon_unmon() {
    check(stop(
        fg("mon_unmon").probe(&sm_mon("mon", "peer-a", "client")).probe(&sm_unmon("unmon", "peer-a", "client")),
    ));
}

#[test]
fn mon_kept() {
    let c = check(stop(fg("mon_kept").probe(&sm_mon("mon", "peer-a", "client"))));
    assert!(c.state.contains("./sm/peer-a"), "{c:#?}");
}

#[test]
fn mon_tcp() {
    // The probe closes the connection after the reply: wait for statd to see that
    // (its fifth wait) before stopping it.
    check(stop(
        fg("mon_tcp")
            .probe(&format!("call mon tcp 127.0.0.1 0 2 {}", mon_args("peer-b", "client", PRIV)))
            .expect_n(5, "Waiting for client connections\\n"),
    ));
}

#[test]
fn mon_duplicate() {
    check(stop(
        fg("mon_duplicate").probe(&sm_mon("mon1", "peer-a", "client")).probe(&sm_mon("mon2", "peer-a", "client")),
    ));
}

#[test]
fn mon_new_cookie() {
    check(stop(
        fg("mon_new_cookie")
            .probe(&sm_mon("mon1", "peer-a", "client"))
            .probe(&format!("call mon2 udp 127.0.0.1 800 2 {}", mon_args("peer-a", "client", PRIV2))),
    ));
}

#[test]
fn mon_two_names_one_host() {
    // peer-a and its alias, and its address: matched by canonical name and address.
    check(stop(
        fg("mon_two_names_one_host")
            .probe(&sm_mon("mon1", "peer-a", "client"))
            .probe(&sm_mon("mon2", "peer-a.example.net", "client"))
            .probe(&sm_mon("mon3", "127.0.0.2", "client")),
    ));
}

#[test]
fn mon_address() {
    // An address with a name, and one without (filed under the address itself).
    check(stop(fg("mon_address").probe(&sm_mon("mon1", "127.0.0.3", "client")).probe(&sm_mon(
        "mon2",
        "127.0.0.9",
        "client",
    ))));
}

#[test]
fn mon_ipv6() {
    check(stop(
        fg("mon_ipv6").probe(&sm_mon("mon1", "peer-six", "client")).probe(&sm_mon("mon2", "fd00::5", "client")),
    ));
}

#[test]
fn mon_unknown_host() {
    check(stop(fg("mon_unknown_host").probe(&sm_mon("mon", "no-such-host.invalid", "client"))));
}

#[test]
fn mon_remote_caller() {
    check(stop(
        fg("mon_remote_caller").probe(&format!("call mon udp 10.77.0.9 800 2 {}", mon_args("peer-a", "client", PRIV))),
    ));
}

#[test]
fn mon_not_lockd() {
    check(stop(
        fg("mon_not_lockd")
            .probe(&format!("call mon1 udp 127.0.0.1 800 2 {}{}{PRIV}", xs("peer-a"), my_id("client", 100003, 3, 16)))
            .probe(&format!("call mon2 udp 127.0.0.1 800 2 {}{}{PRIV}", xs("peer-a"), my_id("client", 100021, 4, 17)))
            .probe(&format!("call mon3 udp 127.0.0.1 800 2 {}{}{PRIV}", xs("peer-a"), my_id("client", 100021, 1, 24))),
    ));
}

#[test]
fn mon_bad_names() {
    check(stop(
        fg("mon_bad_names")
            .probe(&sm_mon("slash", "../etc/passwd", "client"))
            .probe(&sm_mon("dot", ".hidden", "client"))
            .probe(&sm_mon("empty", "", "client")),
    ));
}

#[test]
fn mon_white_space() {
    // White space in my_name becomes '_' (in the record too).
    check(stop(fg("mon_white_space").probe(&sm_mon("mon", "peer-a", "my client\tname\r\n"))));
}

#[test]
fn mon_nul_in_name() {
    // XDR strings may hold NULs; statd reads up to the first.
    check(stop(fg("mon_nul_in_name").probe(&format!(
        "call mon udp 127.0.0.1 800 2 {}{}{PRIV}",
        xb(b"peer-a\0junk"),
        my_id("client", LOCKD.0, LOCKD.1, LOCKD.2)
    ))));
}

#[test]
fn unmon_not_monitoring() {
    check(stop(fg("unmon_not_monitoring").probe(&sm_unmon("unmon", "peer-a", "client"))));
}

#[test]
fn unmon_unknown() {
    check(stop(
        fg("unmon_unknown")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_unmon("unmon1", "peer-b", "client"))
            .probe(&sm_unmon("unmon2", "peer-a", "other")),
    ));
}

#[test]
fn unmon_remote_caller() {
    check(stop(fg("unmon_remote_caller").probe(&sm_mon("mon", "peer-a", "client")).probe(&format!(
        "call unmon udp 10.77.0.9 0 3 {}{}",
        xs("peer-a"),
        my_id("client", LOCKD.0, LOCKD.1, LOCKD.2)
    ))));
}

#[test]
fn unmon_all() {
    check(stop(
        fg("unmon_all")
            .probe(&sm_mon("mon1", "peer-a", "client"))
            .probe(&sm_mon("mon2", "peer-b", "client"))
            .probe(&sm_mon("mon3", "multi", "other"))
            .probe(&sm_unmon_all("all", "127.0.0.1", "client"))
            .probe(&sm_unmon_all("again", "127.0.0.1", "client")),
    ));
}

#[test]
fn unmon_all_not_monitoring() {
    check(stop(fg("unmon_all_not_monitoring").probe(&sm_unmon_all("all", "127.0.0.1", "client"))));
}

#[test]
fn unmon_all_remote_stale_state() {
    // A remote SM_UNMON_ALL is refused, and gets the static result as it was: state 0
    // before any local call, then the state number.
    check(stop(
        fg("unmon_all_remote_stale_state")
            .probe(&sm_unmon_all("remote1", "10.77.0.9", "client"))
            .probe(&sm_unmon_all("local", "127.0.0.1", "client"))
            .probe(&sm_unmon_all("remote2", "10.77.0.9", "client")),
    ));
}

#[test]
fn stat() {
    check(stop(
        fg("stat")
            .probe(&sm_stat("known", "peer-a"))
            .probe(&sm_stat("address", "127.0.0.2"))
            .probe(&sm_stat("unknown", "no-such-host.invalid")),
    ));
}

// ---------------------------------------------------------------------------
// SM_NOTIFY and callbacks to lockd

#[test]
fn notify_callback() {
    check(stop(
        lockd(fg("notify_callback"), "void")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 1")
            .expect("succeeded"),
    ));
}

#[test]
fn notify_by_address() {
    // The notifying host's address matches though the name doesn't.
    check(stop(
        lockd(fg("notify_by_address"), "void")
            .probe(&sm_mon("mon", "client", "me"))
            .probe(&sm_notify("notify", "10.77.0.9", "some-other-name", 3))
            .probe("wait lockd 1")
            .expect("succeeded"),
    ));
}

#[test]
fn notify_same_state_twice() {
    check(stop(
        lockd(fg("notify_same_state_twice"), "void")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("n1", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 1")
            .expect("succeeded")
            .probe(&sm_notify("n2", "127.0.0.2", "peer-a", 5))
            .probe(&sm_notify("n3", "127.0.0.2", "peer-a", 7))
            .probe("wait lockd 2")
            .expect_n(2, "succeeded"),
    ));
}

#[test]
fn notify_two_monitors() {
    check(stop(
        lockd(fg("notify_two_monitors"), "void")
            .probe(&sm_mon("mon1", "peer-a", "client"))
            .probe(&format!("call mon2 udp 127.0.0.1 800 2 {}", mon_args("peer-a.example.net", "other", PRIV2)))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 9))
            .probe("wait lockd 2")
            .expect("Callback to client (for peer-a) succeeded")
            .expect("Callback to other (for peer-a.example.net) succeeded"),
    ));
}

#[test]
fn notify_not_monitoring() {
    check(stop(fg("notify_not_monitoring").probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))));
}

#[test]
fn notify_unknown_host() {
    check(stop(lockd(fg("notify_unknown_host"), "void").probe(&sm_mon("mon", "peer-a", "client")).probe(&sm_notify(
        "notify",
        "127.0.0.3",
        "peer-b",
        5,
    ))));
}

#[test]
fn notify_from_ipv6() {
    check(stop(
        lockd(fg("notify_from_ipv6"), "void")
            .probe(&sm_mon("mon", "peer-six", "client"))
            .probe(&format!("call notify udp fd00::5 0 6 {}{}", xs("peer-six"), xi(3)))
            .probe("wait lockd 1")
            .expect("succeeded"),
    ));
}

#[test]
fn notify_loaded_record() {
    // A record from sm/ at startup is monitored like one from SM_MON.
    check(stop(
        lockd(fg("notify_loaded_record"), "void")
            .state("sm/peer-a", format!("{}\n", mon_record("peer-a", "client")).as_bytes())
            .setup("chown nobody:nobody /var/lib/nfs/sm/peer-a")
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a.example.net", 11))
            .probe("wait lockd 1")
            .expect("succeeded"),
    ));
}

#[test]
fn callback_lockd_not_registered() {
    check(stop(
        fg("callback_lockd_not_registered")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .expect("not registered on localhost"),
    ));
}

#[test]
fn callback_retries_give_up() {
    // lockd never answers: five calls, five seconds apart, then statd gives up.
    check(stop(
        lockd(fg("callback_retries_give_up"), "drop")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 4")
            .expect("giving up"),
    ));
}

#[test]
fn callback_error_reply() {
    // An error reply ends nothing: it's not matched, and the call is retried.
    check(stop(
        lockd(fg("callback_error_reply"), "accept:3,void")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 2")
            .expect("succeeded"),
    ));
}

#[test]
fn ha_callout() {
    check(stop(
        lockd(case("ha_callout", &["-F", "-d", "-L", "-p", "32765", "-H", "/run/ha"]), "void")
            .setup("printf '#!/bin/sh\\necho \"$@\" >>/run/ha.log\\nexit 3\\n' >/run/ha && chmod 755 /run/ha")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 1")
            .expect("succeeded")
            .probe(&sm_unmon("unmon", "peer-a", "client")),
    ));
}

#[test]
fn ha_callout_missing() {
    check(stop(
        case("ha_callout_missing", &["-F", "-d", "-L", "-p", "32765", "-H", "/nonexistent"])
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

// ---------------------------------------------------------------------------
// SM_SIMU_CRASH, signals

#[test]
fn simu_crash() {
    // From a reserved loopback port: statd forgets its monitor list and restarts its
    // loop (running sm-notify again, without -L).
    check(stop(
        case("simu_crash", &["-F", "-d", "-p", "32765"])
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe("call crash udp 127.0.0.1 700 5")
            .probe(&sm_unmon("unmon", "peer-a", "client")),
    ));
}

#[test]
fn simu_crash_refused() {
    check(stop(
        fg("simu_crash_refused")
            .probe("call unprivileged udp 127.0.0.1 2000 5")
            .probe("call remote udp 10.77.0.9 700 5")
            .probe("call ipv6 udp ::1 700 5"),
    ));
}

#[test]
fn sigusr1() {
    check(stop(fg("sigusr1").probe("kill USR1").expect("re-notifying")));
}

#[test]
fn sighup() {
    check(fg("sighup").probe("kill HUP").probe("gone").probe("dump"));
}

#[test]
fn sigusr2_toggles_debug() {
    check(stop(
        case("sigusr2_toggles_debug", &["-F", "-L", "-p", "32765"])
            .probe("kill USR2")
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

// ---------------------------------------------------------------------------
// odd calls

#[test]
fn unknown_procedure() {
    check(stop(fg("unknown_procedure").probe("call p7 udp 127.0.0.1 800 7").probe("call p0 udp 127.0.0.1 800 0")));
}

#[test]
fn garbage_arguments() {
    check(stop(
        fg("garbage_arguments")
            .probe("call short udp 127.0.0.1 800 2 0000000470656572")
            .probe("call long_name udp 127.0.0.1 800 1 00000401"),
    ));
}

#[test]
fn wrong_version_and_program() {
    check(stop(
        fg("wrong_version_and_program")
            .probe("raw vers udp 127.0.0.1 800 XID0000000000000002000186b8000000020000000000000000000000000000000000")
            .probe("raw prog udp 127.0.0.1 800 XID000000000000000200018000000000010000000000000000000000000000000000"),
    ));
}
