//! Differential tests for sm-notify: options and `nfs.conf`, the state directory (the
//! `state` file, `sm/` retired to `sm.bak/`, the records), the calls to peers (rpcbind
//! lookups over IPv4 and IPv6, `SM_NOTIFY` with and without the domain, retries and
//! giving up), and odd replies.

mod common;

use common::{Case, check, record};

const HOSTS: &str = "127.0.0.1 localhost\n::1 localhost\n\
127.0.0.2 peer-a peer-a.example.net\n127.0.0.3 peer-b\nfd00::5 peer-six\n\
127.0.0.4 multi\n127.0.0.5 multi\n10.77.0.9 client.example.net client\n";

fn case(name: &str, args: &[&str]) -> Case {
    Case::new(name, "sm-notify", args)
        .etc("hosts", HOSTS.as_bytes())
        .setup("ip addr add fd00::5/128 dev lo nodad")
        .setup("ip addr add 10.77.0.9/32 dev lo")
}

/// A peer at ADDR whose rpcbind says statd is on 32765, and whose statd answers.
fn good_peer(c: Case, name: &str, addr: &str) -> Case {
    c.peer(&format!("rpcbind-{name} {addr} 111 port:32765")).peer(&format!("statd-{name} {addr} 32765 void"))
}

// ---------------------------------------------------------------------------
// options

#[test]
fn usage_bad_option() {
    check(case("usage_bad_option", &["-x"]));
}

#[test]
fn usage_operand() {
    check(case("usage_operand", &["-d", "extra"]));
}

#[test]
fn usage_missing_argument() {
    check(case("usage_missing_argument", &["-m"]));
}

#[test]
fn state_dir_missing() {
    check(case("state_dir_missing", &["-d", "-P", "/nonexistent"]));
}

#[test]
fn state_dir_relative() {
    check(case("state_dir_relative", &["-d", "-P", "nfs"]).setup("mkdir -p /run/nfs && cd /run"));
}

#[test]
fn state_dir_too_long() {
    let long = format!("/{}", "x".repeat(4100));
    check(case("state_dir_too_long", &["-d", "-P", &long]));
}

#[test]
fn state_dir_other() {
    // Not the default directory: no pid file, and the records live there.
    check(
        case("state_dir_other", &["-d", "-P", "/run/alt"])
            .setup("mkdir -p /run/alt/sm /run/alt/sm.bak && chown nobody:nobody /run/alt/sm /run/alt/sm.bak")
            .setup(&format!("printf '%s\\n' '{}' >/run/alt/sm/peer-a", record("peer-a", "client")))
            .peer("rpcbind-a 127.0.0.2 111 port:32765")
            .peer("statd-a 127.0.0.2 32765 void"),
    );
}

// ---------------------------------------------------------------------------
// no hosts

#[test]
fn no_hosts_debug() {
    let c = check(case("no_hosts_debug", &["-d"]));
    assert!(c.stderr.contains("No hosts to notify"), "{c:#?}");
}

#[test]
fn no_hosts_syslog() {
    let c = check(case("no_hosts_syslog", &[]));
    assert!(c.kernel.contains("nlm_end_grace=\"Y\""), "{c:#?}");
}

#[test]
fn no_state_dirs() {
    check(Case::bare("no_state_dirs", "sm-notify", &["-d"]));
}

#[test]
fn already_running() {
    check(case("already_running", &["-d"]).setup("echo 1 >/run/sm-notify.pid"));
}

#[test]
fn already_running_force() {
    check(good_peer(
        case("already_running_force", &["-d", "-f"])
            .setup("echo 1 >/run/sm-notify.pid")
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn already_running_no_update() {
    check(good_peer(
        case("already_running_no_update", &["-d", "-n"])
            .setup("echo 1 >/run/sm-notify.pid")
            .state("state", &5i32.to_ne_bytes())
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

// ---------------------------------------------------------------------------
// notifying

#[test]
fn notify_one_peer() {
    let c = check(good_peer(
        case("notify_one_peer", &["-d"]).notify("peer-a", &[&record("peer-a", "client.example.net")]),
        "a",
        "127.0.0.2",
    ));
    assert!(c.peers.contains("statd-a got"), "{c:#?}");
}

#[test]
fn notify_backgrounded() {
    check(good_peer(
        case("notify_backgrounded", &[]).notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn notify_retired_from_sm() {
    // Records in sm/ move to sm.bak/ first; a directory and a dot file are skipped.
    check(good_peer(
        case("notify_retired_from_sm", &["-d"])
            .state("sm/peer-a", format!("{}\n", record("peer-a", "client")).as_bytes())
            .state("sm/.hidden", b"x\n")
            .setup("mkdir /var/lib/nfs/sm/adir"),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn notify_several_peers_in_mtime_order() {
    let c = case("notify_several_peers_in_mtime_order", &["-d"])
        .notify("peer-a", &[&record("peer-a", "client")])
        .notify("peer-b", &[&record("peer-b", "client")])
        .notify("peer-six", &[&record("peer-six", "client")])
        .setup("touch -d @1795600000 /var/lib/nfs/sm.bak/peer-a")
        .setup("touch -d @1795600500 /var/lib/nfs/sm.bak/peer-b")
        .setup("touch -d @1795600200 /var/lib/nfs/sm.bak/peer-six")
        .peer("statd-six fd00::5 32766 void")
        .peer("rpcbind-six fd00::5 111 uaddr:fd00::5.127.254");
    check(good_peer(good_peer(c, "a", "127.0.0.2"), "b", "127.0.0.3"));
}

#[test]
fn notify_two_records_one_file() {
    // Two my_names for one peer: two entries, and the file is rewritten after the first.
    check(good_peer(
        case("notify_two_records_one_file", &["-d"])
            .notify("peer-a", &[&record("peer-a", "client"), &record("peer-a", "other.name")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn notify_ipv6_getaddr() {
    check(
        case("notify_ipv6_getaddr", &["-d"])
            .notify("peer-six", &[&record("peer-six", "client")])
            .peer("rpcbind-six fd00::5 111 uaddr:fd00::5.127.254")
            .peer("statd-six fd00::5 32766 void"),
    );
}

#[test]
fn notify_ipv6_not_registered() {
    check(
        case("notify_ipv6_not_registered", &["-d", "-m", "5"])
            .notify("peer-six", &[&record("peer-six", "client")])
            .peer("rpcbind-six fd00::5 111 uaddr:,uaddr:,uaddr:fd00::5.127.254")
            .peer("statd-six fd00::5 32766 void"),
    );
}

#[test]
fn notify_ipv6_bad_uaddr() {
    check(
        case("notify_ipv6_bad_uaddr", &["-d", "-m", "3"])
            .notify("peer-six", &[&record("peer-six", "client")])
            .peer("rpcbind-six fd00::5 111 uaddr:fd00::5.1.300,uaddr:nodots,uaddr:fd00::5.1.,uaddr:fd00::5.+1.+2")
            .peer("statd-six fd00::5 258 void"),
    );
}

#[test]
fn notify_no_statd_then_statd() {
    // GETPORT says 0 (no statd): deferred for two minutes, then found.
    check(
        case("notify_no_statd_then_statd", &["-d"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 port:0,port:32765")
            .peer("statd-a 127.0.0.2 32765 void"),
    );
}

#[test]
fn notify_bad_port() {
    check(
        case("notify_bad_port", &["-d", "-m", "3"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 port:70000,port:32765")
            .peer("statd-a 127.0.0.2 32765 void"),
    );
}

#[test]
fn notify_silent_peer_gives_up() {
    // Nobody answers: backoff, a fresh port lookup after four tries, then give up.
    check(case("notify_silent_peer_gives_up", &["-d", "-m", "4"]).notify("peer-a", &[&record("peer-a", "client")]));
}

#[test]
fn notify_silent_statd_relookup() {
    // statd never answers: the port is looked up again every fourth try.
    check(
        case("notify_silent_statd_relookup", &["-d", "-m", "3"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 port:32765")
            .peer("statd-a 127.0.0.2 32765 drop"),
    );
}

#[test]
fn notify_rotates_addresses() {
    // QUIRK: glibc lists 127.0.0.4 then .5; the first try drops .4, and .5 is all that's
    // left after that.
    check(
        case("notify_rotates_addresses", &["-d", "-m", "3"])
            .notify("multi", &[&record("multi", "client")])
            .peer("rpcbind-m5 127.0.0.5 111 drop")
            .peer("rpcbind-m4 127.0.0.4 111 port:32765")
            .peer("statd-m4 127.0.0.4 32765 void"),
    );
}

#[test]
fn notify_rotates_three_addresses() {
    let hosts = format!("{HOSTS}127.0.0.6 tri\n127.0.0.7 tri\n127.0.0.8 tri\n");
    check(
        case("notify_rotates_three_addresses", &["-d", "-m", "3"])
            .etc("hosts", hosts.as_bytes())
            .notify("tri", &[&record("tri", "client")])
            .peer("rpcbind-t6 127.0.0.6 111 port:32765")
            .peer("rpcbind-t7 127.0.0.7 111 drop")
            .peer("rpcbind-t8 127.0.0.8 111 port:32765")
            .peer("statd-t8 127.0.0.8 32765 void"),
    );
}

#[test]
fn notify_unknown_host() {
    check(case("notify_unknown_host", &["-d", "-m", "2"]).notify("no-such-host", &[&record("no-such-host", "client")]));
}

#[test]
fn notify_daemon_gives_up() {
    check(case("notify_daemon_gives_up", &["-m", "2"]).notify("peer-a", &[&record("peer-a", "client")]));
}

#[test]
fn notify_ten_at_a_time() {
    let mut hosts = String::from(HOSTS);
    let mut c = case("notify_ten_at_a_time", &["-d"]);
    for i in 0..12 {
        hosts.push_str(&format!("127.0.1.{} many{i}\n", i + 1));
        c = c.notify(&format!("many{i}"), &[&record(&format!("many{i}"), "client")]);
        c = good_peer(c, &format!("m{i}"), &format!("127.0.1.{}", i + 1));
    }
    check(c.etc("hosts", hosts.as_bytes()));
}

// ---------------------------------------------------------------------------
// odd replies

#[test]
fn reply_denied_and_errors() {
    check(
        case("reply_denied_and_errors", &["-d", "-m", "2"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 denied,accept:1,accept:2,hex:XID00000001000000000000000000000002,port:32765")
            .peer("statd-a 127.0.0.2 32765 void"),
    );
}

#[test]
fn reply_garbage() {
    check(
        case("reply_garbage", &["-d", "-m", "2"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 hex:00,hex:XID00000000,hex:12345678000000010000000000000000000000000000000000007ffd,hex:XID0000000100000000,port:32765")
            .peer("statd-a 127.0.0.2 32765 hex:XID000000010000000300000000,void"),
    );
}

#[test]
fn reply_short_getport() {
    check(
        case("reply_short_getport", &["-d", "-m", "2"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("rpcbind-a 127.0.0.2 111 void,port:32765")
            .peer("statd-a 127.0.0.2 32765 void"),
    );
}

// ---------------------------------------------------------------------------
// records

#[test]
fn records_malformed() {
    check(good_peer(
        case("records_malformed", &["-d", "-m", "1"])
            .notify("peer-a", &["garbage", &record("peer-a", "client"), "1 2 3"])
            .notify("peer-b", &["not a record at all"])
            .state("sm.bak/empty", b"")
            .setup("mkdir /var/lib/nfs/sm.bak/adir"),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn records_hex_variants() {
    // scanf's %8x takes leading blanks, a sign and a 0x prefix (all within the width);
    // the cookie is read at the fixed offset 36, so these keep the fields 36 wide.
    let prefixed = "0x00007f -0000001 +0000004 00000010 0123456789ABCDEF0123456789abcdef peer-a  client.example.net";
    let blanks = "      7f        1        4       10 0123456789abcdef0123456789abcdef peer-a other";
    check(good_peer(case("records_hex_variants", &["-d"]).notify("peer-a", &[prefixed, blanks]), "a", "127.0.0.2"));
}

#[test]
fn records_short_line_leftovers() {
    // QUIRK: a short line's cookie and names come from the line before it, left in the
    // buffer: here mon_name "peer-a" and an empty my_name.
    check(good_peer(
        case("records_short_line_leftovers", &["-d"]).notify("peer-a", &[&record("peer-a", "client"), "1 2 3 4"]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn records_bad_file_name() {
    check(case("records_bad_file_name", &["-d"]).state("sm.bak/has space", b"x\n").state("sm/sp ace", b"x\n"));
}

#[test]
fn records_long_line() {
    let long = format!("{} {}", record("peer-a", "client"), "y".repeat(1200));
    check(good_peer(case("records_long_line", &["-d", "-m", "1"]).notify("peer-a", &[&long]), "a", "127.0.0.2"));
}

// ---------------------------------------------------------------------------
// the state file and privileges

#[test]
fn state_even_number() {
    check(good_peer(
        case("state_even_number", &["-d"])
            .state("state", &8i32.to_ne_bytes())
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn state_short_file() {
    check(good_peer(
        case("state_short_file", &["-d"]).state("state", b"\x05").notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn state_no_update() {
    check(good_peer(
        case("state_no_update", &["-d", "-n"])
            .state("state", &7i32.to_ne_bytes())
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn state_is_a_directory() {
    check(
        case("state_is_a_directory", &["-d"])
            .setup("mkdir /var/lib/nfs/state")
            .notify("peer-a", &[&record("peer-a", "client")]),
    );
}

#[test]
fn state_dir_read_only() {
    check(
        case("state_dir_read_only", &["-d"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .setup("chmod 555 /var/lib/nfs && mount -o remount,bind,ro /var/lib/nfs"),
    );
}

#[test]
fn sm_owned_by_root() {
    check(good_peer(
        case("sm_owned_by_root", &["-d"])
            .setup("chown root:root /var/lib/nfs/sm")
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn sm_missing_after_retire() {
    // sm/ is gone, so the privilege drop can't stat it.
    check(
        case("sm_missing_after_retire", &["-d"])
            .setup("rmdir /var/lib/nfs/sm")
            .notify("peer-a", &[&record("peer-a", "client")]),
    );
}

// ---------------------------------------------------------------------------
// source address and port

#[test]
fn source_name_numeric() {
    // -v with an address: its canonical name is sent, and the socket is bound to it.
    check(good_peer(
        case("source_name_numeric", &["-d", "-v", "10.77.0.9"]).notify("peer-a", &[&record("peer-a", "ignored.name")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn source_name_no_reverse() {
    check(case("source_name_no_reverse", &["-d", "-v", "10.77.0.10"]).notify("peer-a", &[&record("peer-a", "x")]));
}

#[test]
fn source_name_plain() {
    check(good_peer(
        case("source_name_plain", &["-d", "-v", "client"]).notify("peer-a", &[&record("peer-a", "x")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn source_port() {
    check(good_peer(
        case("source_port", &["-d", "-p", "4321"]).notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn source_port_invalid() {
    check(case("source_port_invalid", &["-d", "-p", "nope"]).notify("peer-a", &[&record("peer-a", "client")]));
}

#[test]
fn source_port_in_use() {
    check(
        case("source_port_in_use", &["-d", "-p", "4321"])
            .notify("peer-a", &[&record("peer-a", "client")])
            .peer("squatter 0.0.0.0 4321 drop"),
    );
}

// ---------------------------------------------------------------------------
// nfs.conf

#[test]
fn conf_sm_notify_section() {
    let conf = "[sm-notify]\n  retry-time = 1\noutgoing-port=4322 # a comment\nlift-grace = n\nupdate-state=no\n\
[statd]\nstate-directory-path = \"/run/alt\"\n";
    check(good_peer(
        case("conf_sm_notify_section", &["-d"])
            .etc("nfs.conf", conf.as_bytes())
            .setup("mkdir -p /run/alt/sm /run/alt/sm.bak && chown nobody:nobody /run/alt/sm /run/alt/sm.bak")
            .setup(&format!("printf '%s\\n' '{}' >/run/alt/sm.bak/peer-a", record("peer-a", "client"))),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn conf_debug_to_syslog() {
    // debug= turns on logging without -d: debug messages go to syslog.
    check(good_peer(
        case("conf_debug_to_syslog", &[])
            .etc("nfs.conf", b"[sm-notify]\ndebug = general, bogus ,all\n")
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn conf_errors() {
    let conf = "orphan = 1\n[sm-notify\n[ok]\njust words\n = novalue\nq = \"unterminated\n[x \"sub\n\
[sm-notify]\nforce = maybe\nretry-time\t=\t2\nlast = line";
    check(case("conf_errors", &["-d"]).etc("nfs.conf", conf.as_bytes()));
}

#[test]
fn conf_includes_and_dir() {
    // nfs.conf.d goes in version order (9-b before 10-a); only *.conf files count.
    // Without -d, debug = all sends debug messages to syslog; lift-grace = off from the
    // include keeps nlm_end_grace untouched.
    let main =
        "[sm-notify]\nretry-time = 7\ninclude = extra.conf\ninclude = -missing.conf\ninclude = /etc/missing2.conf\n";
    check(
        case("conf_includes_and_dir", &[])
            .etc("nfs.conf", main.as_bytes())
            .etc("extra.conf", b"lift-grace = off\n[statd]\nname = x\n")
            .etc("nfs.conf.d/10-a.conf", b"[sm-notify]\ndebug = call\n")
            .etc("nfs.conf.d/9-b.conf", b"[sm-notify]\nretry-time = 8\ndebug = all\n")
            .etc("nfs.conf.d/notconf.txt", b"[sm-notify]\ndebug = general\n")
            .etc("nfs.conf.d/.conf", b"x\n")
            .setup("mkdir /etc/nfs.conf.d/dir.conf"),
    );
}

#[test]
fn conf_dir_overrides_main() {
    // A later file's value wins; force = yes from nfs.conf.d beats the pid file.
    check(good_peer(
        case("conf_dir_overrides_main", &["-d"])
            .etc("nfs.conf", b"[sm-notify]\nforce = no\n")
            .etc("nfs.conf.d/a.conf", b"[sm-notify]\nforce = yes\n")
            .setup("echo 1 >/run/sm-notify.pid")
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn conf_environment_values() {
    let conf = "[environment]\nretry = 3\n[sm-notify]\nretry-time = $retry\noutgoing-port = $SMPORT\n";
    check(good_peer(
        case("conf_environment_values", &["-d"])
            .etc("nfs.conf", conf.as_bytes())
            .env("SMPORT=4323")
            .notify("peer-a", &[&record("peer-a", "client")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn conf_continuation_and_case() {
    let conf = "[SM-Notify]\nRETRY-TIME = 1\\\n0\noutgoing-addr = 'client'\n";
    check(good_peer(
        case("conf_continuation_and_case", &["-d"])
            .etc("nfs.conf", conf.as_bytes())
            .notify("peer-a", &[&record("peer-a", "x")]),
        "a",
        "127.0.0.2",
    ));
}

#[test]
fn conf_bad_state_directory() {
    check(case("conf_bad_state_directory", &[]).etc("nfs.conf", b"[statd]\nstate-directory-path = /nope\n"));
}
