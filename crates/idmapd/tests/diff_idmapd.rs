//! rpc.idmapd against the C one: its options and settings, nfsd's text upcalls on the
//! `/proc/net/rpc` channels, the NFS client's binary ones on `rpc_pipefs`, the
//! directory scans (inotify and signals), and libevent's loop. The channels are
//! sockets the probe listens on (see `tests/shim/fakepipes.c`); the probe makes the
//! `rpc_pipefs` tree and drives the program.

#[path = "../../statd/tests/common/mod.rs"]
mod common;
mod idmap;

use common::{Case, check};
use idmap::*;

const PIPEFS: &str = "/var/lib/nfs/rpc_pipefs/nfs";

/// A case for rpc.idmapd with `conf` as idmapd.conf and an empty `rpc_pipefs/nfs`.
fn ic(name: &str, args: &[&str], conf: &str) -> Case {
    icase(&format!("idmapd_{name}"), "rpc.idmapd", args, conf).setup(&format!("mkdir -p {PIPEFS}"))
}

/// nfsd's channels and flush files, listened on as `nametoid` and `idtoname`.
fn nfsd(c: Case) -> Case {
    c.file("procrpc/nfs4.nametoid/flush", b"")
        .file("procrpc/nfs4.idtoname/flush", b"")
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel")
        .before("listen idtoname @T@/procrpc/nfs4.idtoname/channel")
}

/// A client directory `clntN` with its idmap pipe, there before the program starts.
fn client(c: Case, n: &str) -> Case {
    c.before(&format!("listen clnt{n} {PIPEFS}/clnt{n}/idmap"))
}

#[test]
fn server_upcalls() {
    let c = nfsd(ic("server_upcalls", &["-f", "-vvv"], &conf("")))
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("up idtoname nfsd group 50%0a")
        .probe("fds");
    check(c);
}

#[test]
fn client_upcalls() {
    let c = client(ic("client_upcalls", &["-f", "-vvv"], &conf("")), "0")
        .probe("msg clnt0 0 1 0 0 bob@example.org")
        .probe("msg clnt0 1 0 0 100 -")
        .probe("fds");
    check(c);
}

/// `[General]` with `Domain` and `extra`, then `mapping` as `[Mapping]`.
fn mconf(general: &str, mapping: &str) -> String {
    format!("[General]\nDomain = example.org\n{general}[Mapping]\n{mapping}")
}

/// nfsd and one client, in the foreground at -vvv.
fn both(name: &str, conf: &str) -> Case {
    client(nfsd(ic(name, &["-f", "-vvv"], conf)), "0")
}

// --- Options and settings --------------------------------------------------------

#[test]
fn help() {
    check(ic("help", &["-h"], &conf("")));
}

#[test]
fn invalid_option() {
    check(ic("invalid_option", &["-x"], &conf("")));
}

#[test]
fn missing_argument() {
    check(ic("missing_argument", &["-f", "-p"], &conf("")));
}

#[test]
fn colon_option() {
    // '-:' is "in" the option string, so it "requires an argument".
    check(ic("colon_option", &["-:"], &conf("")));
}

#[test]
fn removed_options() {
    check(ic("removed_d", &["-f", "-d", "example.org"], &conf("")));
    check(ic("removed_u", &["-U", "nobody"], &conf("")));
    check(ic("removed_g", &["-G", "nobody", "-f"], &conf("")));
}

#[test]
fn client_and_server_only() {
    check(ic("both_c_s", &["-C", "-S"], &conf("")));
    check(ic("conf_both_only", &["-f"], &conf("server-only = yes\nclient-only = 1\n")));
}

#[test]
fn h_after_conf_warnings() {
    // The configuration is read before the second pass sees -h.
    check(ic("h_after_conf", &["-c", "/nonexistent", "-h"], &conf("")));
}

#[test]
fn c_missing_file() {
    // Nothing is read: the cache expiry is 0, not 600, and goes to the kernel.
    let c = both("c_missing", &conf("Verbosity = 5\n"))
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("msg clnt0 0 0 0 1001 -");
    let mut c = c;
    c.args = vec!["-f".into(), "-c".into(), "/nonexistent".into()];
    check(c);
}

#[test]
fn c_file() {
    let alt = "[General]\nVerbosity = 2\nCache-Expiration = 77\nPipefs-Directory = /var/lib/nfs/alt\n\
               Domain = example.org\n[Mapping]\nNobody-User = bob\nNobody-Group = staff\n";
    let c = ic("c_file", &["-f", "-c", "/etc/alt.conf"], &conf("Verbosity = 0\n"))
        .etc("alt.conf", alt.as_bytes())
        .setup("mkdir -p /var/lib/nfs/alt/nfs");
    let c = nfsd(c)
        .before("listen clnt7 /var/lib/nfs/alt/nfs/clnt7/idmap")
        .probe("up idtoname nfsd user 4242%0a")
        .probe("up nametoid nfsd group nosuch@example.org%0a")
        .probe("msg clnt7 1 0 0 4242 -");
    check(c);
}

#[test]
fn c_twice() {
    check(ic("c_twice", &["-c", "/nonexistent", "-c", "/etc/idmapd.conf", "-f", "-C"], &conf("Verbosity = 3\n")));
}

#[test]
fn c_directory() {
    check(ic("c_directory", &["-f", "-c", "/etc", "-v"], &conf("")));
}

#[test]
fn default_files() {
    // nfs.conf gives the pipefs directory; idmapd.conf's own is ignored without -c.
    let c = ic(
        "default_files",
        &["-f"],
        &conf("Verbosity = 3\nPipefs-Directory = /var/lib/nfs/ignored\ncache-expiration = 30\n"),
    )
    .etc("nfs.conf", b"[general]\npipefs-directory = /var/lib/nfs/fromnfsconf\n[General]\nVerbosity = 9\n")
    .setup("mkdir -p /var/lib/nfs/fromnfsconf/nfs /var/lib/nfs/ignored/nfs")
    .before("listen clnt1 /var/lib/nfs/fromnfsconf/nfs/clnt1/idmap")
    .probe("msg clnt1 0 0 0 1000 -");
    check(nfsd(c).probe("up nametoid nfsd user alice@example.org%0a"));
}

#[test]
fn p_option() {
    let c = ic("p_option", &["-f", "-vvv", "-p", "/var/lib/nfs/pp"], &conf(""))
        .setup("mkdir -p /var/lib/nfs/pp/nfs")
        .before("listen clnt3 /var/lib/nfs/pp/nfs/clnt3/idmap")
        .probe("msg clnt3 0 1 0 0 alice@example.org");
    check(c);
}

#[test]
fn p_too_long() {
    // Cut at PATH_MAX - 1 bytes; "/nfs" then doesn't fit, which the fortified strncat()
    // catches. One byte less fits, and is then too long for inotify.
    let long = format!("/{}", "d".repeat(5000));
    check(ic("p_too_long", &["-f", "-p", &long], &conf("")));
    let fits = format!("/{}", "d".repeat(4090));
    check(ic("p_just_fits", &["-f", "-p", &fits], &conf("")));
    let over = format!("/{}", "d".repeat(4091));
    check(ic("p_one_over", &["-f", "-p", &over], &conf("")));
}

#[test]
fn no_pipefs() {
    check(ic("no_pipefs", &["-f", "-p", "/nonexistent"], &conf("")));
}

#[test]
fn nobody_unknown() {
    check(ic("nobody_user", &["-f"], &mconf("", "Nobody-User = nosuchuser\n")));
    check(ic("nobody_group", &["-f"], &mconf("", "Nobody-Group = nosuchgroup\n")));
}

#[test]
fn nobody_unknown_daemon() {
    // After daemon_init(): the message goes to /dev/null and the parent exits 1.
    check(ic("nobody_daemon", &[], &mconf("", "Nobody-User = nosuchuser\n")));
}

#[test]
fn bad_method() {
    check(ic("bad_method", &["-f", "-v"], &conf("[Translation]\nMethod = umich_ldap\n")));
}

#[test]
fn verbosity_levels() {
    for v in ["0", "1", "2"] {
        let c = both(&format!("verbosity_{v}"), &conf(&format!("Verbosity = {v}\n")))
            .probe("up nametoid nfsd user nosuch@example.org%0a")
            .probe("msg clnt0 0 1 0 0 alice@example.org");
        let mut c = c;
        c.args = vec!["-f".into()];
        check(c);
    }
}

#[test]
fn v_adds_to_verbosity() {
    check(nfsd(ic("v_adds", &["-f", "-v", "-v"], &conf("Verbosity = 1\n"))));
}

#[test]
fn cache_expiration() {
    let c = both("cache_expiration", &conf("cache-expiration = -5\n"))
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("up idtoname nfsd user 1000%0a");
    check(c);
}

#[test]
fn cache_timeout_unwritable() {
    // The kernel's file without the sandbox's stand-in: not ours to open.
    let c = ic("cache_timeout_unwritable", &["-f"], &conf("cache-expiration = 30\n"))
        .setup("umount /proc/sys/fs/nfs/idmap_cache_timeout");
    check(c);
}

#[test]
fn daemon_mode() {
    // daemon_init()'s descriptor 3 is closed once the program is ready, so the first
    // client's directory takes it.
    let c = client(nfsd(ic("daemon_mode", &["-v"], &conf(""))), "0")
        .probe("fds")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("msg clnt0 0 1 0 0 bob@example.org");
    check(c);
}

// --- nfsd's channels -------------------------------------------------------------

#[test]
fn server_only_no_nfsd() {
    check(ic("server_only_no_nfsd", &["-f", "-S", "-v"], &conf("")));
}

#[test]
fn server_only() {
    // No SIGTERM handler without the client side: the default action.
    let c = nfsd(ic("server_only", &["-f", "-S", "-vvv"], &conf("")))
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("fds");
    check(c);
}

#[test]
fn server_only_signals() {
    // SIGUSR1 is still xlog's debug toggle; SIGHUP kills.
    let c = nfsd(ic("server_only_signals", &["-f", "-S"], &conf("")))
        .probe("kill USR1")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("kill HUP");
    check(c);
}

#[test]
fn client_only_hup_opens_nfsd() {
    // -C never opens nfsd's channels, but SIGHUP "reopens" them.
    let c = nfsd(ic("client_only_hup", &["-f", "-C", "-vvv"], &conf("")))
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("kill HUP")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("up idtoname nfsd user 1001%0a");
    check(c);
}

#[test]
fn nfsd_half_present() {
    // nametoid opens, idtoname doesn't: no flush, and with -S "neither" was found,
    // after nametoid's event was added.
    let c = ic("nfsd_half", &["-f", "-S", "-vvv"], &conf(""))
        .file("procrpc/nfs4.nametoid/flush", b"")
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel");
    check(c);
    let c = ic("nfsd_half_client", &["-f", "-vvv"], &conf(""))
        .file("procrpc/nfs4.nametoid/flush", b"")
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel")
        .probe("up nametoid nfsd user alice@example.org%0a");
    check(c);
}

#[test]
fn flush_missing() {
    let c = ic("flush_missing", &["-f"], &conf(""))
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel")
        .before("listen idtoname @T@/procrpc/nfs4.idtoname/channel");
    check(c);
    let c = ic("flush_half", &["-f"], &conf(""))
        .file("procrpc/nfs4.idtoname/flush", b"")
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel")
        .before("listen idtoname @T@/procrpc/nfs4.idtoname/channel");
    check(c);
}

/// nfsd's channels only, in the foreground at -vvv.
fn server(name: &str) -> Case {
    nfsd(ic(name, &["-f", "-vvv"], &mconf("", "Nobody-User = bob\nNobody-Group = staff\n")))
}

#[test]
fn name_to_id() {
    let c = server("name_to_id")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("up nametoid nfsd group staff@example.org%0a")
        .probe("up nametoid nfsd user nosuch@example.org%0a")
        .probe("up nametoid nfsd group alice@other.org%0a")
        .probe("up nametoid nfsd user root%0a")
        .probe("up nametoid nfsd frobnicate users@example.org%0a");
    check(c);
}

#[test]
fn id_to_name() {
    let c = server("id_to_name")
        .probe("up idtoname nfsd user 1000%0a")
        .probe("up idtoname nfsd group 100%0a")
        .probe("up idtoname nfsd user 4242%0a")
        .probe("up idtoname nfsd group 4242%0a")
        .probe("up idtoname nfsd user 4294967294%0a")
        .probe("up idtoname nfsd other 0%0a");
    check(c);
}

#[test]
fn id_parsing() {
    let c = server("id_parsing")
        .probe("up idtoname nfsd user 4294967295%0a")
        .probe("up idtoname nfsd user 4294967296%0a")
        .probe("up idtoname nfsd user -1%0a")
        .probe("up idtoname nfsd user abc%0a")
        .probe("up idtoname nfsd user +1001%0a")
        .probe("up idtoname nfsd user 1000xyz%0a")
        .probe("up idtoname nfsd user 99999999999999999999999%0a");
    check(c);
}

#[test]
fn long_nobody() {
    let long = "n".repeat(130);
    let c = nfsd(ic("long_nobody", &["-f", "-vv"], &mconf("", &format!("Nobody-User = {long}\n"))))
        .setup(&format!("echo '{long}:x:4000:4000::/:/bin/false' >>/etc/passwd"))
        .probe("up idtoname nfsd user 4242%0a")
        .probe("up nametoid nfsd user nosuch@example.org%0a");
    check(c);
}

#[test]
fn bad_upcalls() {
    let c = server("bad_upcalls")
        .probe("up nametoid %0a")
        .probe("up nametoid nfsd%0a")
        .probe("up nametoid nfsd user%0a")
        .probe("up idtoname nfsd group%0a")
        .probe("up nametoid nfsd   user    alice@example.org%0a")
        .probe("up nametoid %20nfsd user alice@example.org%0a");
    check(c);
}

#[test]
fn escapes() {
    let c = server("escapes")
        .probe("up nametoid a\\040b\\011c\\134d user alice@example.org%0a")
        .probe("up nametoid nfsd user al\\151ce@example.org%0a")
        .probe("up nametoid a\\7 bc alice@example.org%0a")
        .probe("up nametoid nfsd\\400 user alice@example.org%0a")
        .probe("up nametoid nfsd\\x user alice@example.org%0a")
        .probe("up nametoid nfsd \\165ser alice@example.org%0a")
        .probe("up nametoid nfsd user \\040%0a")
        .probe("up nametoid nfsd user a\\000b%0a")
        .probe("up nametoid nfsd user alice@example.org\\000%0a")
        .probe("up nametoid nfsd user \\-01%0a");
    check(c);
}

#[test]
fn field_lengths() {
    let n127 = format!("{}@example.org", "a".repeat(115));
    let n128 = format!("{}@example.org", "a".repeat(116));
    let c = server("field_lengths")
        .probe(&format!("up nametoid nfsd user {n127}%0a"))
        .probe(&format!("up nametoid nfsd user {n128}%0a"))
        .probe(&format!("up nametoid {} user alice@example.org%0a", "x".repeat(230)));
    check(c);
}

#[test]
fn no_newline() {
    // The last byte is taken for the newline.
    let c = server("no_newline")
        .probe("up nametoid nfsd user alice@example.org")
        .probe("up nametoid nfsd user alice@example.orgg")
        .probe(&format!("up nametoid nfsd user {}", "z".repeat(300)));
    check(c);
}

#[test]
fn reply_overflow() {
    // Escaped spaces take four bytes each in the answer: the fields that don't fit
    // are left out, the newline put over the last space that did.
    let sp = "\\040".repeat(50);
    let c = server("reply_overflow")
        .probe(&format!("up nametoid {sp} user alice@example.org%0a"))
        .probe(&format!("up idtoname {sp}{} group 50%0a", "\\040".repeat(9)))
        .probe(&format!("up idtoname {}x group 50%0a", "\\040".repeat(62)));
    check(c);
}

#[test]
fn channel_reset() {
    // nfsd goes away with an answer unread: a read error, and a new descriptor.
    let c = server("channel_reset")
        .probe("fds")
        .probe("up-close nametoid nfsd user alice@example.org%0a")
        .probe("up nametoid nfsd user bob@example.org%0a")
        .probe("fds");
    check(c);
}

#[test]
fn channel_eof_spins() {
    // An end of file isn't an error: "no upcall to read", and the descriptor stays
    // readable, so the loop spins.
    check(server("channel_eof").probe("close idtoname").probe("kill KILL"));
}

#[test]
fn sighup_reopens() {
    let c = server("sighup_reopens")
        .probe("kill HUP")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("up idtoname nfsd user 1000%0a")
        .probe("fds")
        .probe("rm @T@/procrpc/nfs4.idtoname/channel")
        .probe("kill HUP")
        .probe("fds")
        .probe("up idtoname nfsd user 1000%0a");
    check(c);
}

// --- The NFS client's pipes ------------------------------------------------------

/// One client, `clnt0`, in the foreground at -vvv, nobody being bob and staff.
fn clnt(name: &str) -> Case {
    client(ic(name, &["-f", "-vvv"], &mconf("", "Nobody-User = bob\nNobody-Group = staff\n")), "0")
}

#[test]
fn client_lookups() {
    // Failures map to nobody, and LOOKUPFAIL comes back as SUCCESS.
    let c = clnt("client_lookups")
        .probe("msg clnt0 0 1 0 0 alice@example.org")
        .probe("msg clnt0 1 1 0 0 users@example.org")
        .probe("msg clnt0 0 1 0 0 nosuch@example.org")
        .probe("msg clnt0 1 1 0 0 nosuch@example.org")
        .probe("msg clnt0 0 0 0 1000 -")
        .probe("msg clnt0 1 0 0 50 -")
        .probe("msg clnt0 0 0 0 4242 -")
        .probe("msg clnt0 1 0 0 4242 -")
        .probe("msg clnt0 0 0 0 4294967294 -");
    check(c);
}

#[test]
fn client_odd_messages() {
    let c = clnt("client_odd")
        // An unknown conversion: INVALIDMSG added to the status.
        .probe("msg clnt0 0 5 2 7 alice@example.org")
        // An unknown type: no lookup, SUCCESS (id to name), or the id untouched.
        .probe("msg clnt0 7 0 0 1000 keep")
        .probe("msg clnt0 7 1 4 99 alice@example.org")
        // A byte right after the name's NUL: no lookup, the message back as it came
        // (with LOOKUPFAIL made SUCCESS).
        .probe("msg clnt0 0 1 4 99 alice@example.org 41")
        .probe("msg clnt0 0 1 0 99 alice@example.org 41")
        // Bytes further on are only echoed.
        .probe("msg clnt0 0 1 0 99 alice@example.org 0041")
        // id to name leaves what follows the new name's NUL.
        .probe(&format!("msg clnt0 0 0 0 1000 {}", "x".repeat(40)));
    check(c);
}

#[test]
fn client_long_names() {
    // 127 bytes and a NUL in the padding after the array: looked up as 127 bytes.
    let n127 = format!("{}@example.org", "a".repeat(115));
    let c = clnt("client_long_names")
        .probe(&format!("msg clnt0 0 1 0 0 {n127}"))
        .probe(&format!("raw clnt0 0001{}00{}", "61".repeat(128), "00".repeat(10)))
        .probe(&format!("raw clnt0 0001{}41{}", "61".repeat(128), "00".repeat(9)));
    check(c);
}

#[test]
fn client_reset() {
    // The client goes away with an answer unread: the read error is logged (at -v),
    // then the descriptor reads end of file, again and again, logging the same errno.
    // (SIGTERM would be a gamble in C: sig_die() logs from the handler, and with the
    // loop logging too, syslog()'s lock can deadlock it. So SIGKILL.)
    let c = clnt("client_reset").probe("up-close clnt0 %00").probe("kill KILL").squeeze();
    let mut c = c;
    c.probe = vec![format!("up-close clnt0 {}", "%00".repeat(140)), "kill KILL".into()];
    check(c);
}

// --- Finding clients -------------------------------------------------------------

#[test]
fn new_client() {
    let c = ic("new_client", &["-f", "-vvv"], &conf(""))
        .probe(&format!("mkdir {PIPEFS}/clnt5"))
        .probe(&format!("listen clnt5 {PIPEFS}/clnt5/idmap"))
        .probe("msg clnt5 0 1 0 0 alice@example.org")
        .probe(&format!("listen clnt6 {PIPEFS}/clnt6/idmap"))
        .probe("msg clnt6 1 0 0 50 -")
        .probe("fds")
        .probe(&format!("rm {PIPEFS}/clnt5"))
        .probe("fds")
        .probe("msg clnt6 0 0 0 1001 -");
    check(c);
}

#[test]
fn scan_order() {
    let mut c = ic("scan_order", &["-f", "-vvv"], &conf(""));
    for n in ["10", "2", "1", "b", "A"] {
        c = client(c, n);
    }
    let c = c.probe("fds").probe("kill USR1").probe("fds");
    check(c);
}

#[test]
fn odd_entries() {
    // "clnt" alone (an empty id); a regular file; a directory with a regular file for
    // its pipe, which epoll refuses; a socket, which open() refuses, ending the scan.
    let c = ic("odd_entries", &["-f", "-vvv"], &conf(""))
        .before(&format!("listen bare {PIPEFS}/clnt/idmap"))
        .before(&format!("file {PIPEFS}/clntfile x"))
        .before(&format!("file {PIPEFS}/clntreg/idmap x"))
        .before(&format!("listen sock {PIPEFS}/clntsock"))
        .before(&format!("listen zz {PIPEFS}/clntzz/idmap"))
        .probe("msg bare 0 1 0 0 alice@example.org")
        .probe("fds")
        .probe(&format!("rm {PIPEFS}/clntsock"))
        .probe("kill USR1")
        .probe("fds");
    check(c);
}

#[test]
fn file_as_pipe() {
    // Without the probe's sockets in the way: just the regular file.
    let c =
        ic("file_as_pipe", &["-f", "-v"], &conf("")).before(&format!("file {PIPEFS}/clnt1/idmap hello")).probe("fds");
    check(c);
}

#[test]
fn waiting_for_pipe() {
    // The directory first: a one-shot watch on it, then the pipe.
    let c = ic("waiting_for_pipe", &["-f", "-vvv"], &conf(""))
        .before(&format!("mkdir {PIPEFS}/clnt9"))
        .probe(&format!("listen clnt9 {PIPEFS}/clnt9/idmap"))
        .probe("msg clnt9 0 1 0 0 bob@example.org")
        .probe(&format!("mkdir {PIPEFS}/clnt8"))
        .probe(&format!("file {PIPEFS}/clnt8/other x"))
        .probe(&format!("listen clnt8 {PIPEFS}/clnt8/idmap"))
        .probe("kill USR1")
        .probe("msg clnt8 0 1 0 0 bob@example.org");
    check(c);
}

#[test]
fn long_client_names() {
    // ic_clid holds 29 bytes; a longer name never matches its own entry, so every scan
    // drops the client and opens it again.
    let long = format!("clnt{}", "9".repeat(40));
    let c = ic("long_client_names", &["-f", "-vvv"], &conf(""))
        .before(&format!("listen long {PIPEFS}/{long}/idmap"))
        .probe("fds")
        .probe("kill USR1")
        .probe("fds")
        .probe("msg long 0 1 0 0 alice@example.org");
    check(c);
}

#[test]
fn pipefs_removed() {
    let c = client(ic("pipefs_removed", &["-f", "-vvv"], &conf("")), "0")
        .probe(&format!("rm {PIPEFS}"))
        .probe("kill USR1")
        .probe("kill USR2")
        .probe("fds");
    check(c);
}

#[test]
fn sigusr2_and_sigint() {
    let c = clnt("sigusr2_sigint").probe("kill USR2").probe("msg clnt0 0 1 0 0 alice@example.org").probe("kill INT");
    check(c);
}

/// In the foreground with only nfsd's name-to-id channel: syslog's socket is 3,
/// epoll 4, libevent's pipe 5 and 6, the channel 7, inotify 8, and clnt0's directory
/// and pipe 9 and 10.
fn fd10_layout(name: &str, args: &[&str]) -> Case {
    client(ic(name, args, &conf("")), "0")
        .file("procrpc/nfs4.nametoid/flush", b"")
        .before("listen nametoid @T@/procrpc/nfs4.nametoid/channel")
        .before(&format!("listen clnt1 {PIPEFS}/clnt1/idmap"))
}

#[test]
fn sigusr1_reads_fd_10() {
    // The SIGUSR1 event hands dirscancb() 10, the signal number, as the inotify
    // descriptor. Here 10 is clnt0's pipe: the rescan blocks reading it and swallows
    // its requests; SIGTERM can't stop it (SA_RESTART restarts the read); a second
    // one exits.
    let c = fd10_layout("sigusr1_fd10", &["-f"])
        .probe("fds")
        .probe("kill USR1")
        .probe("msg clnt0 0 1 0 0 alice@example.org")
        .probe("msg clnt0 0 1 0 0 bob@example.org")
        .probe("msg clnt1 0 1 0 0 alice@example.org")
        .probe("up nametoid nfsd user alice@example.org%0a")
        .probe("kill TERM")
        .probe("kill TERM");
    check(c);
}

#[test]
fn sigusr1_reads_fd_10_verbose() {
    // At -vvv each swallowed request is logged as inotify events.
    let c = fd10_layout("sigusr1_fd10_v", &["-f", "-vvv"])
        .probe("fds")
        .probe("kill USR1")
        .probe("msg clnt0 0 1 0 0 alice@example.org")
        .probe(&format!("raw clnt0 {}", "00".repeat(16)))
        .probe("kill KILL");
    check(c);
}

#[test]
fn sigusr1_fd_10_harmless() {
    // In the usual layouts 10 is a directory (EISDIR) or the inotify descriptor
    // itself, and the rescan goes ahead.
    let c = client(client(ic("sigusr1_fd10_dir", &["-f", "-vvv"], &conf("")), "0"), "1")
        .probe("fds")
        .probe("kill USR1")
        .probe("msg clnt1 0 1 0 0 alice@example.org");
    check(c);
    let c = client(nfsd(ic("sigusr1_fd10_inotify", &[], &conf(""))), "0")
        .probe("fds")
        .probe(&format!("listen clnt1 {PIPEFS}/clnt1/idmap"))
        .probe("kill USR1")
        .probe("fds");
    check(c);
}

#[test]
fn many_clients() {
    let mut c = ic("many_clients", &["-f", "-vv"], &conf(""));
    for n in 0..40 {
        c = client(c, &n.to_string());
    }
    let mut c = c.probe("fds");
    for n in [0, 17, 39] {
        c = c.probe(&format!("msg clnt{n} 0 0 0 1000 -"));
    }
    check(c.probe("kill USR1"));
}
