//! Differential tests for rpc.statd under hostile input: malformed and truncated calls
//! (UDP and TCP), hostile `mon_name`s and `my_name`s (and canonical names), `SM_NOTIFY`
//! floods and spoofed senders, spoofed callback replies, a full, read-only or tampered
//! state directory, and connection floods on the TCP listener.

mod common;

use common::statd::*;
use common::{Case, check};

/// Extra hosts whose canonical (first) names are hostile, as a DNS server could make them.
fn hostile_hosts() -> String {
    format!(
        "{HOSTS}127.0.0.9 .. dotdot\n127.0.0.10 . dot\n127.0.0.11 a/b slashy\n\
         127.0.0.12 %s%n%x fmt\n127.0.0.13 {} longname\n127.0.0.14 sm.bak bakname\n\
         127.0.0.15 -rf dashname\n",
        "x".repeat(300)
    )
}

fn hcase(name: &str) -> Case {
    fg(name).etc("hosts", hostile_hosts().as_bytes())
}

/// A whole call message (AUTH_NONE) to statd, `XID` standing for the xid.
fn call_hex(proc_: u32, args: &str) -> String {
    format!("XID0000000000000002000186b800000001{proc_:08x}00000000000000000000000000000000{args}")
}

/// HEX's length in bytes (`XID` stands for four).
fn hex_len(hex: &str) -> usize {
    hex.replace("XID", "00000000").len() / 2
}

/// HEX as one record (a single, last fragment).
fn rec(hex: &str) -> String {
    format!("{:08x}{hex}", 0x8000_0000u32 | hex_len(hex) as u32)
}

/// A fragment that isn't the last.
fn frag(hex: &str) -> String {
    format!("{:08x}{hex}", hex_len(hex) as u32)
}

fn tcp_stat(c: Case, conn: &str, mon_name: &str) -> Case {
    c.probe(&format!("send {conn} {}", rec(&call_hex(1, &xs(mon_name))))).probe(&format!("recv {conn}"))
}

// ---------------------------------------------------------------------------
// malformed and truncated calls

/// `SM_MON` arguments cut at every field (and inside the strings), after a full call:
/// over UDP the rest comes from the transport's buffer.
#[test]
fn truncated_mon_udp() {
    let full = mon_args("peer-b", "client", PRIV2);
    let mut c = fg("truncated_mon_udp").probe(&sm_mon("full", "peer-a", "client"));
    for cut in [0, 2, 4, 6, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48] {
        c = c.probe(&format!("call cut{cut} udp 127.0.0.1 800 2 {}", &full[..cut * 2]));
    }
    check(stop(c));
}

#[test]
fn truncated_mon_tcp() {
    let full = mon_args("peer-b", "client", PRIV2);
    let mut c = fg("truncated_mon_tcp").probe(&sm_mon("full", "peer-a", "client"));
    for cut in [0, 4, 8, 12, 20, 28, 36, 48] {
        c = c.probe(&format!("call cut{cut} tcp 127.0.0.1 800 2 {}", &full[..cut * 2]));
    }
    check(stop(c));
}

/// Truncated `SM_NOTIFY`, `SM_STAT`, `SM_UNMON` and `SM_UNMON_ALL` arguments.
#[test]
fn truncated_other_calls() {
    check(stop(
        lockd(fg("truncated_other_calls"), "void")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe("call notify0 udp 127.0.0.2 0 6")
            .probe(&format!("call notify1 udp 127.0.0.2 0 6 {}", xs("peer-a")))
            .probe("wait lockd 1")
            .expect("succeeded")
            .probe("call stat0 udp 127.0.0.1 800 1 0000")
            .probe(&format!("call unmon1 udp 127.0.0.1 800 3 {}", xs("peer-a")))
            .probe("call unmonall0 udp 127.0.0.1 800 4 00000006636c69")
            .probe("pause 300"),
    ));
}

/// Strings at and past `SM_MAXSTRLEN` (1024), and absurd lengths.
#[test]
fn oversized_strings() {
    let a1024 = "a".repeat(1024);
    let a1025 = "a".repeat(1025);
    let mut c = lockd(fg("oversized_strings"), "void")
        .probe(&sm_mon("mon_1024", &a1024, "client"))
        .probe(&sm_mon("mon_1025", &a1025, "client"))
        .probe(&sm_mon("my_1025", "peer-a", &a1025))
        .probe(&sm_mon("my_1024", "peer-a", &a1024))
        .probe(&sm_stat("stat_1024", &a1024))
        .probe(&sm_stat("stat_1025", &a1025))
        .probe(&sm_notify("notify_1024", "127.0.0.2", &a1024, 3))
        .probe(&sm_notify("notify_1025", "127.0.0.2", &a1025, 4));
    for (name, len) in [("huge", "ffffffff"), ("neg", "80000000"), ("big", "00002000")] {
        c = c
            .probe(&format!("call stat_{name} udp 127.0.0.1 800 1 {len}61616161"))
            .probe(&format!("call stat_{name}_tcp tcp 127.0.0.1 800 1 {len}61616161"));
    }
    check(stop(c.probe(&sm_unmon("unmon", "peer-a", &a1024))));
}

/// Calls with bad RPC headers: a reply, RPC version 3, credentials of every kind, a
/// credential over 400 bytes, a message too short for a header, an empty one, and one
/// bigger than the transport's buffer.
#[test]
fn bad_rpc_headers() {
    let stat = xs("peer-a");
    let sys_cred = format!("00000001{}", xb(&hex_bytes(&format!("00000000{}0000000000000000{}", xs("evil"), xi(0)))));
    let mut c = fg("bad_rpc_headers");
    for (name, msg) in [
        ("reply", format!("XID00000001000000020000000000000000{stat}")),
        ("rpcvers3", format!("XID0000000000000003000186b80000000100000001{}{stat}", "0".repeat(32))),
        ("auth_sys", hdr(&sys_cred, NONE, &stat)),
        ("auth_sys_short", hdr("000000010000000400000000", NONE, &stat)),
        ("auth_long", hdr(&format!("0000000100000191{}", "00".repeat(404)), NONE, &stat)),
        ("auth_flavor9", hdr("0000000900000000", NONE, &stat)),
        ("verf_sys", hdr(NONE, "0000000100000004deadbeef", &stat)),
        ("short12", "XID0000000000000002".to_string()),
        ("short20", "XID0000000000000002000186b800000001".to_string()),
        ("empty", String::new()),
        ("huge", call_hex(1, &format!("{stat}{}", "ab".repeat(10000)))),
    ] {
        c = c.probe(&format!("raw {name} udp 127.0.0.1 800 {msg}"));
        if !msg.is_empty() {
            c = c.probe(&format!("raw {name}_tcp tcp 127.0.0.1 800 {msg}"));
        }
    }
    check(stop(c.probe(&sm_stat("after", "peer-a"))));
}

const NONE: &str = "0000000000000000";

/// An `SM_STAT` call with these credential and verifier (flavor, length, body).
fn hdr(cred: &str, verf: &str, args: &str) -> String {
    format!("XID0000000000000002000186b80000000100000001{cred}{verf}{args}")
}

fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// Record marking, each on its own connection: a call in three fragments (each fragment
/// is taken as a whole record, a tirpc quirk: see rpcbind-rs's QUIRKS.md), a
/// zero-length record, two calls in one write, a record header claiming more than the
/// 9000-byte limit, fragments adding up to more than it, a connection that ends half-way
/// through a record, and a fragment that never ends the record.
#[test]
fn tcp_records() {
    let call = call_hex(1, &xs("peer-a"));
    // "XID" and ten more bytes, then fifteen, then the rest.
    let (a, b) = call.split_at(23);
    let (b, d) = b.split_at(30);
    let c = fg("tcp_records")
        .probe("conn frag")
        .probe(&format!("send frag {}{}{}", frag(a), frag(b), rec(d)))
        .probe("recv frag")
        .probe("timeout 500")
        .probe("conn empty")
        .probe("send empty 80000000")
        .probe("recv empty")
        .probe("alive empty")
        .probe("timeout 0")
        .probe("conn two")
        .probe(&format!("send two {}{}", rec(&call), rec(&call)))
        .probe("recv two")
        .probe("recv two")
        .probe("conn big")
        .probe("send big 7fffffff00000000")
        .probe("recv big")
        .probe("conn big2")
        .probe(&format!("send big2 {}", frag(&"00".repeat(5000))))
        .probe(&format!("send big2 {}", rec(&"00".repeat(5000))))
        .probe("recv big2")
        .probe("conn half")
        .probe(&format!("send half {}", &rec(&call)[..40]))
        .probe("close half")
        .probe("conn nofrag")
        .probe(&format!("send nofrag {}", frag(&call)))
        .probe("timeout 500")
        .probe("recv nofrag")
        .probe("timeout 0")
        .probe("alive nofrag");
    check(stop(tcp_stat(c.probe("conn after"), "after", "peer-a")));
}

// ---------------------------------------------------------------------------
// hostile names

/// Canonical names that are path tricks (`..`, `.`, `a/b`), format directives, overlong,
/// another directory's name, or an option: `mon_name` passes statd's checks (no `/`,
/// no leading `.`), but the record file is named after the canonical name.
#[test]
fn mon_canonical_hostile() {
    let mut c = lockd(hcase("mon_canonical_hostile"), "void");
    for n in ["dotdot", "dot", "slashy", "fmt", "longname", "bakname", "dashname", "127.0.0.9"] {
        c = c.probe(&sm_mon(&format!("mon_{n}"), n, "client"));
    }
    c = c
        .probe(&sm_notify("notify_dotdot", "127.0.0.9", "dotdot", 3))
        .probe(&sm_notify("notify_fmt", "127.0.0.12", "%s%n%x", 3))
        .probe("pause 300");
    for n in ["dotdot", "dot", "fmt", "longname", "bakname"] {
        c = c.probe(&sm_unmon(&format!("unmon_{n}"), n, "client"));
    }
    check(stop(c));
}

/// The records statd wrote for hostile canonical names, loaded again at startup (and
/// handed to sm-notify).
#[test]
fn load_hostile_records() {
    let c = hcase("load_hostile_records")
        .state("sm/%s%n%x", format!("{}\n", mon_record("fmt", "client")).as_bytes())
        .state("sm/sm.bak", format!("{}\n", mon_record("bakname", "client")).as_bytes())
        .state("sm/-rf", format!("{}\n", mon_record("dashname", "c%nlient")).as_bytes())
        .setup("chown nobody:nobody /var/lib/nfs/sm/*")
        .probe(&sm_stat("stat", "fmt"))
        .probe(&sm_notify("notify", "127.0.0.12", "fmt", 7))
        .probe("pause 300");
    check(stop(c));
}

/// `mon_name`s with control characters, high bytes, format directives, quotes, a
/// leading dash, and a long name that doesn't resolve (only logged), plus `my_name`s
/// that are path tricks, format directives or long (written into the record).
#[test]
fn odd_bytes_in_names() {
    let mut c = fg("odd_bytes_in_names");
    for (i, n) in [
        &b"peer\x01\x7f\x1b[2J"[..],
        b"\xff\xfe\xc3(",
        b"%n%n%n%n%s%s",
        b"peer-a'\";$(id)`id`",
        b"-x",
        b"peer-a\n127.0.0.2",
        &[b'y'; 1000][..],
    ]
    .iter()
    .enumerate()
    {
        let args = format!("{}{}{PRIV}", xb(n), my_id("client", LOCKD.0, LOCKD.1, LOCKD.2));
        c = c.probe(&format!("call mon{i} udp 127.0.0.1 800 2 {args}"));
        c = c.probe(&format!("call stat{i} udp 127.0.0.1 800 1 {}", xb(n)));
    }
    for (i, n) in [&b"../../etc/passwd"[..], b"%n%s%x", b"a\0b", b"\xff\x01x", &[b'z'; 1000][..]].iter().enumerate() {
        let args = format!("{}{}{PRIV}", xs("peer-a"), format_args!("{}{}{}{}", xb(n), xi(LOCKD.0.into()), xi(LOCKD.1.into()), xi(LOCKD.2.into())));
        c = c.probe(&format!("call my{i} udp 127.0.0.1 800 2 {args}"));
    }
    check(stop(c.probe(&sm_unmon_all("unmon_all", "127.0.0.1", "client"))));
}

/// Hostile names in `SM_NOTIFY` reach the ha-callout as arguments (no shell).
#[test]
fn notify_hostile_names_ha_callout() {
    let mut c = lockd(case("notify_hostile_names_ha_callout", &["-F", "-d", "-L", "-p", "32765", "-H", "/run/ha"]), "void")
        .setup("printf '#!/bin/sh\\nfor a; do printf \"[%%s]\" \"$a\"; done >>/var/lib/nfs/sm.bak/ha.log; echo >>/var/lib/nfs/sm.bak/ha.log\\n' >/run/ha && chmod 755 /run/ha")
        .probe(&sm_mon("mon", "peer-a", "client"));
    for (i, n) in ["$(touch /run/pwned)", "-rf", "", "%s%n", "a b\tc", "peer-a;id"].iter().enumerate() {
        c = c.probe(&sm_notify(&format!("notify{i}"), "127.0.0.3", n, i as i64 + 1));
    }
    c = c.probe(&format!("call notify_long udp 127.0.0.3 0 6 {}{}", xs(&"q".repeat(1024)), xi(9)));
    check(stop(c.probe("pause 300").probe(&sm_unmon("unmon", "peer-a", "client"))));
}

// ---------------------------------------------------------------------------
// SM_NOTIFY floods and spoofed peers

/// Twenty state changes in a row while lockd doesn't answer: each queues a callback,
/// and every queued callback is retried until it gives up.
#[test]
fn notify_flood_states() {
    let mut c = lockd(fg("notify_flood_states"), "drop").probe(&sm_mon("mon", "peer-a", "client"));
    for s in 1..=20 {
        c = c.probe(&sm_notify(&format!("n{s}"), "127.0.0.2", "peer-a", s));
    }
    c = c.probe("wait lockd 80").expect_n(20, "giving up");
    check(stop(c));
}

/// The same state fifty times: one callback.
#[test]
fn notify_flood_same_state() {
    let mut c = lockd(fg("notify_flood_same_state"), "void").probe(&sm_mon("mon", "peer-a", "client"));
    for i in 0..50 {
        c = c.probe(&sm_notify(&format!("n{i}"), "127.0.0.2", "peer-a", 7));
    }
    check(stop(c.probe("wait lockd 1").expect("succeeded").probe("pause 300")));
}

/// Notifications from many sources (all of 127.0.0.0/8 is local), each naming a
/// monitored host it isn't, and from hosts statd doesn't know.
#[test]
fn notify_flood_sources() {
    let mut c = lockd(fg("notify_flood_sources"), "void")
        .probe(&sm_mon("mon_a", "peer-a", "client"))
        .probe(&sm_mon("mon_b", "peer-b", "client"));
    for i in 20..60 {
        let name = if i % 2 == 0 { "peer-a" } else { "nobody.invalid" };
        c = c.probe(&sm_notify(&format!("n{i}"), &format!("127.0.0.{i}"), name, i));
        if i % 2 == 0 {
            // One callback each, done before the next call.
            let k = (i - 18) / 2;
            c = c.probe(&format!("wait lockd {k}")).expect_n(k as usize, "succeeded");
        }
    }
    check(stop(c.probe("pause 500")));
}

/// Anyone can claim to be a monitored host: an `SM_NOTIFY` naming peer-a, sent from
/// peer-b's address, is a reboot of peer-a (by name) and of peer-b (by address).
#[test]
fn notify_spoofed_name() {
    check(stop(
        lockd(fg("notify_spoofed_name"), "void")
            .probe(&sm_mon("mon_a", "peer-a", "client"))
            .probe(&sm_mon("mon_b", "peer-b", "client"))
            .probe(&sm_notify("spoof", "127.0.0.3", "peer-a", 9))
            .probe("wait lockd 2")
            .expect_n(2, "succeeded")
            .probe(&sm_notify("spoof_v6", "::1", "peer-b", 11))
            .probe("wait lockd 3")
            .expect_n(3, "succeeded"),
    ));
}

/// lockd's answer to the callback comes from another local port (accepted: only the
/// address is checked) ...
#[test]
fn callback_reply_other_port() {
    check(stop(
        lockd(fg("callback_reply_other_port"), "void@127.0.0.1")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 1")
            .expect("succeeded"),
    ));
}

/// ... or from another address (refused, and the callback is retried until it gives up).
#[test]
fn callback_reply_other_address() {
    check(stop(
        lockd(fg("callback_reply_other_address"), "void@127.0.0.2")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 4")
            .expect("giving up"),
    ));
}

/// Short, zero-xid and wrong-xid replies to the callback, then a good one.
#[test]
fn callback_reply_garbage() {
    check(stop(
        lockd(fg("callback_reply_garbage"), "hex:XID,hex:00000000000000010000000000000000000000000000000000000000,hex:1234567800000001000000000000000000000000000000000000000000000000,void")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 5))
            .probe("wait lockd 4")
            .expect("succeeded"),
    ));
}

// ---------------------------------------------------------------------------
// the state directory

/// `sm/` not writable (by its owner, whom statd runs as): `SM_MON` fails, and so does
/// removing a loaded record.
#[test]
fn sm_read_only() {
    check(stop(
        lockd(fg("sm_read_only"), "void")
            .state("sm/peer-b", format!("{}\n", mon_record("peer-b", "client")).as_bytes())
            .setup("chown nobody:nobody /var/lib/nfs/sm/peer-b && chmod 555 /var/lib/nfs/sm")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_mon("mon_b", "peer-b", "other"))
            .probe(&sm_unmon("unmon_b", "peer-b", "client"))
            .probe(&sm_unmon_all("unmon_all", "127.0.0.1", "client")),
    ));
}

/// The whole state directory on a read-only mount: statd can't update `state` at startup.
#[test]
fn state_dir_read_only_mount() {
    check(stop(
        fg("state_dir_read_only_mount")
            .setup("mount -o remount,bind,ro /var/lib/nfs")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_stat("stat", "peer-a")),
    ));
}

/// `sm/` on a full file system, then on one out of inodes.
#[test]
fn sm_full() {
    for (name, opts, fill) in [
        ("sm_full_space", "size=4k", "head -c 4096 /dev/zero >/var/lib/nfs/sm/filler"),
        ("sm_full_inodes", "nr_inodes=2", "touch /var/lib/nfs/sm/filler"),
    ] {
        check(stop(
            lockd(fg(name), "void")
                .setup(&format!("mount -t tmpfs -o {opts},mode=755 tmpfs /var/lib/nfs/sm && {fill}"))
                .setup("chown nobody:nobody /var/lib/nfs/sm")
                .probe(&sm_mon("mon", "peer-a", "client"))
                .probe(&sm_mon("mon_again", "peer-a", "client"))
                .probe(&sm_notify("notify", "127.0.0.2", "peer-a", 3))
                .probe("pause 300"),
        ));
    }
}

/// A directory where peer-a's record should be.
#[test]
fn record_is_directory() {
    check(stop(
        fg("record_is_directory")
            .setup("mkdir /var/lib/nfs/sm/peer-a && chown nobody:nobody /var/lib/nfs/sm/peer-a")
            .probe(&sm_mon("mon", "peer-a", "client"))
            .probe(&sm_unmon("unmon", "peer-a", "client")),
    ));
}

/// peer-a's record is a symlink: to the `state` file (whose bytes then end up in the
/// new record, which replaces the link), and dangling.
#[test]
fn record_symlink() {
    check(stop(
        fg("record_symlink")
            .setup("ln -s ../state /var/lib/nfs/sm/peer-a")
            .setup("ln -s /nonexistent /var/lib/nfs/sm/peer-b")
            .probe(&sm_mon("mon_a", "peer-a", "client"))
            .probe(&sm_mon("mon_b", "peer-b", "client")),
    ));
}

/// A NUL in a record file: the next record is added at the NUL, and what follows it is
/// written as zeros.
#[test]
fn record_with_nul() {
    let body = format!("{}\n\0trailing junk\n", mon_record("peer-a", "other"));
    check(stop(
        fg("record_with_nul")
            .state("sm/peer-a", body.as_bytes())
            .setup("chown nobody:nobody /var/lib/nfs/sm/peer-a")
            .probe(&sm_mon("mon", "peer-a", "client")),
    ));
}

// ---------------------------------------------------------------------------
// connection floods

/// More connections than descriptors (a limit of 32, a stopped clock): the idle sweep
/// finds nothing less active, accept() fails while the connection waits in the backlog,
/// and UDP still works. Closing connections lets the waiting ones in.
#[test]
fn tcp_flood_low_fd_limit() {
    let c = fg("tcp_flood_low_fd_limit")
        .nofile(32)
        .squeeze()
        .probe("conn flood 40")
        .probe(&sm_stat("udp_stat", "peer-a"))
        .probe("conn late")
        .probe(&format!("send late {}", rec(&call_hex(1, &xs("peer-a")))))
        .probe("timeout 1000")
        .probe("recv late")
        .probe("alive flood")
        .probe("close flood")
        .probe("timeout 0")
        .probe("recv late");
    check(stop(c));
}

/// Connections that each hold half a record don't block other clients (the record
/// streams are non-blocking).
#[test]
fn tcp_partial_records() {
    let mut c = fg("tcp_partial_records");
    let call = rec(&call_hex(1, &xs("peer-a")));
    for i in 0..20 {
        c = c.probe(&format!("conn p{i}")).probe(&format!("send p{i} {}", &call[..(i % 5 + 1) * 6]));
    }
    c = tcp_stat(c.probe("conn ok"), "ok", "peer-a").probe(&sm_stat("udp", "peer-a"));
    for i in 0..20 {
        c = c.probe(&format!("alive p{i}"));
    }
    check(stop(c));
}

/// statd lowers its descriptor limit to `FD_SETSIZE` (1024) at startup. On a stopped
/// clock the idle sweep (at four fifths of the table) finds no connection less active
/// than another and closes nothing, so a flood uses up every descriptor: accept() fails,
/// and so does every name lookup (`SM_STAT` answers `STAT_FAIL`). Moving the clock on
/// doesn't help, as the sweep only runs after an accept succeeds.
#[test]
fn tcp_flood_descriptors() {
    let late = rec(&call_hex(1, &xs("peer-a")));
    let c = fg("tcp_flood_descriptors")
        .nofile(2048)
        .squeeze()
        .probe("conn flood 1100")
        .probe("conn late")
        .probe(&format!("send late {late}"))
        .probe("timeout 1000")
        .probe("recv late")
        .probe("timeout 0")
        .probe(&sm_stat("udp_stat", "peer-a"))
        .probe("fds")
        .probe("clock 20 @T@/faketime")
        .probe("conn after")
        .probe("fds")
        .probe("alive flood")
        .probe("close flood")
        .probe("fds")
        .probe("recv late")
        .probe(&sm_stat("udp_stat2", "peer-a"));
    check(stop(c));
}

/// The same flood on a clock that moves: once four fifths of the table is open, each
/// accept closes the least recently active connection (one of the older batch), so
/// descriptors never run out.
#[test]
fn tcp_flood_sweep() {
    let call = rec(&call_hex(1, &xs("peer-a")));
    let c = fg("tcp_flood_sweep")
        .squeeze()
        .probe("conn old 700")
        .probe("fds")
        .probe("clock 1 @T@/faketime")
        .probe("conn new 400")
        .probe("fds")
        .probe("alive old")
        .probe("alive new")
        .probe(&sm_stat("udp_stat", "peer-a"))
        .probe("conn late")
        .probe(&format!("send late {call}"))
        .probe("recv late")
        .probe("fds");
    check(stop(c));
}
