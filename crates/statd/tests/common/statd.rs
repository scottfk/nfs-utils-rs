//! rpc.statd test helpers: the cases' hosts, a foreground statd, a fake lockd, and XDR
//! builders for the NSM calls.

use super::Case;

pub const HOSTS: &str = "127.0.0.1 localhost\n::1 localhost\n\
127.0.0.2 peer-a peer-a.example.net\n127.0.0.3 peer-b\nfd00::5 peer-six\n\
127.0.0.4 multi\n127.0.0.5 multi\n10.77.0.9 client.example.net client\n";

/// The kernel's lockd: prog 100021, version 4, `NLMPROC_NSM_NOTIFY` (16).
pub const LOCKD: (u32, u32, u32) = (100021, 4, 16);

pub fn case(name: &str, args: &[&str]) -> Case {
    Case::new(name, "rpc.statd", args)
        .etc("hosts", HOSTS.as_bytes())
        .setup("ip addr add fd00::5/128 dev lo nodad")
        .setup("ip addr add 10.77.0.9/32 dev lo")
}

/// A foreground statd that logs everything to stderr, without sm-notify, on port 32765.
pub fn fg(name: &str) -> Case {
    case(name, &["-F", "-d", "-L", "-p", "32765"])
}

/// Stop statd (SIGTERM), wait for it, and dump rpcbind.
pub fn stop(c: Case) -> Case {
    c.probe("kill TERM").probe("gone").probe("dump")
}

/// A fake lockd on 127.0.0.1:4045 answering with ACTIONS, registered with rpcbind.
pub fn lockd(c: Case, actions: &str) -> Case {
    c.peer(&format!("lockd 127.0.0.1 4045 {actions}")).before(&format!("register {} {} 17 4045", LOCKD.0, LOCKD.1))
}

// XDR helpers for call arguments.
pub fn xs(s: &str) -> String {
    xb(s.as_bytes())
}
pub fn xb(b: &[u8]) -> String {
    let mut h = format!("{:08x}", b.len());
    for x in b {
        h.push_str(&format!("{x:02x}"));
    }
    for _ in 0..(4 - b.len() % 4) % 4 {
        h.push_str("00");
    }
    h
}
pub fn xi(v: i64) -> String {
    format!("{:08x}", v as u32)
}
pub const PRIV: &str = "000102030405060708090a0b0c0d0e0f";
pub const PRIV2: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/// `struct my_id`.
pub fn my_id(my_name: &str, prog: u32, vers: u32, proc_: u32) -> String {
    format!("{}{}{}{}", xs(my_name), xi(prog.into()), xi(vers.into()), xi(proc_.into()))
}

/// `SM_MON` args from lockd.
pub fn mon_args(mon_name: &str, my_name: &str, priv_: &str) -> String {
    format!("{}{}{priv_}", xs(mon_name), my_id(my_name, LOCKD.0, LOCKD.1, LOCKD.2))
}

/// An `SM_MON` call from lockd (127.0.0.1:800).
pub fn sm_mon(name: &str, mon_name: &str, my_name: &str) -> String {
    format!("call {name} udp 127.0.0.1 800 2 {}", mon_args(mon_name, my_name, PRIV))
}

pub fn sm_unmon(name: &str, mon_name: &str, my_name: &str) -> String {
    format!("call {name} udp 127.0.0.1 800 3 {}{}", xs(mon_name), my_id(my_name, LOCKD.0, LOCKD.1, LOCKD.2))
}

pub fn sm_unmon_all(name: &str, src: &str, my_name: &str) -> String {
    format!("call {name} udp {src} 0 4 {}", my_id(my_name, LOCKD.0, LOCKD.1, LOCKD.2))
}

pub fn sm_stat(name: &str, mon_name: &str) -> String {
    format!("call {name} udp 127.0.0.1 800 1 {}", xs(mon_name))
}

/// An `SM_NOTIFY` from SRC.
pub fn sm_notify(name: &str, src: &str, mon_name: &str, state: i64) -> String {
    format!("call {name} udp {src} 0 6 {}{}", xs(mon_name), xi(state))
}

/// A monitor record from lockd, as statd writes them.
pub fn mon_record(mon_name: &str, my_name: &str) -> String {
    format!("0100007f 000186b5 00000004 00000010 {} {mon_name} {my_name}", PRIV.to_uppercase())
}
