//! What the nfsidmap and libnfsidmap cases share: a sandbox with its own users and
//! groups, `/etc/idmapd.conf`, a fake DNS server on 127.0.0.1 and an empty
//! `/proc/keys`.

#![allow(dead_code)]

use crate::common::Case;

pub const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
alice:x:1000:1000::/home/alice:/bin/sh
bob:x:1001:1001::/home/bob:/bin/sh
nfsnobody:x:4294967294:4294967294::/:/bin/false
";

pub const GROUP: &str = "root:x:0:
nobody:x:65534:
alice:x:1000:
bob:x:1001:
staff:x:50:alice,bob
users:x:100:alice
";

/// A case running `prog` with `conf` as `/etc/idmapd.conf`.
pub fn icase(name: &str, prog: &str, args: &[&str], conf: &str) -> Case {
    Case::bare(name, prog, args)
        .etc("idmapd.conf", conf.as_bytes())
        .etc("passwd", PASSWD.as_bytes())
        .etc("group", GROUP.as_bytes())
        .etc("hosts", b"127.0.0.1 localhost\n")
        .etc("resolv.conf", b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        .etc("nsswitch.conf", b"passwd: files\ngroup: files\nhosts: files dns\n")
        .peer("dns 127.0.0.1 53 dns")
        .file("proc-keys", b"")
        .setup(r#"mount --bind "$R/proc-keys" /proc/keys"#)
}

/// `[General] Domain = example.org`, and whatever else.
pub fn conf(extra: &str) -> String {
    format!("[General]\nDomain = example.org\n{extra}")
}

/// A DNS rule (a probe command).
pub fn dns(c: Case, rule: &str) -> Case {
    c.before(&format!("dns {rule}"))
}

/// The keys the shim knows (its `TEST_KEYS` file) and what `/proc/keys` shows.
pub fn keys(c: Case, state: &str, proc_keys: &str) -> Case {
    c.file("keys.state", state.as_bytes()).file("proc-keys", proc_keys.as_bytes())
}
