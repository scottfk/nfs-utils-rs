//! libnfsidmap against the C library, through the idmaptest drivers (one over each):
//! the configuration, the default domain (with a fake DNS server), loading the
//! methods, and each method's mappings, with the library's log at level 4 on stderr.

#[path = "../../statd/tests/common/mod.rs"]
mod common;
mod idmap;

use common::{Case, check};
use idmap::*;

/// The driver with `cmds` after `debug 4 log` and `init -`.
fn lib(name: &str, conf: &str, cmds: &[&str]) -> Case {
    let mut args = vec!["debug", "4", "log", "init", "-"];
    args.extend_from_slice(cmds);
    icase(&format!("lib_{name}"), "idmaptest", &args, conf)
}

/// The driver with exactly `cmds`.
fn raw(name: &str, conf: &str, cmds: &[&str]) -> Case {
    icase(&format!("lib_{name}"), "idmaptest", cmds, conf)
}

const HOSTS_NET: &[u8] = b"127.0.0.1 localhost\n127.0.1.1 host.example.net nsmtest\n";

fn net(c: Case) -> Case {
    c.etc("hosts", HOSTS_NET)
}

const LOOKUPS: &[&str] = &[
    "uid2name",
    "1000",
    "-",
    "128",
    "gid2name",
    "50",
    "-",
    "128",
    "name2uid",
    "alice@example.org",
    "name2gid",
    "staff@example.org",
    "uid2name",
    "4242",
    "-",
    "128",
    "name2uid",
    "nosuch@example.org",
];

// --- The default domain ----------------------------------------------------------

#[test]
fn domain_from_conf() {
    check(lib("domain_from_conf", &conf(""), &["domain", "512", "domain", "12", "domain", "11", "domain", "0"]));
}

#[test]
fn domain_none_anywhere() {
    // No Domain, a host name without a dot that DNS doesn't know: localdomain.
    check(lib("domain_none_anywhere", "", &["domain", "512", "uid2name", "1000", "-", "128"]));
}

#[test]
fn domain_from_host_name() {
    // DNS has no TXT record: the domain part of the host's name.
    check(net(lib("domain_from_host_name", "", &["domain", "512", "uid2name", "1000", "-", "128"])));
}

#[test]
fn domain_from_txt_record() {
    let c = net(lib("domain_from_txt_record", "", &["domain", "512", "uid2name", "1000", "-", "128"]));
    check(dns(c, "_nfsv4idmapdomain.example.net TXT txt:nfs.example.com"));
}

#[test]
fn domain_txt_variants() {
    for (i, ans) in [
        "txt:",
        "txt:two%20words%2Fslash",
        "txt:first+txt:second",
        "txtraw:03616263036465660a",
        "txtraw:0561620063",
        "cname:abc.example.net+txt:real",
        "a:10.1.2.3",
        "servfail",
        "refused",
        "nodata",
        "nx",
    ]
    .iter()
    .enumerate()
    {
        let c = net(lib(&format!("domain_txt_{i}"), "", &["domain", "512"]));
        check(dns(c, &format!("_nfsv4idmapdomain.example.net TXT {ans}")));
    }
}

#[test]
fn domain_txt_malformed() {
    // Whole answers by hand (after the id): a bad name pointer in the answer, an
    // answer cut short, a header that claims an answer that isn't there, and one
    // with high bytes.
    let q = "115f6e6673763469646d6170646f6d61696e076578616d706c65036e65740000100001";
    for (i, body) in [
        format!("81800001000100000000{q}c0ff00100001000000000005046869676800"),
        format!("81800001000100000000{q}c00c0010"),
        format!("81800001000100000000{q}"),
        format!("81800001000100000000{q}c00c00100001000000000005048899aabb"),
        "818000010001000000".to_string(),
    ]
    .iter()
    .enumerate()
    {
        let c = net(lib(&format!("domain_txt_malformed_{i}"), "", &["domain", "512"]));
        check(dns(c, &format!("_nfsv4idmapdomain.example.net TXT raw:{body}")));
    }
}

#[test]
fn domain_host_name_cases() {
    // The host's name as is, when DNS doesn't know it.
    for (i, host) in
        ["box.lan.example", "trailing.", "a.b", &"h".repeat(63), &format!("x.{}", "y".repeat(62))].iter().enumerate()
    {
        let c = lib(&format!("domain_host_name_{i}"), "", &["domain", "512"]).setup(&format!("hostname {host}"));
        check(c);
    }
    // DNS knows the host's name, as one without a dot.
    let c = lib("domain_host_known_no_dot", "", &["domain", "512"]);
    check(dns(c, "nsmtest A a:127.0.1.1"));
}

#[test]
fn domain_before_init() {
    // nfs4_get_default_domain() without the library set up: the DNS lookup, or "".
    check(raw("domain_before_init", "", &["debug", "2", "log", "domain", "512", "init", "-", "domain", "512"]));
    check(net(raw("domain_before_init_dns", "", &["debug", "2", "log", "domain", "512", "domain", "4"])));
}

#[test]
fn domain_too_long() {
    let d = "d".repeat(600);
    let c = format!("[General]\nDomain = {d}\n");
    check(lib(
        "domain_too_long",
        &c,
        &["domain", "512", "uid2name", "1000", "-", "128", "name2uid", "alice@", "princ", "krb5", "alice@"],
    ));
}

#[test]
fn domain_given_by_caller() {
    check(lib(
        "domain_given_by_caller",
        &conf(""),
        &["uid2name", "1000", "other.net", "128", "gid2name", "50", "", "128", "uid2owner", "1000", "x", "4"],
    ));
}

// --- Initialization ------------------------------------------------------------

#[test]
fn init_twice_and_term() {
    let c = raw(
        "init_twice_and_term",
        &conf(""),
        &[
            "debug",
            "1",
            "log",
            "init",
            "-",
            "init",
            "-",
            "path",
            "term",
            "conf",
            "General",
            "Domain",
            "init",
            "@T@/other.conf",
            "path",
            "domain",
            "512",
            "uid2name",
            "1000",
            "-",
            "128",
        ],
    )
    .file("other.conf", b"[General]\nDomain = other.example\n");
    check(c);
}

// Not compared: after nfs4_term_name_mapping(), C's default domain points into the
// freed configuration (the Rust library keeps the old value).

#[test]
fn init_with_missing_file() {
    check(raw("init_with_missing_file", "", &["debug", "1", "log", "init", "@T@/nope.conf", "path", "domain", "512"]));
}

#[test]
fn realms() {
    check(lib(
        "realms_default",
        &conf(""),
        &["princ", "krb5", "alice@EXAMPLE.ORG", "princ", "krb5", "alice@example.org"],
    ));
    check(lib(
        "realms_listed",
        &conf("Local-Realms = A.ORG, EXAMPLE.ORG ,B.ORG\n"),
        &["princ", "krb5", "alice@A.ORG", "princ", "krb5", "bob@B.ORG", "princ", "krb5", "alice@EXAMPLE.ORG"],
    ));
    check(lib("realms_empty_list", &conf("Local-Realms = ,\n"), &["princ", "krb5", "alice@EXAMPLE.ORG"]));
}

#[test]
fn nobody() {
    let c = conf("[Mapping]\nNobody-User = bob\nNobody-Group = users\n");
    check(lib("nobody_set", &c, &["owner2uid", "nosuch@example.org", "group2gid", "nosuch@example.org"]));
    let c = conf("[Mapping]\nNobody-User = nosuch\nNobody-Group = nosuch\n");
    check(lib("nobody_missing", &c, &["owner2uid", "nosuch@example.org", "group2gid", "nosuch@example.org"]));
    check(lib("nobody_default", &conf(""), &["owner2uid", "x@y", "group2gid", "x@y"]));
    let c = lib("nobody_none", &conf(""), &["owner2uid", "x@y", "group2gid", "x@y"])
        .etc("passwd", b"root:x:0:0::/:/bin/sh\n")
        .etc("group", b"root:x:0:\n");
    check(c);
}

#[test]
fn owner_numbers() {
    let mut cmds = Vec::new();
    for v in ["1234", "0", "00", "12abc", "-1", "4294967296", "99999999999", " 7", "+8", "0x10", ""] {
        cmds.extend_from_slice(&["owner2uid", v, "group2gid", v]);
    }
    check(lib("owner_numbers", &conf(""), &cmds));
}

#[test]
fn owner_names() {
    check(lib(
        "owner_names",
        &conf(""),
        &[
            "uid2owner",
            "1000",
            "-",
            "128",
            "uid2owner",
            "4242",
            "-",
            "128",
            "gid2owner",
            "4242",
            "-",
            "128",
            "uid2owner",
            "1000",
            "-",
            "5",
        ],
    ));
}

// --- Methods ---------------------------------------------------------------------

#[test]
fn methods_unknown() {
    let c = conf("[Translation]\nMethod = umich_ldap\n");
    check(lib("methods_unknown", &c, &["uid2name", "1000", "-", "128", "name2uid", "alice@example.org"]));
    let c = conf("[Translation]\nMethod = nsswitch, static , bogus\n[Static]\nx = alice\n");
    check(lib("methods_one_unknown", &c, &["uid2name", "1000", "-", "128"]));
    let long = "m".repeat(150);
    check(lib("methods_long_name", &conf(&format!("[Translation]\nMethod = {long}\n")), &["domain", "512"]));
}

#[test]
fn methods_order() {
    let st = "[Static]\nbob@EXAMPLE.ORG = alice\nstaff@EXAMPLE.ORG = users\n";
    for (i, m) in ["nsswitch,static", "static,nsswitch", "static", "nsswitch,nsswitch"].iter().enumerate() {
        let c = conf(&format!("[Translation]\nMethod = {m}\n{st}"));
        let cmds = [
            "uid2name",
            "1000",
            "-",
            "128",
            "gid2name",
            "100",
            "-",
            "128",
            "name2uid",
            "bob@EXAMPLE.ORG",
            "name2uid",
            "bob@example.org",
            "name2gid",
            "staff@EXAMPLE.ORG",
            "name2uid",
            "alice@other.org",
        ];
        check(lib(&format!("methods_order_{i}"), &c, &cmds));
    }
}

#[test]
fn methods_empty_list() {
    let c = conf("[Translation]\nMethod = ,\n");
    check(lib(
        "methods_empty_list",
        &c,
        &[
            "uid2name",
            "1000",
            "-",
            "128",
            "name2uid",
            "alice@example.org",
            "owner2uid",
            "x@y",
            "princ",
            "krb5",
            "alice@EXAMPLE.ORG",
        ],
    ));
}

#[test]
fn gss_methods() {
    let st = "[Static]\nbob@EXAMPLE.ORG = alice\n";
    let c = conf(&format!("[Translation]\nGSS-Methods = static\n{st}"));
    check(lib(
        "gss_methods",
        &c,
        &[
            "princ",
            "krb5",
            "bob@EXAMPLE.ORG",
            "princ",
            "krb5",
            "alice@EXAMPLE.ORG",
            "groups",
            "krb5",
            "bob@EXAMPLE.ORG",
            "8",
            "name2uid",
            "bob@EXAMPLE.ORG",
        ],
    ));
    // An unknown GSS method fails the setup when the domain is configured...
    let c = conf("[Translation]\nGSS-Methods = bogus\n[Mapping]\nNobody-User = bob\n");
    check(lib("gss_methods_unknown", &c, &["owner2uid", "x@y", "uid2name", "1000", "-", "128"]));
    // ...and is ignored (with the Nobody settings) when it came from DNS.
    let c = "[Translation]\nGSS-Methods = bogus\n[Mapping]\nNobody-User = bob\n";
    check(net(lib("gss_methods_unknown_dns_domain", c, &["owner2uid", "x@y", "princ", "krb5", "alice@EXAMPLE.NET"])));
}

#[test]
fn failed_init_retried_each_call() {
    let c = conf("[Translation]\nMethod = nsswitch,bogus\n");
    check(lib(
        "failed_init_retried_each_call",
        &c,
        &["uid2name", "1000", "-", "128", "name2gid", "staff@example.org", "domain", "512"],
    ));
}

// --- nsswitch ------------------------------------------------------------------

const ADPASSWD: &str = "carol@ad.example.com:x:3000:3000::/:/bin/sh\nEXAMPLE\\dave:x:3001:3001::/:/bin/sh\n";
const ADGROUP: &str = "devs@ad.example.com:x:3000:\nAD\\ops:x:3001:\n";

fn ad(c: Case) -> Case {
    c.etc("passwd", format!("{}{ADPASSWD}", idmap::PASSWD).as_bytes())
        .etc("group", format!("{}{ADGROUP}", idmap::GROUP).as_bytes())
}

#[test]
fn nss_lookups() {
    check(lib("nss_lookups", &conf(""), LOOKUPS));
}

#[test]
fn nss_name_forms() {
    let cmds = [
        "name2uid",
        "ALICE@EXAMPLE.ORG",
        "name2uid",
        "alice@EXAMPLE.ORG",
        "name2uid",
        "alice",
        "name2uid",
        "@example.org",
        "name2uid",
        "a@b@example.org",
        "name2uid",
        "alice@example.org@x",
        "name2gid",
        "staff",
        "name2gid",
        "staff@other.org",
        "name2gid",
        "STAFF@example.org",
        "name2uid",
        "",
    ];
    check(ad(lib("nss_name_forms", &conf(""), &cmds)));
}

#[test]
fn nss_no_strip() {
    for (i, ns) in ["user", "group", "both", "none", "BOTH", "junk"].iter().enumerate() {
        let c = conf(&format!("No-Strip = {ns}\n"));
        let cmds = [
            "name2uid",
            "carol@ad.example.com",
            "name2uid",
            "alice@example.org",
            "name2gid",
            "devs@ad.example.com",
            "name2gid",
            "staff@example.org",
            "uid2name",
            "3000",
            "-",
            "128",
            "gid2name",
            "3000",
            "-",
            "128",
            "uid2name",
            "1000",
            "-",
            "128",
        ];
        check(ad(lib(&format!("nss_no_strip_{i}"), &c, &cmds)));
    }
}

#[test]
fn nss_reformat_group() {
    for (i, (ns, rf)) in
        [("group", "true"), ("both", "yes"), ("user", "on"), ("group", "false"), ("both", "ON")].iter().enumerate()
    {
        let c = conf(&format!("No-Strip = {ns}\nReformat-Group = {rf}\n"));
        let cmds = [
            "name2gid",
            "ops@ad.example.com",
            "name2gid",
            "ops@ad",
            "name2gid",
            "staff@example.org",
            "name2gid",
            "devs@ad.example.com",
        ];
        check(ad(lib(&format!("nss_reformat_group_{i}"), &c, &cmds)));
    }
}

#[test]
fn nss_name_length() {
    // alice@example.org is 17 bytes, 18 with the NUL.
    let mut cmds = Vec::new();
    for len in ["18", "17", "1", "0"] {
        cmds.extend_from_slice(&["uid2name", "1000", "-", len, "gid2name", "1000", "-", len]);
    }
    check(lib("nss_name_length", &conf(""), &cmds));
    let c = conf("No-Strip = both\n");
    check(ad(lib("nss_name_length_nostrip", &c, &["uid2name", "3000", "-", "21", "uid2name", "3000", "-", "20"])));
}

#[test]
fn nss_big_entries() {
    // getpwnam_r()'s 1024-byte buffer is never grown: ERANGE (and for a uid, ENOENT);
    // getgrgid_r()'s and getgrnam_r()'s are.
    let gecos = "g".repeat(1100);
    let members: Vec<String> = (0..300).map(|i| format!("member{i}")).collect();
    let c = lib(
        "nss_big_entries",
        &conf("[Translation]\nMethod = nsswitch,static\n[Static]\nbig@example.org = alice\n"),
        &[
            "name2uid",
            "big@example.org",
            "uid2name",
            "5000",
            "-",
            "128",
            "name2gid",
            "crowd@example.org",
            "gid2name",
            "5000",
            "-",
            "128",
            "owner2uid",
            "big@example.org",
        ],
    )
    .etc("passwd", format!("{}big:x:5000:5000:{gecos}:/:/bin/sh\n", idmap::PASSWD).as_bytes())
    .etc("group", format!("{}crowd:x:5000:{}\n", idmap::GROUP, members.join(",")).as_bytes());
    check(c);
}

#[test]
fn nss_principals() {
    let cmds = [
        "princ",
        "krb5",
        "alice@EXAMPLE.ORG",
        "princ",
        "krb5",
        "alice@OTHER.ORG",
        "princ",
        "spkm3",
        "alice@EXAMPLE.ORG",
        "princ",
        "lipkey",
        "alice@EXAMPLE.ORG",
        "princ",
        "krb5",
        "alice",
        "princ",
        "krb5",
        "nosuch@EXAMPLE.ORG",
        "princ_ex",
        "krb5",
        "bob@EXAMPLE.ORG",
        "princ",
        "krb5",
        "a@b@EXAMPLE.ORG",
    ];
    check(lib("nss_principals", &conf(""), &cmds));
}

#[test]
fn nss_grouplists() {
    let cmds = [
        "groups",
        "krb5",
        "alice@EXAMPLE.ORG",
        "10",
        "groups",
        "krb5",
        "alice@EXAMPLE.ORG",
        "1",
        "groups",
        "krb5",
        "alice@EXAMPLE.ORG",
        "0",
        "groups",
        "krb5",
        "alice@ANYWHERE",
        "10",
        "groups",
        "spkm3",
        "alice@EXAMPLE.ORG",
        "10",
        "groups",
        "krb5",
        "nosuch@EXAMPLE.ORG",
        "10",
        "groups_ex",
        "krb5",
        "bob",
        "10",
    ];
    check(lib("nss_grouplists", &conf(""), &cmds));
}

// --- static ----------------------------------------------------------------------

#[test]
fn static_mappings() {
    let c = conf(
        "[Translation]\nMethod = static\n[Static]\nbob@EXAMPLE.ORG = alice\nalice@EXAMPLE.ORG = alice\n\
         staff@EXAMPLE.ORG = staff\nghost@EXAMPLE.ORG = nosuch\nusers@EXAMPLE.ORG = users\n",
    );
    let cmds = [
        "uid2name",
        "1000",
        "-",
        "128",
        "uid2name",
        "1000",
        "-",
        "1",
        "gid2name",
        "50",
        "-",
        "128",
        "gid2name",
        "1000",
        "-",
        "128",
        "uid2name",
        "1001",
        "-",
        "128",
        "name2uid",
        "bob@EXAMPLE.ORG",
        "name2uid",
        "BOB@example.org",
        "name2uid",
        "ghost@EXAMPLE.ORG",
        "name2gid",
        "staff@EXAMPLE.ORG",
        "name2gid",
        "ghost@EXAMPLE.ORG",
        "princ",
        "krb5",
        "bob@EXAMPLE.ORG",
        "princ",
        "spkm3",
        "bob@EXAMPLE.ORG",
        "princ",
        "lipkey",
        "bob@EXAMPLE.ORG",
        "groups",
        "krb5",
        "bob@EXAMPLE.ORG",
        "10",
        "groups",
        "krb5",
        "bob@EXAMPLE.ORG",
        "1",
        "groups",
        "krb5",
        "ghost@EXAMPLE.ORG",
        "4",
    ];
    check(lib("static_mappings", &c, &cmds));
}

#[test]
fn static_sections() {
    // Subsections' tags are in the tag list, but conf_get_str() doesn't see them; a
    // later file's binding replaces an earlier one; values are expanded from the
    // environment.
    let c = conf(
        "[Translation]\nMethod = static\n[Static]\na@X = alice\n[Static \"sub\"]\nb@X = bob\n[Static]\nc@X = $IDMAP_USER\n",
    )
    .to_string();
    let t = lib(
        "static_sections",
        &c,
        &["uid2name", "1000", "-", "128", "uid2name", "1001", "-", "128", "name2uid", "b@X", "name2uid", "c@X"],
    )
    .env("IDMAP_USER=bob")
    .etc("idmapd.conf.d/extra.conf", b"[Static]\na@X = bob\n");
    check(t);
}

#[test]
fn static_empty() {
    check(lib(
        "static_empty",
        &conf("[Translation]\nMethod = static\n"),
        &["uid2name", "1000", "-", "128", "name2uid", "x@y"],
    ));
}

#[test]
fn static_long_principal() {
    // C copies the principal without looking at the length.
    let p = format!("{}@EXAMPLE.ORG", "p".repeat(200));
    let c = conf(&format!("[Translation]\nMethod = static\n[Static]\n{p} = alice\n"));
    check(lib("static_long_principal", &c, &["uid2name", "1000", "-", "16"]));
}

// --- regex ---------------------------------------------------------------------

const REGEX: &str = "[Translation]\nMethod = regex\n[Regex]\n\
    User-Regex = ^DOMAIN\\\\([^@]+)@REALM$\n\
    Group-Regex = ^([^@]+)@REALM$\n\
    Prepend-Before-User = DOMAIN\\\n\
    Append-After-User = @REALM\n\
    Prepend-Before-Group = <\n\
    Append-After-Group = @REALM\n";

#[test]
fn regex_mappings() {
    let cmds = [
        "name2uid",
        "DOMAIN\\alice@REALM",
        "name2uid",
        "domain\\alice@realm",
        "name2uid",
        "alice@REALM",
        "name2uid",
        "DOMAIN\\nosuch@REALM",
        "name2gid",
        "staff@REALM",
        "name2gid",
        "nosuch@REALM",
        "uid2name",
        "1000",
        "-",
        "128",
        "uid2name",
        "1000",
        "-",
        "20",
        "uid2name",
        "4242",
        "-",
        "128",
        "gid2name",
        "50",
        "-",
        "128",
        "princ",
        "krb5",
        "DOMAIN\\bob@REALM",
        "princ",
        "lipkey",
        "x",
        "groups",
        "krb5",
        "DOMAIN\\alice@REALM",
        "10",
        "groups",
        "krb5",
        "DOMAIN\\alice@REALM",
        "1",
    ];
    check(lib("regex_mappings", &conf(REGEX), &cmds));
}

#[test]
fn regex_group_prefix() {
    let c = conf(&format!("{REGEX}Group-Name-Prefix = grp-\nGroup-Name-No-Prefix-Regex = ^grp-(keep|users)$\n"))
        .replace("Prepend-Before-Group = <\n", "");
    let g = format!("{}grp-ops:x:60:\ngrp-keep:x:61:\nkeep:x:62:\nops:x:63:\n", idmap::GROUP);
    let cmds = [
        "name2gid",
        "grp-ops@REALM",
        "name2gid",
        "ops@REALM",
        "name2gid",
        "grp-keep@REALM",
        "name2gid",
        "grp-users@REALM",
        "gid2name",
        "60",
        "-",
        "128",
        "gid2name",
        "61",
        "-",
        "128",
        "gid2name",
        "62",
        "-",
        "128",
        "gid2name",
        "63",
        "-",
        "128",
        "gid2name",
        "100",
        "-",
        "128",
    ];
    check(lib("regex_group_prefix", &c, &cmds).etc("group", g.as_bytes()));
}

#[test]
fn regex_no_subexpression() {
    let c = conf("[Translation]\nMethod = regex\n[Regex]\nUser-Regex = ^alice$\nGroup-Regex = (x)|(staff)\n");
    check(lib("regex_no_subexpression", &c, &["name2uid", "alice", "name2gid", "staff", "name2gid", "x"]));
}

#[test]
fn regex_bad_settings() {
    // regex_init() always succeeds; the calls that use what it didn't set crash.
    for (i, (re, cmds)) in [
        ("", &["uid2name", "4242", "-", "128", "uid2name", "1000", "-", "128"][..]),
        ("", &["name2uid", "alice"][..]),
        ("User-Regex = (\n", &["gid2name", "4242", "-", "128", "name2gid", "x"][..]),
        ("User-Regex = (a)\n", &["name2uid", "a"][..]),
        ("User-Regex = (a)\nGroup-Regex = [\n", &["name2gid", "a"][..]),
        (
            "User-Regex = (a)\nGroup-Regex = (b)\nGroup-Name-No-Prefix-Regex = (\n",
            &["uid2name", "1000", "-", "128", "gid2name", "50", "-", "128", "name2uid", "a"][..],
        ),
    ]
    .iter()
    .enumerate()
    {
        let c = conf(&format!("[Translation]\nMethod = regex\n[Regex]\n{re}"));
        check(lib(&format!("regex_bad_settings_{i}"), &c, cmds));
    }
}

// --- Logging and the rest ---------------------------------------------------------

#[test]
fn log_levels() {
    for lvl in ["0", "1", "2", "3"] {
        let c = raw(
            &format!("log_level_{lvl}"),
            &conf("[Translation]\nMethod = nsswitch,bogus\n"),
            &["debug", lvl, "log", "init", "-", "name2uid", "alice@other.org"],
        );
        check(c);
    }
}

#[test]
fn log_to_syslog() {
    // The default logger: syslog, LOG_WARNING.
    check(raw(
        "log_to_syslog",
        &conf("Local-Realms = A\n"),
        &["debug", "2", "syslog", "init", "-", "name2uid", "alice@other.org", "princ", "krb5", "x@B"],
    ));
    check(raw("log_default_level", &conf(""), &["init", "-", "name2uid", "alice@other.org"]));
}

#[test]
fn config_get() {
    let c = conf("[Mapping]\nNobody-User = bob\n[Odd \"sub\"]\nx = 1\n[env]\ny = $HOME_X\n");
    check(
        lib(
            "config_get",
            &c,
            &[
                "conf",
                "General",
                "Domain",
                "conf",
                "mapping",
                "NOBODY-USER",
                "conf",
                "Odd",
                "x",
                "conf",
                "env",
                "y",
                "conf",
                "none",
                "none",
            ],
        )
        .env("HOME_X=hx"),
    );
}

#[test]
fn conf_errors_logged_per_copy() {
    let c = conf(
        "junk without equals\n[Translation]\nMethod = nsswitch,static,regex\n[Regex]\nUser-Regex = (a)\nGroup-Regex = (b)\n",
    );
    check(lib("conf_errors_logged_per_copy", &c, &["uid2name", "1000", "-", "128"]));
}
