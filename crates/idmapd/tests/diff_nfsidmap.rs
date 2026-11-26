//! nfsidmap, the request-key helper, against the C one: the keys it answers, the
//! keyring tools, its options and messages. The keys are the shim's (see
//! `tests/shim/fakekeys.c`), and `/proc/keys` a file; the key log records every key
//! call either program made.

#[path = "../../statd/tests/common/mod.rs"]
mod common;
mod idmap;

use common::{Case, check};
use idmap::*;

fn nc(name: &str, args: &[&str], conf: &str) -> Case {
    icase(&format!("nfsidmap_{name}"), "nfsidmap", args, conf)
}

/// A request for key 4660 (0x1234) described as `desc`.
fn req(name: &str, desc: &str, conf: &str) -> Case {
    nc(name, &["4660", desc], conf)
}

/// The `.id_resolver` keyring (serial 0x100) in /proc/keys, with `members`.
const RING_LINE: &str = "00000100 I------     1 perm 3f030000     0     0 keyring   .id_resolver: 2\n";

fn ring(c: Case, members: &[(&str, &str)], extra_state: &str) -> Case {
    let mut state = "key 100 keyring .id_resolver\n".to_string();
    let mut proc_keys = RING_LINE.to_string();
    for (serial, desc) in members {
        state.push_str(&format!("key {serial} id_resolver {desc}\nmember 100 {serial}\n"));
        proc_keys.push_str(&format!("{serial:0>8} I--Q---     1  9m 3b010000     0     0 id_resolver {desc}: 5\n"));
    }
    state.push_str(extra_state);
    keys(c, &state, &proc_keys)
}

// --- Answering keys -------------------------------------------------------------

#[test]
fn uid_key() {
    check(req("uid_key", "uid:alice@example.org", &conf("")));
}

#[test]
fn gid_key() {
    check(req("gid_key", "gid:staff@example.org", &conf("")));
}

#[test]
fn user_key() {
    check(req("user_key", "user:1000", &conf("")));
}

#[test]
fn group_key() {
    check(req("group_key", "group:50", &conf("")));
}

#[test]
fn hex_key_is_decimal() {
    // strtol(..., 10): "0x1234" is key 0.
    check(nc("hex_key_is_decimal", &["0x1234", "uid:alice@example.org"], &conf("")));
}

#[test]
fn key_number_overflows() {
    check(nc("key_number_overflows", &["99999999999", "uid:alice@example.org"], &conf("")));
}

#[test]
fn uid_unknown_user_is_nobody() {
    check(req("uid_unknown_user_is_nobody", "uid:nosuch@example.org", &conf("")));
}

#[test]
fn uid_foreign_domain_is_nobody() {
    check(req("uid_foreign_domain_is_nobody", "uid:alice@other.org", &conf("")));
}

#[test]
fn gid_unknown_group_is_nobody() {
    check(req("gid_unknown_group_is_nobody", "gid:nosuch@example.org", &conf("")));
}

#[test]
fn uid_numbers() {
    for (i, v) in ["1234", "0", "12abc", "-1", "99999999999", " 7", "+8", "0x10", "00"].iter().enumerate() {
        check(req(&format!("uid_numbers_{i}"), &format!("uid:{v}"), &conf("")));
    }
}

#[test]
fn gid_numbers() {
    for (i, v) in ["4321", "0", "5x"].iter().enumerate() {
        check(req(&format!("gid_numbers_{i}"), &format!("gid:{v}"), &conf("")));
    }
}

#[test]
fn nobody_user_and_group_set() {
    let c = conf("[Mapping]\nNobody-User = bob\nNobody-Group = users\n");
    check(req("nobody_user_set", "uid:nosuch@example.org", &c));
    check(req("nobody_group_set", "gid:nosuch@example.org", &c));
}

#[test]
fn nobody_user_missing() {
    let c = conf("[Mapping]\nNobody-User = nosuchuser\nNobody-Group = nosuchgroup\n");
    check(req("nobody_user_missing", "uid:nosuch@example.org", &c));
    check(req("nobody_group_missing", "gid:nosuch@example.org", &c));
}

#[test]
fn no_nobody_at_all() {
    // Without a nobody to map to, -2.
    let c = req("no_nobody_at_all", "uid:nosuch@example.org", &conf(""))
        .etc("passwd", b"root:x:0:0::/:/bin/sh\nalice:x:1000:1000::/:/bin/sh\n");
    check(c);
}

#[test]
fn user_key_unknown_uid() {
    check(req("user_key_unknown_uid", "user:4242", &conf("")));
}

#[test]
fn group_key_unknown_gid() {
    check(req("group_key_unknown_gid", "group:4242", &conf("")));
}

#[test]
fn user_key_not_a_number() {
    // atoi(): "abc" is uid 0.
    check(req("user_key_not_a_number", "user:abc", &conf("")));
}

#[test]
fn user_key_name_too_long() {
    // 116 + "@example.org" + NUL = 129 bytes: one too many.
    let long = "u".repeat(116);
    let c = req("user_key_name_too_long", "user:2000", &conf(""))
        .etc("passwd", format!("{}{long}:x:2000:2000::/:/bin/sh\n", idmap::PASSWD).as_bytes());
    check(c);
    // 128 bytes with the NUL: just fits.
    let fits = "v".repeat(115);
    let c = req("user_key_name_just_fits", "user:2001", &conf(""))
        .etc("passwd", format!("{}{fits}:x:2001:2001::/:/bin/sh\n", idmap::PASSWD).as_bytes());
    check(c);
}

#[test]
fn unknown_key_type() {
    // rc stays 0: the key gets a timeout, no answer, exit 0.
    check(req("unknown_key_type", "foo:bar", &conf("")));
}

#[test]
fn key_without_value() {
    check(req("key_without_value", "uid", &conf("")));
    check(req("key_empty_value", "uid:", &conf("")));
    check(req("key_only_colons", ":::", &conf("")));
}

#[test]
fn key_desc_strtok() {
    check(req("key_desc_leading_colons", "::uid::alice@example.org", &conf("")));
    check(req("key_desc_extra_field", "uid:alice@example.org:extra", &conf("")));
}

#[test]
fn bad_arg_count() {
    check(nc("bad_arg_count_0", &[], &conf("")));
    check(nc("bad_arg_count_1", &["4660"], &conf("")));
    check(nc("bad_arg_count_3", &["4660", "uid:alice@example.org", "x"], &conf("")));
    check(nc("bad_arg_count_1v", &["-v", "4660"], &conf("")));
}

#[test]
fn verbose() {
    check(nc("verbose_1", &["-v", "4660", "uid:alice@example.org"], &conf("")));
    check(nc("verbose_2", &["-vv", "4660", "user:1000"], &conf("")));
    check(nc("verbose_4", &["-vvvv", "4660", "uid:nosuch@example.org"], &conf("")));
}

#[test]
fn verbosity_setting_ignored() {
    // nfsidmap reads Verbosity from its own copy of the configuration, never loaded.
    check(req("verbosity_setting_ignored", "uid:alice@example.org", &conf("Verbosity = 4\n")));
}

#[test]
fn timeout_option() {
    check(nc("timeout_30", &["-t", "30", "4660", "uid:alice@example.org"], &conf("")));
    check(nc("timeout_junk", &["-t", "abc", "4660", "uid:alice@example.org"], &conf("")));
    check(nc("timeout_negative", &["-t", "-5", "4660", "gid:staff@example.org"], &conf("")));
}

#[test]
fn operands_before_options() {
    // glibc's getopt() moves the operands last.
    check(nc("operands_before_options", &["4660", "uid:alice@example.org", "-v"], &conf("")));
}

#[test]
fn help_and_bad_options() {
    check(nc("help", &["-h"], &conf("")));
    check(nc("bad_option", &["-x"], &conf("")));
    check(nc("missing_argument", &["-t"], &conf("")));
}

#[test]
fn not_root() {
    let c = req("not_root", "uid:alice@example.org", &conf("")).wrap(
        "python3 -c 'import os,sys; os.setgroups([]); os.setgid(1000); os.setuid(1000); os.execv(sys.argv[1], sys.argv[1:])'",
    );
    check(c);
}

// --- Instantiation failures -----------------------------------------------------

#[test]
fn keyring_full_cleared_and_retried() {
    let c = ring(
        req("keyring_full", "uid:alice@example.org", &conf("")),
        &[("201", "uid:bob")],
        "fail instantiate 1234 122 1\n",
    );
    check(c);
    let c = ring(
        nc("keyring_full_v", &["-v", "4660", "uid:alice@example.org"], &conf("")),
        &[],
        "fail instantiate 1234 12 1\n",
    );
    check(c);
}

#[test]
fn keyring_full_retry_fails() {
    let c =
        ring(req("keyring_full_retry_fails", "gid:staff@example.org", &conf("")), &[], "fail instantiate 1234 23\n");
    check(c);
}

#[test]
fn keyring_full_no_keyring() {
    // The keyring can't be found: "cleared", and the retry fails.
    let c = keys(req("keyring_full_no_keyring", "uid:alice@example.org", &conf("")), "fail instantiate 1234 122\n", "");
    check(c);
}

#[test]
fn keyring_full_clear_fails() {
    let c = ring(
        req("keyring_full_clear_fails", "uid:alice@example.org", &conf("")),
        &[],
        "fail instantiate 1234 122\nfail clear 100 13\n",
    );
    check(c);
}

#[test]
fn instantiate_other_error() {
    // Not EDQUOT/ENFILE/ENOMEM: exit 1 without a word.
    check(keys(req("instantiate_eacces", "uid:alice@example.org", &conf("")), "fail instantiate 1234 13\n", ""));
    check(keys(req("instantiate_name_fails", "user:1000", &conf("")), "fail instantiate 1234 122\n", ""));
}

#[test]
fn set_timeout_fails() {
    check(keys(req("set_timeout_fails", "uid:alice@example.org", &conf("")), "fail set_timeout * 13\n", ""));
}

#[test]
fn possessor_request_fails() {
    // request_key() for the keyring is only to become a possessor: its result is
    // ignored.
    check(keys(req("possessor_request_fails", "uid:alice@example.org", &conf("")), "fail request_key * 1\n", ""));
}

// --- -c ------------------------------------------------------------------------

#[test]
fn clear() {
    check(ring(nc("clear", &["-c"], &conf("")), &[("201", "uid:bob"), ("202", "gid:staff")], ""));
    check(ring(nc("clear_v", &["-cv"], &conf("")), &[("201", "uid:bob")], ""));
}

#[test]
fn clear_found_by_request_key() {
    let c = ring(nc("clear_found_by_request_key", &["-c"], &conf("")), &[], "request keyring .id_resolver 100\n");
    check(c);
}

#[test]
fn clear_no_keyring() {
    check(nc("clear_no_keyring", &["-c"], &conf("")));
    check(nc("clear_no_keyring_v", &["-c", "-v"], &conf("")));
}

#[test]
fn clear_fails() {
    check(ring(nc("clear_fails", &["-c"], &conf("")), &[], "fail clear 100 13\n"));
}

#[test]
fn keyring_lookup_details() {
    // A keyring whose /proc/keys description only starts with the name, one whose
    // real description differs, one of another type, and a describe that fails.
    let proc_keys = "00000101 I------     1 perm 3f030000     0     0 keyring   .id_resolver_x: 1\n\
                     00000102 I------     1 perm 3f030000     0     0 user      .id_resolver: 1\n\
                     00000103 I------     1 perm 3f030000     0     0 keyring   .id_resolver: 1\n\
                     00000104 I------     1 perm 3f030000     0     0 keyring   .id_resolver: 1\n\
                     00000105 I------     1 perm 3f030000     0     0 keyring   .id_resolver: 1\n";
    let state = "key 101 keyring .id_resolver_x\nkey 102 user .id_resolver\nkey 103 keyring other\n\
                 key 104 keyring .id_resolver\nfail describe 104 13\nkey 105 keyring .id_resolver\n";
    check(keys(nc("keyring_lookup_details", &["-cv"], &conf("")), state, proc_keys));
    // Every candidate fails: errno is the last failure's.
    let state = "key 104 keyring .id_resolver\nfail describe 104 13\n";
    check(keys(
        nc("keyring_lookup_all_fail", &["-cv"], &conf("")),
        state,
        "00000104 I------     1 perm 3f030000     0     0 keyring   .id_resolver: 1\n",
    ));
}

#[test]
fn proc_keys_odd_lines() {
    // Short and malformed lines are skipped.
    let proc_keys = "garbage\n\n00000100 I------\n00000100 I------     1 perm 3f030000     0     0 keyring\n"
        .to_string()
        + RING_LINE;
    check(keys(nc("proc_keys_odd_lines", &["-c"], &conf("")), "key 100 keyring .id_resolver\n", &proc_keys));
}

// --- -l ------------------------------------------------------------------------

#[test]
fn list() {
    check(ring(nc("list_empty", &["-l"], &conf("")), &[], ""));
    check(ring(nc("list_one", &["-l"], &conf("")), &[("201", "uid:bob")], ""));
    check(ring(
        nc("list_three", &["-l"], &conf("")),
        &[("201", "uid:bob"), ("202", "gid:staff"), ("203", "user:1000")],
        "",
    ));
}

#[test]
fn list_expired_key() {
    check(ring(nc("list_expired_key", &["-l"], &conf("")), &[("201", "uid:bob"), ("202", "gid:x")], "expired 201\n"));
}

#[test]
fn list_describe_fails() {
    // Exits at once, after what was printed.
    check(ring(
        nc("list_describe_fails", &["-l"], &conf("")),
        &[("201", "uid:bob"), ("202", "gid:x")],
        "fail describe 202 13\n",
    ));
    // A member the kernel doesn't know.
    check(ring(nc("list_unknown_member", &["-l"], &conf("")), &[("201", "uid:bob")], "member 100 999\n"));
}

#[test]
fn list_read_fails() {
    check(ring(nc("list_read_fails", &["-l"], &conf("")), &[], "fail read 100 13\n"));
}

#[test]
fn list_no_keyring() {
    check(nc("list_no_keyring", &["-l"], &conf("")));
}

#[test]
fn display_wins() {
    check(ring(nc("display_wins", &["-l", "-d", "-c", "-u", "bob"], &conf("")), &[], ""));
    check(ring(nc("list_before_invalidate", &["-c", "-l", "-u", "bob"], &conf("")), &[], ""));
    check(ring(nc("invalidate_before_clear", &["-c", "-u", "bob"], &conf("")), &[("201", "uid:bob")], ""));
}

// --- -u, -g, -r ------------------------------------------------------------------

fn idkeys(c: Case, extra: &str) -> Case {
    ring(
        c,
        &[
            ("201", "uid:bob@example.org"),
            ("202", "gid:staff@example.org"),
            ("203", "uid:alice@example.org"),
            ("204", "gid:bob@example.org"),
        ],
        extra,
    )
}

#[test]
fn invalidate() {
    check(idkeys(nc("invalidate_u", &["-u", "bob"], &conf("")), ""));
    check(idkeys(nc("invalidate_g", &["-g", "staff"], &conf("")), ""));
    check(idkeys(nc("invalidate_r", &["-r", "bob"], &conf("")), ""));
    check(idkeys(nc("invalidate_v", &["-v", "-r", "bob"], &conf("")), ""));
    check(idkeys(nc("invalidate_prefix", &["-u", "al"], &conf("")), ""));
    check(idkeys(nc("invalidate_last_option_wins", &["-u", "bob", "-g", "staff"], &conf("")), ""));
}

#[test]
fn invalidate_not_found() {
    check(idkeys(nc("invalidate_not_found", &["-u", "carol"], &conf("")), ""));
    check(idkeys(nc("invalidate_r_half_found", &["-r", "alice"], &conf("")), ""));
    check(nc("invalidate_no_keys", &["-g", "x"], &conf("")));
}

#[test]
fn invalidate_falls_back_to_revoke() {
    check(idkeys(nc("invalidate_revoke", &["-u", "bob"], &conf("")), "fail invalidate * 95\n"));
    check(idkeys(nc("invalidate_revoke_fails", &["-u", "bob"], &conf("")), "fail invalidate * 95\nfail revoke * 1\n"));
}

#[test]
fn invalidate_fails() {
    check(idkeys(nc("invalidate_fails", &["-u", "bob"], &conf("")), "fail invalidate * 13\n"));
}

#[test]
fn invalidate_line_matching() {
    // "uid:" anywhere in the line counts, "keyring" anywhere skips it.
    let proc_keys = "00000301 I--Q---     1  9m 3b010000     0     0 user      tag uid:bob: 3\n\
                     00000302 I--Q---     1  9m 3b010000     0     0 id_resolver keyring uid:bob: 3\n\
                     00000303 I--Q---     1  9m 3b010000     0     0 id_resolver gid:uid:bob: 3\n";
    let state = "key 301 user tag\nkey 303 id_resolver x\n";
    check(keys(nc("invalidate_line_matching", &["-vr", "bob"], &conf("")), state, proc_keys));
}

// --- The configuration -----------------------------------------------------------

#[test]
fn init_fails() {
    check(req("init_fails", "uid:alice@example.org", &conf("[Translation]\nMethod = bogus\n")));
    check(nc("init_fails_d", &["-d"], &conf("[Translation]\nMethod = nsswitch,bogus\n")));
}

#[test]
fn domain_too_long() {
    let d = "d".repeat(600);
    let c = format!("[General]\nDomain = {d}\n");
    check(nc("domain_too_long_d", &["-d"], &c));
    check(req("domain_too_long_user", "user:1000", &c));
    check(req("domain_too_long_uid", "uid:alice@", &c));
}

#[test]
fn domain_from_dns() {
    let c =
        nc("domain_from_dns", &["-d"], "").etc("hosts", b"127.0.0.1 localhost\n127.0.1.1 host.example.net nsmtest\n");
    check(dns(c, "_nfsv4idmapdomain.example.net TXT txt:nfs.example.net"));
    let c = req("domain_from_dns_user", "user:1000", "")
        .etc("hosts", b"127.0.0.1 localhost\n127.0.1.1 host.example.net nsmtest\n");
    check(c);
}

#[test]
fn conf_errors_logged_per_copy() {
    // The library and each method read the file into their own copies, each logging
    // its errors (with an empty program name).
    let c = conf("bogus line here\n[Translation]\nMethod = nsswitch,static\n[Static]\nbob@EXAMPLE.ORG = bob\n");
    check(req("conf_errors_logged_per_copy", "uid:alice@example.org", &c));
}

#[test]
fn static_method() {
    let c =
        conf("[Translation]\nMethod = static,nsswitch\n[Static]\nbob@EXAMPLE.ORG = alice\nstaff@EXAMPLE.ORG = staff\n");
    check(req("static_uid", "uid:bob@EXAMPLE.ORG", &c));
    check(req("static_user", "user:1000", &c));
    check(req("static_group", "group:50", &c));
    check(req("static_falls_through", "uid:bob@example.org", &c));
}

#[test]
fn empty_method_list() {
    // QUIRK: no methods at all, and every lookup "succeeds" without an answer: owners
    // map to the id the caller started with, 0.
    let c = conf("[Translation]\nMethod = ,\n");
    check(req("empty_method_list_uid", "uid:anyone@anywhere", &c));
    check(req("empty_method_list_gid", "gid:anyone@anywhere", &c));
    check(req("empty_method_value", "uid:anyone@anywhere", &conf("[Translation]\nMethod =\n")));
}

#[test]
fn regex_without_expressions_crashes() {
    let c = conf("[Translation]\nMethod = regex\n");
    check(req("regex_without_expressions_crashes", "uid:alice@example.org", &c));
}
