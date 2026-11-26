//! idmaptest: drive the library's calls from the command line, for the differential
//! tests. The same commands and output as `tests/tools/idmaptest.c` (see there) over
//! the C library.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use support::sys;

fn elog(msg: &[u8]) {
    let mut v = b"log: ".to_vec();
    v.extend_from_slice(support::xlog::c_str(msg));
    v.push(b'\n');
    sys::stderr(&v);
}

fn opt(s: &[u8]) -> Option<&[u8]> {
    if s == b"-" { None } else { Some(s) }
}

/// Bytes as a string of the chars U+0000-U+00FF, turned back into the same bytes when
/// printed (C prints them as they are).
fn s(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

fn num(b: &[u8]) -> u64 {
    sys::strtoul(b, 10).0
}

fn main() {
    let argv: Vec<Vec<u8>> = std::env::args_os().map(|a| a.as_bytes().to_vec()).collect();
    let mut i = 1;
    let out = std::io::stdout();
    while i < argv.len() {
        let cmd = argv[i].clone();
        i += 1;
        let mut buf = b"(untouched)".to_vec();
        let line = match &cmd[..] {
            b"init" => {
                let rc = nfsidmap::nfs4_init_name_mapping(opt(&argv[i]));
                i += 1;
                format!("init = {rc}")
            }
            b"term" => {
                nfsidmap::nfs4_term_name_mapping();
                "term".to_string()
            }
            b"debug" => {
                let n = sys::atoi(&argv[i]);
                let logger: Option<nfsidmap::LogFn> = if argv[i + 1] == b"log" { Some(elog) } else { None };
                i += 2;
                nfsidmap::nfs4_set_debug(n, logger);
                format!("debug {n}")
            }
            b"domain" => {
                let len = num(&argv[i]) as usize;
                i += 1;
                let rc = nfsidmap::nfs4_get_default_domain(None, &mut buf, len);
                format!("domain = {rc} '{}'", s(&buf))
            }
            b"uid2name" | b"gid2name" | b"uid2owner" | b"gid2owner" => {
                let id = num(&argv[i]) as u32;
                let dom = opt(&argv[i + 1]).map(<[u8]>::to_vec);
                let len = num(&argv[i + 2]) as usize;
                i += 3;
                let d = dom.as_deref();
                let rc = match &cmd[..] {
                    b"uid2name" => nfsidmap::nfs4_uid_to_name(id, d, &mut buf, len),
                    b"gid2name" => nfsidmap::nfs4_gid_to_name(id, d, &mut buf, len),
                    b"uid2owner" => nfsidmap::nfs4_uid_to_owner(id, d, &mut buf, len),
                    _ => nfsidmap::nfs4_gid_to_group_owner(id, d, &mut buf, len),
                };
                format!("{} {id} = {rc} '{}'", s(&cmd), s(&buf))
            }
            b"name2uid" | b"name2gid" | b"owner2uid" | b"group2gid" => {
                let name = argv[i].clone();
                i += 1;
                let mut id: u32 = 4242424242;
                let rc = match &cmd[..] {
                    b"name2uid" => nfsidmap::nfs4_name_to_uid(&name, &mut id),
                    b"name2gid" => nfsidmap::nfs4_name_to_gid(&name, &mut id),
                    b"owner2uid" => nfsidmap::nfs4_owner_to_uid(&name, &mut id),
                    _ => nfsidmap::nfs4_group_owner_to_gid(&name, &mut id),
                };
                format!("{} '{}' = {rc} {id}", s(&cmd), s(&name))
            }
            b"princ" | b"princ_ex" => {
                let (sec, princ) = (argv[i].clone(), argv[i + 1].clone());
                i += 2;
                let (mut uid, mut gid): (u32, u32) = (4242424242, 4242424242);
                let rc = if cmd == b"princ" {
                    nfsidmap::nfs4_gss_princ_to_ids(&sec, &princ, &mut uid, &mut gid)
                } else {
                    nfsidmap::nfs4_gss_princ_to_ids_ex(&sec, &princ, &mut uid, &mut gid)
                };
                format!("{} {} '{}' = {rc} {uid} {gid}", s(&cmd), s(&sec), s(&princ))
            }
            b"groups" | b"groups_ex" => {
                let (sec, princ) = (argv[i].clone(), argv[i + 1].clone());
                let room = sys::atoi(&argv[i + 2]);
                i += 3;
                let mut n = room;
                let mut groups = Vec::new();
                let rc = if cmd == b"groups" {
                    nfsidmap::nfs4_gss_princ_to_grouplist(&sec, &princ, &mut groups, &mut n)
                } else {
                    nfsidmap::nfs4_gss_princ_to_grouplist_ex(&sec, &princ, &mut groups, &mut n)
                };
                let mut l = format!("{} {} '{}' = {rc} {n}:", s(&cmd), s(&sec), s(&princ));
                // What the call didn't write keeps the driver's sentinel, as in C.
                for k in 0..n.max(0).min(room.max(0)) as usize {
                    l.push_str(&format!(" {}", groups.get(k).copied().unwrap_or(4242424242)));
                }
                l
            }
            b"conf" => {
                let v = nfsidmap::nfsidmap_config_get(&argv[i], &argv[i + 1]);
                let l = format!(
                    "conf {} {} = '{}'",
                    s(&argv[i]),
                    s(&argv[i + 1]),
                    v.map_or("(null)".to_string(), |v| s(&v))
                );
                i += 2;
                l
            }
            b"path" => format!("path = '{}'", s(&nfsidmap::nfsidmap_conf_path())),
            _ => {
                sys::stderr(format!("unknown command {}\n", s(&cmd)).as_bytes());
                std::process::exit(2);
            }
        };
        let mut o = out.lock();
        let mut bytes: Vec<u8> = line.chars().map(|c| c as u32 as u8).collect();
        bytes.push(b'\n');
        o.write_all(&bytes).unwrap();
        o.flush().unwrap();
    }
}
