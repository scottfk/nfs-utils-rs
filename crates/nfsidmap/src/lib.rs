//! libnfsidmap from nfs-utils 2.8.5 (`support/nfsidmap`): NFSv4 name and id mapping.
//!
//! `libnfsidmap.c` is [`core`] and this module (the entry points); its methods,
//! dynamically loaded plugins in C, are built in: `nsswitch` ([`nss`]), `static`
//! ([`staticmap`]) and `regex` ([`regex`]). Other method names (`umich_ldap`, `gums`, or
//! a plugin of one's own) aren't available, as when C can't load the plugin.
//!
//! The state is the C library's: process-wide, behind one lock, set up on the first
//! call (or by [`nfs4_init_name_mapping`]). As in C, each method keeps its own copy of
//! the configuration (read when it is loaded) and of `nfsidmap_common.c`'s caches.
//!
//! The calls keep C's shape: an `i32` result (0 or a negative errno, with C's
//! exceptions) and out-parameters that are left alone when nothing was found.

use std::sync::Mutex;

pub mod common;
pub mod core;
pub mod nss;
pub mod regex;
pub mod staticmap;

use crate::core::Lib;
pub use crate::core::{LogFn, NFS4_MAX_DOMAIN_LEN};

static LIB: Mutex<Option<Lib>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Lib) -> T) -> T {
    let mut g = LIB.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Lib::default))
}

/// `nfs4_init_name_mapping(conffile)`: 0, or `-ENOENT` (`-ENOMEM` in C only when
/// memory runs out).
pub fn nfs4_init_name_mapping(conffile: Option<&[u8]>) -> i32 {
    with(|l| l.init(conffile))
}

/// `nfs4_term_name_mapping()`.
pub fn nfs4_term_name_mapping() {
    with(|l| l.term())
}

/// `nfs4_get_default_domain(server, domain, len)`: the domain into `domain`, or
/// `-ERANGE` when it needs more than `len` bytes with its NUL.
pub fn nfs4_get_default_domain(_server: Option<&[u8]>, domain: &mut Vec<u8>, len: usize) -> i32 {
    with(|l| match l.core.nfs4_get_default_domain(len) {
        Ok(d) => {
            *domain = d;
            0
        }
        Err(e) => e,
    })
}

/// `nfs4_uid_to_name(uid, domain, name, len)`.
pub fn nfs4_uid_to_name(uid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
    with(|l| l.uid_to_name(uid, domain, name, len))
}

/// `nfs4_gid_to_name(gid, domain, name, len)`.
pub fn nfs4_gid_to_name(gid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
    with(|l| l.gid_to_name(gid, domain, name, len))
}

/// `nfs4_uid_to_owner()`: the name, else the number; always 0.
pub fn nfs4_uid_to_owner(uid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
    with(|l| {
        if l.uid_to_name(uid, domain, name, len) != 0 {
            *name = uid.to_string().into_bytes();
        }
        0
    })
}

/// `nfs4_gid_to_group_owner()`: the name, else the number; always 0.
pub fn nfs4_gid_to_group_owner(gid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
    with(|l| {
        if l.gid_to_name(gid, domain, name, len) != 0 {
            *name = gid.to_string().into_bytes();
        }
        0
    })
}

/// `nfs4_name_to_uid(name, uid)`.
pub fn nfs4_name_to_uid(name: &[u8], uid: &mut u32) -> i32 {
    with(|l| l.name_to_uid(name, uid))
}

/// `nfs4_name_to_gid(name, gid)`.
pub fn nfs4_name_to_gid(name: &[u8], gid: &mut u32) -> i32 {
    with(|l| l.name_to_gid(name, gid))
}

/// `nfs4_owner_to_uid()`: the mapping, else the name as a number, else nobody.
pub fn nfs4_owner_to_uid(name: &[u8], uid: &mut u32) -> i32 {
    with(|l| l.owner_to_uid(name, uid))
}

/// `nfs4_group_owner_to_gid()`.
pub fn nfs4_group_owner_to_gid(name: &[u8], gid: &mut u32) -> i32 {
    with(|l| l.group_owner_to_gid(name, gid))
}

/// `nfs4_gss_princ_to_ids(secname, princ, uid, gid)`.
pub fn nfs4_gss_princ_to_ids(secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
    with(|l| l.princ_to_ids(b"nfs4_gss_princ_to_ids", secname, princ, uid, gid))
}

/// `nfs4_gss_princ_to_ids_ex()`: no built-in method uses the extra parameters.
pub fn nfs4_gss_princ_to_ids_ex(secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
    with(|l| l.princ_to_ids(b"nfs4_gss_princ_to_ids_ex", secname, princ, uid, gid))
}

/// `nfs4_gss_princ_to_grouplist(secname, princ, groups, ngroups)`: `groups` gets what
/// fits in `*ngroups`, and `*ngroups` the count `getgrouplist()` reports.
pub fn nfs4_gss_princ_to_grouplist(secname: &[u8], princ: &[u8], groups: &mut Vec<u32>, ngroups: &mut i32) -> i32 {
    with(|l| l.princ_to_grouplist(b"nfs4_gss_princ_to_grouplist", secname, princ, groups, ngroups))
}

/// `nfs4_gss_princ_to_grouplist_ex()`.
pub fn nfs4_gss_princ_to_grouplist_ex(secname: &[u8], princ: &[u8], groups: &mut Vec<u32>, ngroups: &mut i32) -> i32 {
    with(|l| l.princ_to_grouplist(b"nfs4_gss_princ_to_grouplist_ex", secname, princ, groups, ngroups))
}

/// `nfs4_set_debug(level, logger)`: the verbosity, and the function messages go to
/// (`None` keeps the current one; the default is syslog at `LOG_WARNING`). The logger
/// runs with the library locked, so it must not call back into it.
pub fn nfs4_set_debug(level: i32, logger: Option<LogFn>) {
    with(|l| {
        if let Some(f) = logger {
            l.core.log_func = f;
        }
        l.core.verbosity = level;
        let m = support::bfmt!("Setting log level to {}\n", level);
        l.core.log(0, &m);
    })
}

/// `nfsidmap_config_get(section, tag)`: from the library's copy of the configuration.
pub fn nfsidmap_config_get(section: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    with(|l| l.core.conf.get_section(section, None, tag))
}

/// `nfsidmap_conf_path`.
pub fn nfsidmap_conf_path() -> Vec<u8> {
    with(|l| l.core.conf_path.clone())
}

/// `idmap_verbosity`.
pub fn idmap_verbosity() -> i32 {
    with(|l| l.core.verbosity)
}
