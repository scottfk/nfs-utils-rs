//! `nss.c`, the `nsswitch` method: `getpwnam()` and friends, with the domain added to
//! names going out and checked (and stripped) on names coming in.

use support::bfmt;
use support::conffile::Conf;
use support::sys;
use support::xlog;

use crate::common::{Common, IDTYPE_GROUP, IDTYPE_USER};
use crate::core::{Core, NFS4_MAX_DOMAIN_LEN, ns};

/// The method's state: its own configuration and `nfsidmap_common.c` copy, and the
/// default domain it caches.
#[derive(Debug)]
pub struct Nss {
    conf: Conf,
    common: Common,
    default_domain: Vec<u8>,
}

/// `write_name()`: `localname@domain`, or (when not appending and the name has an
/// `@`) the name alone; `-ENOMEM` when it needs more than `len` bytes.
fn write_name(dest: &mut Vec<u8>, localname: &[u8], domain: &[u8], len: usize, doappend: bool) -> i32 {
    if doappend || !localname.contains(&b'@') {
        if localname.len() + 1 + domain.len() + 1 > len {
            return -libc::ENOMEM;
        }
        let mut v = localname.to_vec();
        v.push(b'@');
        v.extend_from_slice(domain);
        *dest = v;
    } else {
        if localname.len() + 1 > len {
            return -libc::ENOMEM;
        }
        *dest = localname.to_vec();
    }
    0
}

/// `strip_domain()`: the name before its last `@` when what follows is `domain`
/// (ignoring case); with no domain, the name before any last `@`, or all of it.
fn strip_domain(name: &[u8], domain: Option<&[u8]>) -> Option<Vec<u8>> {
    let c = name.iter().rposition(|&b| b == b'@');
    match (c, domain) {
        (None, Some(_)) => None,
        (None, None) => Some(name.to_vec()),
        (Some(at), d) => {
            if let Some(d) = d
                && !sys::strcaseeq(&name[at + 1..], d)
            {
                return None;
            }
            Some(name[..at].to_vec())
        }
    }
}

/// `reformat_name()`: `user@dom.ain` as `DOM\user`.
fn reformat_name(name: &[u8]) -> Option<Vec<u8>> {
    let c = name.iter().position(|&b| b == b'@')?;
    let domain = &name[c + 1..];
    let d = domain.iter().position(|&b| b == b'.')?;
    let mut l: Vec<u8> = domain[..d].iter().map(|&b| sys::toupper(b)).collect();
    l.push(b'\\');
    l.extend_from_slice(&name[..c]);
    Some(l)
}

impl Nss {
    pub fn new() -> Nss {
        Nss { conf: Conf::default(), common: Common::default(), default_domain: Vec::new() }
    }

    /// `nss_plugin_init()`: read the configuration into the method's own copy.
    pub fn init(&mut self, core: &mut Core) -> i32 {
        let path = core.conf_path.clone();
        self.conf = xlog::in_library_copy(|| Conf::init_file(Some(&path)));
        0
    }

    /// The method's `get_default_domain()`: cached once it isn't empty.
    fn get_default_domain(&mut self, core: &mut Core) -> Vec<u8> {
        if self.default_domain.is_empty()
            && let Ok(d) = core.nfs4_get_default_domain(NFS4_MAX_DOMAIN_LEN)
        {
            self.default_domain = d;
        }
        self.default_domain.clone()
    }

    fn nostrip(&mut self) -> i32 {
        self.common.get_nostrip(&self.conf)
    }

    pub fn uid_to_name(
        &mut self,
        core: &mut Core,
        uid: u32,
        domain: Option<&[u8]>,
        name: &mut Vec<u8>,
        len: usize,
    ) -> i32 {
        let domain = match domain {
            Some(d) => d.to_vec(),
            None => self.get_default_domain(core),
        };
        let l = sys::getpwuid_r(uid, sys::getpw_r_size_max());
        // A full buffer (ERANGE) is "not found" too.
        let Some(pw) = l.entry else {
            return -libc::ENOENT;
        };
        if l.ret != 0 {
            return -l.ret;
        }
        let append = self.nostrip() & IDTYPE_USER == 0;
        write_name(name, &pw.name, &domain, len, append)
    }

    pub fn gid_to_name(
        &mut self,
        core: &mut Core,
        gid: u32,
        domain: Option<&[u8]>,
        name: &mut Vec<u8>,
        len: usize,
    ) -> i32 {
        let domain = match domain {
            Some(d) => d.to_vec(),
            None => self.get_default_domain(core),
        };
        let mut buflen = sys::getgr_r_size_max();
        let gr = loop {
            let l = sys::getgrgid_r(gid, buflen);
            let mut err = -l.ret;
            if l.entry.is_none() && err == 0 {
                err = -libc::ENOENT;
            }
            if err == -libc::ERANGE {
                buflen *= 2;
                continue;
            }
            if err != 0 {
                return err;
            }
            break l.entry.unwrap();
        };
        let append = self.nostrip() & IDTYPE_GROUP == 0;
        write_name(name, &gr.name, &domain, len, append)
    }

    /// `nss_getpwnam()`: the entry, or a negative errno.
    fn getpwnam(&self, core: &Core, name: &[u8], domain: Option<&[u8]>, dostrip: bool) -> Result<sys::Passwd, i32> {
        let buflen = sys::getpw_r_size_max();
        let l = if dostrip {
            let localname = strip_domain(name, domain);
            if core.logs(4) {
                core.log(
                    4,
                    &bfmt!(
                        "nss_getpwnam: name '{}' domain '{}': resulting localname '{}'",
                        name,
                        ns(domain),
                        ns(localname.as_deref())
                    ),
                );
            }
            let Some(localname) = localname else {
                core.log(
                    0,
                    &bfmt!(
                        "nss_getpwnam: name '{}' does not map into domain '{}'",
                        name,
                        domain.unwrap_or(b"<not-provided>")
                    ),
                );
                return Err(-libc::EINVAL);
            };
            let l = sys::getpwnam_r(&localname, buflen);
            if l.entry.is_none()
                && let Some(d) = domain
            {
                core.log(1, &bfmt!("nss_getpwnam: name '{}' not found in domain '{}'", localname, d));
            }
            l
        } else {
            let l = sys::getpwnam_r(name, buflen);
            if l.entry.is_none() {
                core.log(1, &bfmt!("nss_getpwnam: name '{}' not found (domain not stripped)", name));
            }
            l
        };
        match (l.ret, l.entry) {
            (0, Some(pw)) => Ok(pw),
            (0, None) => Err(-libc::ENOENT),
            (e, _) => Err(-e),
        }
    }

    pub fn name_to_uid(&mut self, core: &mut Core, name: &[u8], uid: &mut u32) -> i32 {
        let domain = self.get_default_domain(core);
        let mut found = None;
        if self.nostrip() & IDTYPE_USER != 0
            && let Ok(pw) = self.getpwnam(core, name, Some(&domain), false)
        {
            found = Some(pw);
        }
        let pw = match found {
            Some(pw) => pw,
            None => match self.getpwnam(core, name, Some(&domain), true) {
                Ok(pw) => pw,
                Err(e) => return e,
            },
        };
        *uid = pw.uid;
        if core.logs(4) {
            core.log(4, &bfmt!("nss_name_to_uid: name '{}' uid {}", name, *uid));
        }
        0
    }

    /// `_nss_name_to_gid()`.
    fn name_to_gid_1(&mut self, core: &mut Core, name: &[u8], gid: &mut u32, dostrip: bool) -> i32 {
        let domain = self.get_default_domain(core);
        let mut localname = None;
        let mut ref_name = None;
        if dostrip {
            localname = strip_domain(name, Some(&domain));
            if core.logs(4) {
                core.log(
                    4,
                    &bfmt!(
                        "nss_name_to_gid: name '{}' domain '{}': resulting localname '{}'",
                        name,
                        domain,
                        ns(localname.as_deref())
                    ),
                );
            }
            if localname.is_none() {
                core.log(0, &bfmt!("nss_name_to_gid: name '{}' does not map into domain '{}'", name, domain));
                return -libc::EINVAL;
            }
        } else if self.common.get_reformat_group() {
            ref_name = reformat_name(name);
            if ref_name.is_none() {
                core.log(1, &bfmt!("nss_name_to_gid: failed to reformat name '{}'", name));
                return -libc::ENOENT;
            }
        }
        let mut buflen = sys::getgr_r_size_max();
        loop {
            let reformat = self.common.get_reformat_group();
            let lookup: &[u8] = if dostrip {
                localname.as_deref().unwrap()
            } else if reformat {
                // C passes NULL when reformatting was turned on after the name was
                // (not) reformatted; it can't be: both read the same cache.
                ref_name.as_deref().unwrap_or(b"")
            } else {
                name
            };
            let l = sys::getgrnam_r(lookup, buflen);
            let mut err = -l.ret;
            if l.entry.is_none() && err == 0 {
                if dostrip {
                    core.log(1, &bfmt!("nss_name_to_gid: name '{}' not found in domain '{}'", lookup, domain));
                } else if reformat {
                    core.log(1, &bfmt!("nss_name_to_gid: name '{}' not found (reformatted)", lookup));
                } else {
                    core.log(1, &bfmt!("nss_name_to_gid: name '{}' not found (domain not stripped)", name));
                }
                err = -libc::ENOENT;
            }
            if err == -libc::ERANGE {
                buflen *= 2;
                continue;
            }
            if err != 0 {
                return err;
            }
            *gid = l.entry.unwrap().gid;
            if core.logs(4) {
                core.log(4, &bfmt!("nss_name_to_gid: name '{}' gid {}", name, *gid));
            }
            return 0;
        }
    }

    pub fn name_to_gid(&mut self, core: &mut Core, name: &[u8], gid: &mut u32) -> i32 {
        if self.nostrip() & IDTYPE_GROUP != 0 && self.name_to_gid_1(core, name, gid, false) == 0 {
            return 0;
        }
        self.name_to_gid_1(core, name, gid, true)
    }

    pub fn princ_to_ids(&mut self, core: &mut Core, secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
        if secname == b"spkm3" {
            return -libc::ENOENT;
        }
        if secname != b"krb5" {
            return -libc::EINVAL;
        }
        let Some(at) = princ.iter().position(|&b| b == b'@') else {
            return -libc::EINVAL;
        };
        let princ_realm = &princ[at + 1..];
        let conf = std::mem::take(&mut self.conf);
        let found = self
            .common
            .get_local_realms(&conf, || core.nfs4_get_default_domain(NFS4_MAX_DOMAIN_LEN).unwrap_or_default())
            .iter()
            .any(|r| r == princ_realm);
        self.conf = conf;
        if !found {
            core.log(1, &bfmt!("nss_gss_princ_to_ids: Local-Realm '{}': NOT FOUND", princ_realm));
            return -libc::ENOENT;
        }
        match self.getpwnam(core, princ, None, true) {
            Ok(pw) => {
                *uid = pw.uid;
                *gid = pw.gid;
                0
            }
            Err(_) => -libc::ENOENT,
        }
    }

    pub fn princ_to_grouplist(
        &mut self,
        core: &mut Core,
        secname: &[u8],
        princ: &[u8],
        groups: &mut Vec<u32>,
        ngroups: &mut i32,
    ) -> i32 {
        if secname != b"krb5" {
            return -libc::EINVAL;
        }
        let pw = match self.getpwnam(core, princ, None, true) {
            Ok(pw) => pw,
            Err(_) => return -libc::ENOENT,
        };
        let (r, g, n) = sys::getgrouplist(&pw.name, pw.gid, *ngroups);
        *groups = g;
        *ngroups = n;
        if r < 0 { -libc::ERANGE } else { 0 }
    }
}

impl Default for Nss {
    fn default() -> Self {
        Nss::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_domain_like_c() {
        let d = Some(&b"example.org"[..]);
        assert_eq!(strip_domain(b"alice@EXAMPLE.org", d).as_deref(), Some(&b"alice"[..]));
        assert_eq!(strip_domain(b"a@b@example.org", d).as_deref(), Some(&b"a@b"[..]));
        assert_eq!(strip_domain(b"alice@other.org", d), None);
        assert_eq!(strip_domain(b"alice", d), None);
        assert_eq!(strip_domain(b"alice", None).as_deref(), Some(&b"alice"[..]));
        assert_eq!(strip_domain(b"alice@any", None).as_deref(), Some(&b"alice"[..]));
    }

    #[test]
    fn reformat_name_like_c() {
        assert_eq!(reformat_name(b"ops@ad.example.com").as_deref(), Some(&b"AD\\ops"[..]));
        assert_eq!(reformat_name(b"ops@ad"), None);
        assert_eq!(reformat_name(b"ops"), None);
        assert_eq!(reformat_name(b"a@b@c.d").as_deref(), Some(&b"B@C\\a"[..]));
    }

    #[test]
    fn write_name_lengths() {
        let mut v = Vec::new();
        assert_eq!(write_name(&mut v, b"alice", b"example.org", 18, true), 0);
        assert_eq!(v, b"alice@example.org");
        assert_eq!(write_name(&mut v, b"bob", b"example.org", 15, true), -libc::ENOMEM);
        assert_eq!(v, b"alice@example.org");
        assert_eq!(write_name(&mut v, b"c@ad", b"example.org", 5, false), 0);
        assert_eq!(v, b"c@ad");
    }
}
