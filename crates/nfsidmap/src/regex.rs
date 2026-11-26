//! `regex.c`, the `regex` method: names matched against `[Regex]` expressions (glibc's
//! POSIX extended ones, ignoring case), the first subexpression that matched being the
//! local name; names going out get prefixes and suffixes.
//!
//! The settings come from the library's copy of the configuration
//! (`nfsidmap_config_get()`); this method has none of its own.

use support::bfmt;
use support::sys;

use crate::core::{Core, NFS4_MAX_DOMAIN_LEN};

const MAX_MATCHES: usize = 100;

/// The method's state, C's globals: `None` for an expression that was never compiled
/// or was freed, and for a string never set. C uses them anyway (and crashes): see
/// [`RegexMethod::init`].
#[derive(Debug, Default)]
pub struct RegexMethod {
    user_re: Option<sys::Regex>,
    group_re: Option<sys::Regex>,
    gpx_re: Option<sys::Regex>,
    use_gpx: bool,
    group_prefix: Option<Vec<u8>>,
    group_name_prefix: Option<Vec<u8>>,
    group_suffix: Option<Vec<u8>>,
    user_prefix: Option<Vec<u8>>,
    user_suffix: Option<Vec<u8>>,
    group_name_prefix_length: usize,
    default_domain: Vec<u8>,
}

/// What C does with a regex_t that holds nothing, or `strlen(NULL)`.
fn crash() -> ! {
    sys::segfault()
}

fn first_match(name: &[u8], m: &[(i64, i64)]) -> Option<Vec<u8>> {
    let (so, eo) = *m.iter().skip(1).find(|(so, _)| *so >= 0)?;
    Some(name[so as usize..eo as usize].to_vec())
}

impl RegexMethod {
    pub fn new() -> RegexMethod {
        RegexMethod::default()
    }

    /// `regex_init()`.
    ///
    /// QUIRK: it always succeeds. A missing or bad `User-Regex` or `Group-Regex`
    /// leaves the expressions empty (and the prefixes and suffixes unset), and a bad
    /// `Group-Name-No-Prefix-Regex` frees both expressions: the method stays loaded and
    /// the first call that uses one crashes, as in C (glibc's `regexec()` dereferences
    /// the empty expression; `strlen()` of an unset string).
    pub fn init(&mut self, core: &mut Core) -> i32 {
        let get = |tag: &[u8]| core.conf.get_section(b"Regex", None, tag);
        let flags = libc::REG_EXTENDED | libc::REG_ICASE;
        let Some(s) = get(b"User-Regex") else {
            sys::warnx_msg(b"regex_init: regex for user mapping missing");
            return 0;
        };
        match sys::regcomp(&s, flags) {
            Ok(r) => self.user_re = Some(r),
            Err(st) => {
                sys::warnx_msg(&bfmt!("regex_init: compiling regex for user mapping failed with status {}", st as u32));
                return 0;
            }
        }
        let Some(s) = get(b"Group-Regex") else {
            sys::warnx_msg(b"regex_init: regex for group mapping missing");
            self.user_re = None;
            return 0;
        };
        match sys::regcomp(&s, flags) {
            Ok(r) => self.group_re = Some(r),
            Err(st) => {
                sys::warnx_msg(&bfmt!(
                    "regex_init: compiling regex for group mapping failed with status {}",
                    st as u32
                ));
                self.user_re = None;
                return 0;
            }
        }
        let gnp = get(b"Group-Name-Prefix").unwrap_or_default();
        self.group_name_prefix_length = gnp.len();
        self.group_name_prefix = Some(gnp);
        self.user_prefix = Some(get(b"Prepend-Before-User").unwrap_or_default());
        self.user_suffix = Some(get(b"Append-After-User").unwrap_or_default());
        self.group_prefix = Some(get(b"Prepend-Before-Group").unwrap_or_default());
        self.group_suffix = Some(get(b"Append-After-Group").unwrap_or_default());
        self.use_gpx = false;
        if let Some(s) = get(b"Group-Name-No-Prefix-Regex") {
            match sys::regcomp(&s, flags) {
                Ok(r) => {
                    self.gpx_re = Some(r);
                    self.use_gpx = true;
                }
                Err(st) => {
                    sys::warnx_msg(&bfmt!(
                        "regex_init: compiling regex for group prefix exclusion failed with status {}",
                        st as u32
                    ));
                    self.group_re = None;
                    self.user_re = None;
                    return 0;
                }
            }
        }
        0
    }

    /// The method's `get_default_domain()`.
    fn get_default_domain(&mut self, core: &mut Core) -> Vec<u8> {
        if self.default_domain.is_empty()
            && let Ok(d) = core.nfs4_get_default_domain(NFS4_MAX_DOMAIN_LEN)
        {
            self.default_domain = d;
        }
        self.default_domain.clone()
    }

    /// `regex_getpwnam()`: the error is positive.
    fn getpwnam(&self, core: &Core, name: &[u8]) -> Result<sys::Passwd, i32> {
        let Some(re) = &self.user_re else { crash() };
        let (status, m) = re.exec(name, MAX_MATCHES);
        let localname = if status != 0 { None } else { first_match(name, &m) };
        let Some(localname) = localname else {
            if core.logs(4) {
                core.log(4, &bfmt!("regexp_getpwnam: user '{}' did not match regex", name));
            }
            return Err(libc::ENOENT);
        };
        let l = loop {
            let l = sys::getpwnam_r(&localname, sys::getpw_r_size_max());
            if l.ret != libc::EINTR {
                break l;
            }
        };
        let Some(pw) = l.entry else {
            if core.logs(4) {
                core.log(4, &bfmt!("regex_getpwnam: local user '{}' for '{}' not found", localname, name));
            }
            return Err(if l.ret == 0 { libc::ENOENT } else { l.ret });
        };
        if core.logs(4) {
            core.log(4, &bfmt!("regexp_getpwnam: name '{}' mapped to '{}'", name, localname));
        }
        Ok(pw)
    }

    /// `regex_getgrnam()`.
    fn getgrnam(&self, core: &Core, name: &[u8]) -> Result<sys::Group, i32> {
        let Some(re) = &self.group_re else { crash() };
        let (status, m) = re.exec(name, MAX_MATCHES);
        let localgroup = if status != 0 { None } else { first_match(name, &m) };
        let Some(localgroup) = localgroup else {
            if core.logs(4) {
                core.log(4, &bfmt!("regexp_getgrnam: group '{}' did not match regex", name));
            }
            return Err(libc::ENOENT);
        };
        if core.logs(4) {
            core.log(4, &bfmt!("regexp_getgrnam: group '{}' after match of regex", localgroup));
        }
        let mut groupname: &[u8] = &localgroup;
        let n = self.group_name_prefix_length;
        // With a compiled group expression, init() got as far as setting the prefix.
        let gnp = self.group_name_prefix.as_deref().unwrap_or(b"");
        if n != 0 && localgroup.len() >= n && &localgroup[..n] == gnp {
            let mut err = 1;
            if self.use_gpx
                && let Some(g) = &self.gpx_re
            {
                err = g.exec(&localgroup, 0).0;
            }
            if err != 0 {
                if core.logs(4) {
                    core.log(
                        4,
                        &bfmt!(
                            "regexp_getgrnam: removing prefix '{}' ({} long) from group '{}'",
                            gnp,
                            n as i32,
                            localgroup
                        ),
                    );
                }
                groupname = &localgroup[n..];
            } else if core.logs(4) {
                core.log(4, &bfmt!("regexp_getgrnam: not removing prefix from group '{}'", localgroup));
            }
        }
        if core.logs(4) {
            core.log(4, &bfmt!("regexp_getgrnam: will use '{}'", groupname));
        }
        let l = loop {
            let l = sys::getgrnam_r(groupname, sys::getgr_r_size_max());
            if l.ret != libc::EINTR {
                break l;
            }
        };
        let Some(gr) = l.entry else {
            if core.logs(4) {
                core.log(4, &bfmt!("regex_getgrnam: local group '{}' for '{}' not found", groupname, name));
            }
            return Err(if l.ret == 0 { libc::ENOENT } else { l.ret });
        };
        if core.logs(4) {
            core.log(4, &bfmt!("regex_getgrnam: group '{}' mapped to '{}'", name, groupname));
        }
        Ok(gr)
    }

    fn secname_ok(secname: &[u8]) -> bool {
        secname == b"krb5" || secname == b"spkm3"
    }

    pub fn princ_to_ids(&mut self, core: &mut Core, secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
        if !Self::secname_ok(secname) {
            return -libc::EINVAL;
        }
        match self.getpwnam(core, princ) {
            Ok(pw) => {
                *uid = pw.uid;
                *gid = pw.gid;
                0
            }
            Err(e) => -e,
        }
    }

    /// QUIRK: a list that doesn't fit gives +ERANGE, as in `static`.
    pub fn princ_to_grouplist(
        &mut self,
        core: &mut Core,
        secname: &[u8],
        princ: &[u8],
        groups: &mut Vec<u32>,
        ngroups: &mut i32,
    ) -> i32 {
        if !Self::secname_ok(secname) {
            return -libc::EINVAL;
        }
        match self.getpwnam(core, princ) {
            Ok(pw) => {
                let (r, g, n) = sys::getgrouplist(&pw.name, pw.gid, *ngroups);
                *groups = g;
                *ngroups = n;
                if r < 0 { libc::ERANGE } else { 0 }
            }
            Err(e) => -e,
        }
    }

    pub fn name_to_uid(&mut self, core: &mut Core, name: &[u8], uid: &mut u32) -> i32 {
        match self.getpwnam(core, name) {
            Ok(pw) => {
                *uid = pw.uid;
                0
            }
            Err(e) => -e,
        }
    }

    pub fn name_to_gid(&mut self, core: &mut Core, name: &[u8], gid: &mut u32) -> i32 {
        match self.getgrnam(core, name) {
            Ok(gr) => {
                *gid = gr.gid;
                0
            }
            Err(e) => -e,
        }
    }

    /// `write_name()`: `prefix name_prefix localname suffix`, or `-ENOMEM`.
    fn write_name(
        core: &Core,
        dest: &mut Vec<u8>,
        localname: &[u8],
        name_prefix: Option<&[u8]>,
        prefix: Option<&[u8]>,
        suffix: Option<&[u8]>,
        len: usize,
    ) -> i32 {
        let (Some(np), Some(p), Some(s)) = (name_prefix, prefix, suffix) else { crash() };
        if localname.len() + np.len() + p.len() + s.len() + 1 > len {
            return -libc::ENOMEM;
        }
        let mut v = p.to_vec();
        v.extend_from_slice(np);
        v.extend_from_slice(localname);
        v.extend_from_slice(s);
        if core.logs(4) {
            core.log(4, &bfmt!("write_name: will use '{}'", v));
        }
        *dest = v;
        0
    }

    pub fn uid_to_name(
        &mut self,
        core: &mut Core,
        uid: u32,
        domain: Option<&[u8]>,
        name: &mut Vec<u8>,
        len: usize,
    ) -> i32 {
        if domain.is_none() {
            // Unused, but looked up.
            self.get_default_domain(core);
        }
        let l = sys::getpwuid_r(uid, sys::getpw_r_size_max());
        let Some(pw) = l.entry else {
            return -libc::ENOENT;
        };
        Self::write_name(core, name, &pw.name, Some(b""), self.user_prefix.as_deref(), self.user_suffix.as_deref(), len)
    }

    pub fn gid_to_name(&mut self, core: &mut Core, gid: u32, name: &mut Vec<u8>, len: usize) -> i32 {
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
        let groupname = gr.name;
        let mut name_prefix = self.group_name_prefix.as_deref();
        let n = self.group_name_prefix_length;
        if n != 0 {
            let gnp = self.group_name_prefix.as_deref().unwrap_or(b"");
            if groupname.len() >= n && &groupname[..n] == gnp {
                name_prefix = Some(b"");
            } else if self.use_gpx
                && let Some(g) = &self.gpx_re
                && g.exec(&groupname, 0).0 == 0
            {
                if core.logs(4) {
                    core.log(4, &bfmt!("regex_gid_to_name: not adding prefix to group '{}'", groupname));
                }
                name_prefix = Some(b"");
            }
        }
        Self::write_name(
            core,
            name,
            &groupname,
            name_prefix,
            self.group_prefix.as_deref(),
            self.group_suffix.as_deref(),
            len,
        )
    }
}
