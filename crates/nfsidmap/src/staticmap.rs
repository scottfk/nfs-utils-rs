//! `static.c`, the `static` method: names mapped to local users and groups by the
//! `[Static]` section (`principal = localname`).

use support::bfmt;
use support::conffile::Conf;
use support::sys;
use support::xlog;

use crate::core::Core;

/// The method's state: its configuration and the ids of every mapping, found when it
/// was loaded.
#[derive(Debug, Default)]
pub struct Static {
    conf: Conf,
    /// (uid, principal) in the order C inserts them at the heads of its hash lists, so
    /// a lookup takes the last match.
    uids: Vec<(u32, Vec<u8>)>,
    gids: Vec<(u32, Vec<u8>)>,
}

/// `-err` for a lookup that failed with `err` (a positive errno).
fn neg(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

impl Static {
    pub fn new() -> Static {
        Static::default()
    }

    /// `static_getpwnam()`: the user `[Static] name` names; the error is positive.
    fn getpwnam(&self, core: &Core, name: &[u8]) -> Result<sys::Passwd, i32> {
        let Some(localname) = self.conf.get_str(b"Static", name) else {
            return Err(libc::ENOENT);
        };
        let l = loop {
            let l = sys::getpwnam_r(&localname, sys::getpw_r_size_max());
            if l.ret != libc::EINTR {
                break l;
            }
        };
        let Some(pw) = l.entry else {
            let err = if l.ret == 0 { libc::ENOENT } else { l.ret };
            core.log(0, &bfmt!("static_getpwnam: localname '{}' for '{}' not found", localname, name));
            return Err(err);
        };
        if core.logs(4) {
            core.log(4, &bfmt!("static_getpwnam: name '{}' mapped to '{}'", name, localname));
        }
        Ok(pw)
    }

    /// `static_getgrnam()`.
    fn getgrnam(&self, core: &Core, name: &[u8]) -> Result<sys::Group, i32> {
        let Some(localgroup) = self.conf.get_str(b"Static", name) else {
            return Err(libc::ENOENT);
        };
        let l = loop {
            let l = sys::getgrnam_r(&localgroup, sys::getgr_r_size_max());
            if l.ret != libc::EINTR {
                break l;
            }
        };
        let Some(gr) = l.entry else {
            let err = if l.ret == 0 { libc::ENOENT } else { l.ret };
            core.log(0, &bfmt!("static_getgrnam: local group '{}' for '{}' not found", localgroup, name));
            return Err(err);
        };
        if core.logs(4) {
            core.log(4, &bfmt!("static_getgrnam: group '{}' mapped to '{}'", name, localgroup));
        }
        Ok(gr)
    }

    /// `static_init()`: read the configuration, and look up every mapping both as a
    /// user and as a group (C can't tell which it is), logging those that aren't.
    pub fn init(&mut self, core: &mut Core) -> i32 {
        let path = core.conf_path.clone();
        self.conf = xlog::in_library_copy(|| Conf::init_file(Some(&path)));
        // C returns -ENOENT when there is no list; conf_get_tag_list() always gives
        // one (maybe empty).
        let princ_list = self.conf.get_tag_list(b"Static", None);
        // Loaded again (by a second list naming it), C empties its uid lists but not
        // its gid lists; the duplicates it adds find the same principals.
        self.uids.clear();
        for p in &princ_list {
            if let Ok(pw) = self.getpwnam(core, p) {
                self.uids.push((pw.uid, p.clone()));
            }
        }
        for p in &princ_list {
            if let Ok(gr) = self.getgrnam(core, p) {
                self.gids.push((gr.gid, p.clone()));
            }
        }
        0
    }

    fn secname_ok(secname: &[u8]) -> bool {
        secname == b"krb5" || secname == b"spkm3"
    }

    pub fn princ_to_ids(&mut self, core: &mut Core, secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
        if !Self::secname_ok(secname) {
            return -libc::EINVAL;
        }
        neg(self.getpwnam(core, princ).map(|pw| {
            *uid = pw.uid;
            *gid = pw.gid;
        }))
    }

    /// QUIRK: a list that doesn't fit gives +ERANGE (C negates -ERANGE on return).
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
        neg(self.getpwnam(core, name).map(|pw| *uid = pw.uid))
    }

    pub fn name_to_gid(&mut self, core: &mut Core, name: &[u8], gid: &mut u32) -> i32 {
        neg(self.getgrnam(core, name).map(|gr| *gid = gr.gid))
    }

    /// QUIRK: C copies the principal without checking `len` (`strcpy()`), overrunning
    /// a caller's buffer; this returns the whole principal.
    pub fn uid_to_name(&mut self, uid: u32, name: &mut Vec<u8>) -> i32 {
        match self.uids.iter().rev().find(|(u, _)| *u == uid) {
            Some((_, p)) => {
                *name = p.clone();
                0
            }
            None => -libc::ENOENT,
        }
    }

    pub fn gid_to_name(&mut self, gid: u32, name: &mut Vec<u8>) -> i32 {
        match self.gids.iter().rev().find(|(g, _)| *g == gid) {
            Some((_, p)) => {
                *name = p.clone();
                0
            }
            None => -libc::ENOENT,
        }
    }
}
