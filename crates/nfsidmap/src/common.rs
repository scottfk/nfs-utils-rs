//! `nfsidmap_common.c`: code the library and its methods each have their own copy of
//! (with their own copy of the configuration database behind it).

use support::conffile::Conf;
use support::sys;

pub const IDTYPE_USER: i32 = 1;
pub const IDTYPE_GROUP: i32 = 2;

/// One copy's state: the cached `Local-Realms` list and `No-Strip`/`Reformat-Group`.
#[derive(Debug)]
pub struct Common {
    pub local_realms: Option<Vec<Vec<u8>>>,
    no_strip: i32,
    reformat_group: bool,
}

impl Default for Common {
    fn default() -> Self {
        Common { local_realms: None, no_strip: -1, reformat_group: false }
    }
}

impl Common {
    /// `get_local_realms()`: `[General] Local-Realms`, else the default domain in upper
    /// case (`domain` gives it: `nfs4_get_default_domain()` into a 512-byte buffer,
    /// which stays empty when that fails).
    pub fn get_local_realms(&mut self, conf: &Conf, domain: impl FnOnce() -> Vec<u8>) -> &Vec<Vec<u8>> {
        if self.local_realms.is_none() {
            let list = conf.get_list(b"General", b"Local-Realms").unwrap_or_else(|| {
                let d: Vec<u8> = domain().iter().map(|&c| sys::toupper(c)).collect();
                vec![d]
            });
            self.local_realms = Some(list);
        }
        self.local_realms.as_ref().unwrap()
    }

    /// `free_local_realms()`.
    pub fn free_local_realms(&mut self) {
        self.local_realms = None;
    }

    /// `get_nostrip()`.
    pub fn get_nostrip(&mut self, conf: &Conf) -> i32 {
        if self.no_strip != -1 {
            return self.no_strip;
        }
        let nostrip = conf.get_str_with_def(b"General", b"No-Strip", b"none");
        self.no_strip = if sys::strcaseeq(&nostrip, b"both") {
            IDTYPE_USER | IDTYPE_GROUP
        } else if sys::strcaseeq(&nostrip, b"group") {
            IDTYPE_GROUP
        } else if sys::strcaseeq(&nostrip, b"user") {
            IDTYPE_USER
        } else {
            0
        };
        if self.no_strip & IDTYPE_GROUP != 0 {
            let r = conf.get_str_with_def(b"General", b"Reformat-Group", b"false");
            self.reformat_group =
                sys::strcaseeq(&r, b"true") || sys::strcaseeq(&r, b"on") || sys::strcaseeq(&r, b"yes");
        }
        self.no_strip
    }

    /// `get_reformat_group()`: what the last `get_nostrip()` that read it found.
    pub fn get_reformat_group(&self) -> bool {
        self.reformat_group
    }
}
