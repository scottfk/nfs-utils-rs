//! `support/misc/file.c`: the state-directory helpers.

use crate::conffile::dirname;
use crate::sys;
use crate::xlog::{D_CALL, xlog};

pub const PATH_MAX: usize = 4096;

/// `generic_make_pathname()`: `base/leaf`, or `None` if it would exceed `PATH_MAX`.
pub fn generic_make_pathname(base: &[u8], leaf: &[u8]) -> Option<Vec<u8>> {
    let size = base.len() + leaf.len() + 2;
    if size > PATH_MAX {
        return None;
    }
    Some(bfmt!("{}/{}", base, leaf))
}

/// `generic_setup_basedir()`: check `parentdir` and make it the base directory. Errors
/// go to stderr (logging isn't set up yet), without a newline, as in C.
pub fn generic_setup_basedir(progname: &[u8], parentdir: &[u8], base: &mut Vec<u8>, baselen: usize) -> bool {
    if parentdir.len() >= baselen || parentdir.len() >= PATH_MAX {
        sys::stderr(&bfmt!("{}: Directory name too long: {}", progname, parentdir));
        return false;
    }
    if sys::lstat(parentdir).is_none() {
        let e = sys::strerror(sys::errno());
        sys::stderr(&bfmt!("{}: Failed to stat {}: {}", progname, parentdir, e));
        return false;
    }
    // strncpy(buf, parentdir, sizeof(buf) - 1); path = dirname(buf).
    if dirname(parentdir).first() == Some(&b'.') {
        sys::stderr(&bfmt!("{}: Unusable directory {}", progname, parentdir));
        return false;
    }
    xlog(D_CALL, &bfmt!("Using {} as the state directory", parentdir));
    *base = parentdir.to_vec();
    true
}
