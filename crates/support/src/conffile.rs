//! `support/nfs/conffile.c`, the reading side: `/etc/nfs.conf` (and `/usr/etc/nfs.conf`,
//! the `.d` directories and `include`), and the `conf_get_*()` lookups.
//!
//! The database is kept as C keeps it: 256 hash buckets of bindings, newest first, and a
//! queue of transactions that `conf_end()` applies. That order decides which binding a
//! lookup finds and which one an override removes, so it is modeled, not simplified.

use std::sync::Mutex;

use crate::sys;
use crate::xlog::{self, D_GENERAL, L_WARNING, LOG_INFO_KIND, xlog, xlog_warn};

/// `NFS_CONFFILE`.
pub const NFS_CONFFILE: &[u8] = b"/etc/nfs.conf";
const CONF_FILE_EXT: &[u8] = b".conf";
const PATH_MAX: usize = 4096;

#[derive(Debug, Clone)]
struct Binding {
    section: Vec<u8>,
    arg: Option<Vec<u8>>,
    tag: Vec<u8>,
    value: Vec<u8>,
}

/// A queued `CONF_SET` (the parser queues nothing else).
#[derive(Debug, Clone)]
struct Trans {
    trans: i32,
    section: Vec<u8>,
    arg: Option<Vec<u8>>,
    tag: Vec<u8>,
    value: Vec<u8>,
    overrides: bool,
    is_default: bool,
}

/// The configuration database.
#[derive(Debug)]
pub struct Conf {
    buckets: Vec<Vec<Binding>>,
    queue: Vec<Trans>,
    seq: i32,
}

impl Default for Conf {
    fn default() -> Self {
        Conf { buckets: vec![Vec::new(); 256], queue: Vec::new(), seq: 0 }
    }
}

/// `conf_hash()`.
fn conf_hash(s: &[u8]) -> usize {
    let mut hash: u8 = 0;
    for &c in xlog::c_str(s) {
        hash = hash.rotate_left(1) ^ sys::tolower(c);
    }
    usize::from(hash)
}

/// The C string starting at `buf[at]`: up to the first NUL or the end.
fn cs(buf: &[u8], at: usize) -> &[u8] {
    if at >= buf.len() {
        return b"";
    }
    xlog::c_str(&buf[at..])
}

/// `strchr(buf + at, c)`: the index, if found before the NUL.
fn strchr(buf: &[u8], at: usize, c: u8) -> Option<usize> {
    cs(buf, at).iter().position(|&b| b == c).map(|p| at + p)
}

/// The byte at `i`, or NUL past the end.
fn at(buf: &[u8], i: usize) -> u8 {
    buf.get(i).copied().unwrap_or(0)
}

/// `dirname()` (glibc's `misc/dirname.c`) of a copy of `path`.
pub fn dirname(path: &[u8]) -> Vec<u8> {
    let p = xlog::c_str(path);
    let mut last = p.iter().rposition(|&b| b == b'/');
    if let Some(ls) = last
        && ls != 0
        && ls + 1 == p.len()
    {
        // A trailing slash: look before the run of slashes it ends.
        let mut runp = ls;
        while runp != 0 && p[runp - 1] == b'/' {
            runp -= 1;
        }
        if runp != 0 {
            last = p[..runp].iter().rposition(|&b| b == b'/');
        }
    }
    match last {
        None => b".".to_vec(),
        Some(ls) => {
            let mut runp = ls;
            while runp != 0 && p[runp - 1] == b'/' {
                runp -= 1;
            }
            let end = if runp == 0 {
                // "/" or, for exactly two leading slashes, "//".
                if ls == 1 { 2 } else { 1 }
            } else {
                runp
            };
            p[..end].to_vec()
        }
    }
}

/// `relative_path()`.
fn relative_path(oldfile: &[u8], newfile: &[u8]) -> Vec<u8> {
    if newfile.first() == Some(&b'/') {
        return newfile.to_vec();
    }
    let mut p = dirname(oldfile);
    p.push(b'/');
    p.extend_from_slice(newfile);
    p
}

/// `conf_readfile()`: the file's contents (cut at the first NUL, as C uses them), or
/// `None` after logging why.
fn conf_readfile(path: &[u8]) -> Option<Vec<u8>> {
    if sys::stat(path).is_none() && sys::errno() == libc::ENOENT {
        return None;
    }
    let fd = sys::open(path, libc::O_RDONLY, 0);
    if fd == -1 {
        xlog_warn(&bfmt!("conf_readfile: open (\"{}\", O_RDONLY) failed", path));
        return None;
    }
    if sys::flock(fd, libc::LOCK_SH) != 0 {
        xlog_warn(&bfmt!("conf_readfile: attempt to grab read lock failed: {}", xlog::m()));
        sys::close(fd);
        return None;
    }
    let sz = sys::lseek(fd, 0, libc::SEEK_END);
    if sz < 0 {
        xlog_warn(&bfmt!("conf_readfile: unable to determine file size: {}", xlog::m()));
        sys::close(fd);
        return None;
    }
    sys::lseek(fd, 0, libc::SEEK_SET);
    let mut buf = vec![0u8; sz as usize + 1];
    let n = sys::read(fd, &mut buf[..sz as usize]);
    if n != sz as i32 as isize {
        // QUIRK: C prints the buffer's address here ("%p"); it can't match.
        xlog_warn(&bfmt!("conf_readfile: read ({}, {}, {}) failed", fd, "(buffer)", sz as u64));
        sys::close(fd);
        return None;
    }
    sys::close(fd);
    buf.truncate(sz as usize);
    Some(xlog::c_str(&buf).to_vec())
}

impl Conf {
    /// `conf_init_file()`: a fresh database from `conf_file` (default `NFS_CONFFILE`),
    /// with `/usr/etc` first and the `.d` directories.
    pub fn init_file(conf_file: Option<&[u8]>) -> Conf {
        let mut c = Conf::default();
        let conf_file = conf_file.unwrap_or(NFS_CONFFILE);
        if conf_file.starts_with(b"/etc/") {
            let mut usr = b"/usr".to_vec();
            usr.extend_from_slice(conf_file);
            c.load_file(&usr);
            c.init_dir(&usr);
        }
        c.load_file(conf_file);
        c.init_dir(conf_file);
        c
    }

    /// `conf_begin()`.
    fn begin(&mut self) -> i32 {
        self.seq += 1;
        self.seq
    }

    /// `conf_load_files()`: parse one file of a `.d` directory into `trans`.
    fn load_files(&mut self, trans: i32, conf_file: &[u8]) -> bool {
        let Some(data) = conf_readfile(conf_file) else {
            return false;
        };
        let (mut section, mut subsection) = (None, None);
        self.parse(trans, data, &mut section, &mut subsection, conf_file);
        true
    }

    /// `conf_load_file()`: parse, then replace the whole database with the result.
    fn load_file(&mut self, conf_file: &[u8]) -> bool {
        let trans = self.begin();
        let Some(data) = conf_readfile(conf_file) else {
            return false;
        };
        let (mut section, mut subsection) = (None, None);
        self.parse(trans, data, &mut section, &mut subsection, conf_file);
        // QUIRK: this frees everything loaded before, /usr/etc's files included.
        for b in &mut self.buckets {
            b.clear();
        }
        self.end(trans, true);
        true
    }

    /// `conf_init_dir()`.
    fn init_dir(&mut self, conf_file: &[u8]) {
        let mut dname = conf_file.to_vec();
        dname.extend_from_slice(b".d");
        let list = match sys::scandir_versionsort(&dname) {
            Err(e) => {
                if e != libc::ENOENT {
                    xlog(L_WARNING, &bfmt!("conf_init_dir: scandir {}: {}", dname, sys::strerror(e)));
                }
                return;
            }
            Ok(l) => l,
        };
        if list.is_empty() {
            return;
        }
        let trans = self.begin();
        let mut nfiles = 0;
        for (name, d_type) in list {
            if !matches!(d_type, libc::DT_UNKNOWN | libc::DT_REG | libc::DT_LNK) {
                continue;
            }
            if name.first() == Some(&b'.') {
                continue;
            }
            let fname_len = name.len();
            let path_len = fname_len + dname.len();
            if fname_len == 0 || path_len > PATH_MAX {
                xlog(L_WARNING, &bfmt!("conf_init_dir: Too long file name: {} in {}", name, dname));
                continue;
            }
            if fname_len <= CONF_FILE_EXT.len() {
                xlog(D_GENERAL, &bfmt!("conf_init_dir: {}: name too short", name));
                continue;
            }
            if &name[fname_len - CONF_FILE_EXT.len()..] != CONF_FILE_EXT {
                xlog(D_GENERAL, &bfmt!("conf_init_dir: {}: invalid file extension", name));
                continue;
            }
            let mut fname = dname.clone();
            fname.push(b'/');
            fname.extend_from_slice(&name);
            // snprintf(fname, PATH_MAX, ...) truncates at PATH_MAX - 1 bytes.
            if fname.len() > PATH_MAX - 1 {
                fname.truncate(PATH_MAX - 1);
            }
            if !self.load_files(trans, &fname) {
                continue;
            }
            nfiles += 1;
        }
        if nfiles > 0 {
            self.end(trans, true);
        }
    }

    /// `conf_parse()`.
    fn parse(
        &mut self,
        trans: i32,
        mut buf: Vec<u8>,
        section: &mut Option<Vec<u8>>,
        subsection: &mut Option<Vec<u8>>,
        filename: &[u8],
    ) {
        let bufend = buf.len();
        let mut line = 0;
        let mut lineno = 0;
        let mut cp = 0;
        while cp < bufend {
            if buf[cp] == b'\n' {
                if cp > 0 && buf[cp - 1] == b'\\' {
                    buf[cp - 1] = b' ';
                    buf[cp] = b' ';
                } else {
                    buf[cp] = 0;
                    lineno += 1;
                    let l = buf[line..cp].to_vec();
                    self.parse_line(trans, l, filename, lineno, section, subsection);
                    line = cp + 1;
                }
            }
            cp += 1;
        }
        if cp != line {
            xlog_warn(b"conf_parse: last line non-terminated, ignored.");
        }
    }

    /// `conf_parse_line()`. `l` is the line without its newline (and without NULs).
    fn parse_line(
        &mut self,
        trans: i32,
        mut l: Vec<u8>,
        filename: &[u8],
        lineno: i32,
        section: &mut Option<Vec<u8>>,
        subsection: &mut Option<Vec<u8>>,
    ) {
        let mut line = 0;
        while sys::isspace(at(&l, line)) {
            line += 1;
        }
        if at(&l, line) == 0 {
            return;
        }
        if at(&l, line) == b'#' || at(&l, line) == b';' {
            return;
        }
        if at(&l, line) == b'[' {
            line += 1;
            *section = None;
            *subsection = None;
            while sys::isblank(at(&l, line)) {
                line += 1;
            }
            let Some(close) = strchr(&l, line, b']') else {
                xlog_warn(&bfmt!(
                    "config error at {}:{}: non-matched ']', ignoring until next section",
                    filename,
                    lineno
                ));
                return;
            };
            l[close] = 0;
            let mut ptr = close as isize - 1;
            while ptr >= line as isize && sys::isblank(l[ptr as usize]) {
                l[ptr as usize] = 0;
                ptr -= 1;
            }
            let val = strchr(&l, line, b'"');
            let mut val_at = None;
            if let Some(v) = val {
                let mut p = v as isize - 1;
                l[v] = 0;
                val_at = Some(v + 1);
                while p > line as isize && sys::isblank(l[p as usize]) {
                    l[p as usize] = 0;
                    p -= 1;
                }
            }
            *section = Some(cs(&l, line).to_vec());
            let Some(v) = val_at else {
                return;
            };
            let Some(q) = strchr(&l, v, b'"') else {
                xlog_warn(&bfmt!(
                    "config error at {}:{}: non-matched '\"', ignoring until next section",
                    filename,
                    lineno
                ));
                return;
            };
            l[q] = 0;
            *subsection = Some(cs(&l, v).to_vec());
            return;
        }

        let Some(eq) = strchr(&l, line, b'=') else {
            let rest = cs(&l, line);
            let skip = rest.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
            if skip < rest.len() {
                xlog_warn(&bfmt!("config error at {}:{}: line not empty and not an assignment", filename, lineno));
            }
            return;
        };
        if section.is_none() {
            xlog_warn(&bfmt!("config error at {}:{}: ignoring line not in a section", filename, lineno));
            return;
        }
        let mut val = eq + 1;
        l[eq] = 0;
        let mut ptr = eq as isize - 1;
        while ptr >= line as isize && sys::isblank(l[ptr as usize]) {
            l[ptr as usize] = 0;
            ptr -= 1;
        }
        while at(&l, val) != 0 && sys::isblank(at(&l, val)) {
            val += 1;
        }
        let q = at(&l, val);
        if q == b'"' || q == b'\'' {
            val += 1;
            let Some(end) = strchr(&l, val, q) else {
                xlog_warn(&bfmt!("config error at {}:{}: unmatched quotes", filename, lineno));
                return;
            };
            l[end] = 0;
        } else {
            if let Some(h) = strchr(&l, val, b'#') {
                l[h] = 0;
            }
            if let Some(s) = strchr(&l, val, b';') {
                l[s] = 0;
            }
            let len = cs(&l, val).len();
            let mut p = val as isize + len as isize - 1;
            while p > val as isize && sys::isspace(l[p as usize]) {
                l[p as usize] = 0;
                p -= 1;
            }
        }
        let tag = cs(&l, line).to_vec();
        let value = cs(&l, val).to_vec();
        if tag.is_empty() {
            xlog_warn(&bfmt!("config error at {}:{}: missing tag in assignment", filename, lineno));
            return;
        }
        if sys::strcaseeq(&tag, b"include") {
            let mut v = &value[..];
            let mut optional = false;
            if v.first() == Some(&b'-') {
                optional = true;
                v = &v[1..];
            }
            let relpath = relative_path(filename, v);
            let Some(sub) = conf_readfile(&relpath) else {
                if !optional {
                    xlog_warn(&bfmt!("config error at {}:{}: error loading included config", filename, lineno));
                }
                return;
            };
            let mut inc_section = section.clone();
            let mut inc_subsection = if section.is_some() { subsection.clone() } else { None };
            self.parse(trans, sub, &mut inc_section, &mut inc_subsection, &relpath);
        } else {
            let (s, a) = (section.clone().unwrap(), subsection.clone());
            self.set(trans, &s, a.as_deref(), &tag, &value, true, false);
        }
    }

    /// `conf_set()`: queue a set; empty values are dropped.
    #[allow(clippy::too_many_arguments)]
    fn set(&mut self, trans: i32, section: &[u8], arg: Option<&[u8]>, tag: &[u8], value: &[u8], ov: bool, def: bool) {
        if value.is_empty() {
            return;
        }
        // upper2lower(): stops at the first NUL (there are none).
        let section = section.iter().map(|&c| sys::tolower(c)).collect();
        self.queue.push(Trans {
            trans,
            section,
            arg: arg.map(<[u8]>::to_vec),
            tag: tag.to_vec(),
            value: value.to_vec(),
            overrides: ov,
            is_default: def,
        });
    }

    /// `conf_end()`: apply (or drop) every queued operation of `trans`, in order.
    fn end(&mut self, trans: i32, commit: bool) {
        let queue = std::mem::take(&mut self.queue);
        let (mine, rest): (Vec<Trans>, Vec<Trans>) = queue.into_iter().partition(|t| t.trans == trans);
        self.queue = rest;
        if !commit {
            return;
        }
        for t in mine {
            self.set_now(&t.section, t.arg.as_deref(), &t.tag, &t.value, t.overrides, t.is_default);
        }
    }

    /// `conf_remove_now()`. QUIRK: with no `arg`, it matches a binding with any arg.
    fn remove_now(&mut self, section: &[u8], arg: Option<&[u8]>, tag: &[u8]) -> bool {
        let b = &mut self.buckets[conf_hash(section)];
        for i in 0..b.len() {
            let cb = &b[i];
            if let Some(a) = arg
                && cb.arg.as_deref().is_none_or(|x| !sys::strcaseeq(a, x))
            {
                continue;
            }
            if sys::strcaseeq(&cb.section, section) && sys::strcaseeq(&cb.tag, tag) {
                let cb = b.remove(i);
                xlog(LOG_INFO_KIND, &bfmt!("[{}]:{}->{} removed", section, tag, cb.value));
                return false;
            }
        }
        true
    }

    /// `conf_set_now()`.
    fn set_now(&mut self, section: &[u8], arg: Option<&[u8]>, tag: &[u8], value: &[u8], ov: bool, def: bool) -> bool {
        if ov {
            self.remove_now(section, arg, tag);
        } else if self.get_section(section, arg, tag).is_some() {
            if !def {
                xlog(LOG_INFO_KIND, &bfmt!("conf_set: duplicate tag [{}]:{}, ignoring...", section, tag));
            }
            return true;
        }
        self.buckets[conf_hash(section)].insert(
            0,
            Binding {
                section: section.to_vec(),
                arg: arg.map(<[u8]>::to_vec),
                tag: tag.to_vec(),
                value: value.to_vec(),
            },
        );
        false
    }

    /// `conf_get_section()`: with `$name` values expanded from the environment, else from
    /// the `[environment]` section.
    pub fn get_section(&self, section: &[u8], arg: Option<&[u8]>, tag: &[u8]) -> Option<Vec<u8>> {
        let mut section = section.to_vec();
        let mut tag = tag.to_vec();
        'retry: loop {
            for cb in &self.buckets[conf_hash(&section)] {
                if !sys::strcaseeq(&section, &cb.section) {
                    continue;
                }
                match (arg, &cb.arg) {
                    (Some(a), Some(x)) if sys::strcaseeq(a, x) => {}
                    (Some(_), _) => continue,
                    (None, Some(_)) => continue,
                    (None, None) => {}
                }
                if !sys::strcaseeq(&tag, &cb.tag) {
                    continue;
                }
                if cb.value.first() == Some(&b'$') {
                    // QUIRK: a value naming itself loops forever, as in C.
                    if let Some(env) = sys::getenv(&cb.value[1..])
                        && !env.is_empty()
                    {
                        return Some(env);
                    }
                    section = b"environment".to_vec();
                    tag = cb.value[1..].to_vec();
                    continue 'retry;
                }
                return Some(cb.value.clone());
            }
            return None;
        }
    }

    /// `conf_get_str()`.
    pub fn get_str(&self, section: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
        self.get_section(section, None, tag)
    }

    /// `conf_get_num()`.
    pub fn get_num(&self, section: &[u8], tag: &[u8], def: i32) -> i32 {
        self.get_str(section, tag).map_or(def, |v| sys::atoi(&v))
    }

    /// `conf_get_bool()`.
    pub fn get_bool(&self, section: &[u8], tag: &[u8], def: bool) -> bool {
        let Some(v) = self.get_str(section, tag) else {
            return def;
        };
        let is = |w: &[u8]| sys::strcaseeq(&v, w);
        if is(b"1") || is(b"t") || is(b"true") || is(b"y") || is(b"yes") || is(b"on") {
            return true;
        }
        if is(b"0") || is(b"f") || is(b"false") || is(b"n") || is(b"no") || is(b"off") {
            return false;
        }
        def
    }

    /// `conf_get_list()`: the comma-separated fields, or `None` when the tag is unset.
    pub fn get_list(&self, section: &[u8], tag: &[u8]) -> Option<Vec<Vec<u8>>> {
        let s = self.get_str(section, tag)?;
        let mut out = Vec::new();
        for f in s.split(|&b| b == b',') {
            let mut f = f;
            while let Some((&c, r)) = f.split_first() {
                if !sys::isspace(c) {
                    break;
                }
                f = r;
            }
            // QUIRK: trailing white space is never trimmed: C starts its trimming loop
            // at the NUL that strsep() left in place of the comma.
            if f.is_empty() {
                xlog(LOG_INFO_KIND, b"conf_get_list: empty field, ignoring...");
                continue;
            }
            out.push(f.to_vec());
        }
        Some(out)
    }
}

static CONF: Mutex<Option<Conf>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&Conf) -> T) -> T {
    let g = CONF.lock().unwrap_or_else(|e| e.into_inner());
    match g.as_ref() {
        Some(c) => f(c),
        None => f(&Conf::default()),
    }
}

/// `conf_init_file()` into the process-wide database.
pub fn conf_init_file(conf_file: Option<&[u8]>) {
    let c = Conf::init_file(conf_file);
    *CONF.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
}

/// `conf_get_str()`.
pub fn conf_get_str(section: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    with(|c| c.get_str(section, tag))
}

/// `conf_get_num()`.
pub fn conf_get_num(section: &[u8], tag: &[u8], def: i32) -> i32 {
    with(|c| c.get_num(section, tag, def))
}

/// `conf_get_bool()`.
pub fn conf_get_bool(section: &[u8], tag: &[u8], def: bool) -> bool {
    with(|c| c.get_bool(section, tag, def))
}

/// `conf_get_list()`.
pub fn conf_get_list(section: &[u8], tag: &[u8]) -> Option<Vec<Vec<u8>>> {
    with(|c| c.get_list(section, tag))
}

/// `conf_get_section()`.
pub fn conf_get_section(section: &[u8], arg: Option<&[u8]>, tag: &[u8]) -> Option<Vec<u8>> {
    with(|c| c.get_section(section, arg, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirname_like_glibc() {
        for (p, d) in [
            (&b"/etc/nfs.conf"[..], &b"/etc"[..]),
            (b"nfs.conf", b"."),
            (b"/nfs.conf", b"/"),
            (b"/", b"/"),
            (b"a/b/", b"a"),
            (b"/etc//x", b"/etc"),
            (b"", b"."),
        ] {
            assert_eq!(dirname(p), d, "{}", String::from_utf8_lossy(p));
        }
    }

    #[test]
    fn list_trimming() {
        let mut c = Conf::default();
        c.set_now(b"s", None, b"debug", b" a , b ,, c ", true, false);
        assert_eq!(c.get_list(b"s", b"debug").unwrap(), vec![b"a ".to_vec(), b"b ".to_vec(), b"c ".to_vec()]);
    }
}
