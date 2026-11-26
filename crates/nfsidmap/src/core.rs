//! `libnfsidmap.c`: initialization, the default domain (from the configuration, else
//! DNS), loading the methods, and running a call through them in order.

use support::bfmt;
use support::conffile::Conf;
use support::sys;
use support::xlog;

use crate::common::Common;
use crate::nss::Nss;
use crate::regex::RegexMethod;
use crate::staticmap::Static;

/// `NFS4_MAX_DOMAIN_LEN`.
pub const NFS4_MAX_DOMAIN_LEN: usize = 512;
/// Where C looks for its plugins (configure's `--with-pluginpath`); only the messages
/// show it.
pub const PATH_PLUGINS: &[u8] = b"/usr/lib64/libnfsidmap";
/// `PATH_IDMAPDCONF`.
pub const PATH_IDMAPDCONF: &[u8] = b"/etc/idmapd.conf";
const IDMAPD_DEFAULT_DOMAIN: &[u8] = b"localdomain";
const NFS4DNSTXTREC: &[u8] = b"_nfsv4idmapdomain";
const NS_MAXMSG: usize = 65535;
const NS_MAXDNAME: usize = 1025;
const HFIXEDSZ: isize = 12;
const QFIXEDSZ: isize = 4;
const C_IN: i32 = 1;
const T_TXT: i32 = 16;

/// `nfs4_idmap_log_function_t`: gets the formatted message.
pub type LogFn = fn(&[u8]);

/// `default_logger()`: `vsyslog(LOG_WARNING, ...)`.
fn default_logger(msg: &[u8]) {
    sys::syslog(libc::LOG_WARNING, msg);
}

/// `%s` of a possibly NULL string, as glibc prints it.
pub(crate) fn ns(s: Option<&[u8]>) -> &[u8] {
    s.unwrap_or(b"(null)")
}

/// The library's own state (what the methods may reach).
#[derive(Debug)]
pub struct Core {
    /// The library's copy of the configuration.
    pub conf: Conf,
    /// `nfsidmap_conf_path`.
    pub conf_path: Vec<u8>,
    /// `default_domain`.
    pub default_domain: Option<Vec<u8>>,
    /// The library's copy of `nfsidmap_common.c`.
    pub common: Common,
    pub nobody_uid: u32,
    pub nobody_gid: u32,
    /// `idmap_verbosity`.
    pub verbosity: i32,
    /// `idmap_log_func`.
    pub log_func: LogFn,
}

impl Default for Core {
    fn default() -> Self {
        Core {
            conf: Conf::default(),
            conf_path: PATH_IDMAPDCONF.to_vec(),
            default_domain: None,
            common: Common::default(),
            nobody_uid: u32::MAX,
            nobody_gid: u32::MAX,
            verbosity: 0,
            log_func: default_logger,
        }
    }
}

impl Core {
    /// `IDMAP_LOG(lvl, msg)`.
    pub fn log(&self, lvl: i32, msg: &[u8]) {
        if lvl <= self.verbosity {
            (self.log_func)(msg);
        }
    }

    /// Whether `IDMAP_LOG(lvl, ...)` prints (so callers skip building the message).
    pub fn logs(&self, lvl: i32) -> bool {
        lvl <= self.verbosity
    }

    /// `get_default_domain()`: the cached domain, else DNS's (or "").
    pub fn get_default_domain(&mut self) -> Vec<u8> {
        if let Some(d) = &self.default_domain {
            return d.clone();
        }
        match self.domain_from_dns() {
            Some(d) => self.default_domain = Some(d),
            None => {
                self.log(0, b"Unable to determine a default nfsv4 domain;  consider specifying one in idmapd.conf");
                self.default_domain = Some(Vec::new());
            }
        }
        self.default_domain.clone().unwrap()
    }

    /// `nfs4_get_default_domain(NULL, buf, len)`.
    pub fn nfs4_get_default_domain(&mut self, len: usize) -> Result<Vec<u8>, i32> {
        let d = self.get_default_domain();
        if d.len() + 1 > len {
            return Err(-libc::ERANGE);
        }
        Ok(d)
    }

    /// `dns_txt_query()`: the first answer's text in `_nfsv4idmapdomain.DOMAIN`'s TXT
    /// lookup.
    ///
    /// QUIRK: C reads the first resource record of the answer section as TXT data
    /// whatever its type (a CNAME's target gives its first label's length byte as the
    /// text's length), and it doesn't check that the record is in the message: past
    /// the end it reads the zeros of its buffer, as here (so far that C would leave
    /// its 64 KiB buffer, it reads whatever follows it, and this reads zeros).
    fn dns_txt_query(&self, domain: &[u8]) -> Option<Vec<u8>> {
        let mut msg = vec![0u8; NS_MAXMSG + 1024];
        sys::res_init();
        let len = sys::res_querydomain_into(NFS4DNSTXTREC, domain, C_IN, T_TXT, &mut msg, NS_MAXMSG);
        let txt = NFS4DNSTXTREC;
        if len < 0 {
            let h = sys::hstrerror_of(sys::h_errno());
            self.log(2, &bfmt!("libnfsidmap: res_querydomain() failed for {}.{}: {}\n", txt, domain, h));
            return None;
        }
        let ancount = u16::from_be_bytes([msg[6], msg[7]]);
        if ancount < 1 {
            self.log(2, &bfmt!("libnfsidmap: No TXT record for {}.{}\n", txt, domain));
            return None;
        }
        let eom = (len as usize).min(NS_MAXMSG);
        let mut mptr: isize = HFIXEDSZ;
        mptr += sys::dn_skipname_at(&msg, mptr as usize, eom) as isize + QFIXEDSZ;
        let (n, _) = sys::dn_expand_at(&msg, eom, (mptr as usize).min(msg.len()), NS_MAXDNAME);
        if n < 0 {
            let h = sys::hstrerror_of(sys::h_errno());
            self.log(2, &bfmt!("libnfsidmap: No question section for {}.{}: {}\n", txt, domain, h));
            return None;
        }
        mptr += sys::dn_skipname_at(&msg, mptr as usize, eom) as isize;
        mptr += 2 + 2 + 4;
        // GETSHORT(len, mptr): never negative, so the check after it never fails.
        mptr += 2;
        let at = |i: isize| msg.get(i as usize).copied().unwrap_or(0);
        let l = at(mptr) as isize;
        mptr += 1;
        let mut answ: Vec<u8> = (0..l).map(|i| at(mptr + i)).collect();
        if let Some(z) = answ.iter().position(|&b| b == 0) {
            answ.truncate(z);
        }
        Some(answ)
    }

    /// `domain_from_dns()`: the part of the host's name after its first dot (as DNS
    /// gives the name, else as is), or that domain's `_nfsv4idmapdomain` TXT record.
    fn domain_from_dns(&self) -> Option<Vec<u8>> {
        let hname = sys::gethostname(64)?;
        let name = match sys::gethostbyname_name(&hname) {
            None => {
                self.log(
                    1,
                    b"libnfsidmap: DNS lookup of hostname failed. Attempting to use domain from hostname as is.",
                );
                hname
            }
            Some(h) => h,
        };
        let dot = name.iter().position(|&b| b == b'.')?;
        let c = name[dot + 1..].to_vec();
        if c.is_empty() {
            return None;
        }
        Some(self.dns_txt_query(&c).unwrap_or(c))
    }
}

/// A loaded method.
#[derive(Debug)]
pub enum Method {
    Nss(Box<Nss>),
    Static(Box<Static>),
    Regex(Box<RegexMethod>),
}

impl Method {
    /// `trans->name`.
    fn name(&self) -> &'static [u8] {
        match self {
            Method::Nss(_) => b"nsswitch",
            Method::Static(_) => b"static",
            Method::Regex(_) => b"regex",
        }
    }
}

/// One of the entry points that run through the methods.
#[derive(Debug, Clone, Copy)]
enum Func {
    PrincToIds,
    NameToUid,
    NameToGid,
    UidToName,
    GidToName,
    GssPrincToGrouplist,
}

impl Func {
    fn name(self) -> &'static [u8] {
        match self {
            Func::PrincToIds => b"princ_to_ids",
            Func::NameToUid => b"name_to_uid",
            Func::NameToGid => b"name_to_gid",
            Func::UidToName => b"uid_to_name",
            Func::GidToName => b"gid_to_name",
            Func::GssPrincToGrouplist => b"gss_princ_to_grouplist",
        }
    }
}

/// A loaded method, as `dlopen()` keeps it: one instance however many lists name it,
/// until the last of them unloads it.
#[derive(Debug)]
struct Loaded {
    name: Vec<u8>,
    method: Method,
    refs: usize,
}

/// The whole library: its own state, the loaded methods, and the two method lists
/// (by name).
#[derive(Debug, Default)]
pub struct Lib {
    pub core: Core,
    loaded: Vec<Loaded>,
    nfs4_plugins: Option<Vec<Vec<u8>>>,
    gss_plugins: Option<Vec<Vec<u8>>>,
}

/// `snprintf(buf, 128, ...)`: at most 127 bytes.
fn trunc127(mut v: Vec<u8>) -> Vec<u8> {
    v.truncate(127);
    v
}

impl Lib {
    /// `load_translation_plugin()`: the method's name, now loaded once more.
    fn load_translation_plugin(&mut self, method: &[u8]) -> Option<Vec<u8>> {
        // C first tries dlopen("METHOD.so"): along the library search path, where none
        // of the plugins are, but that also finds a plugin already loaded (by its
        // soname, METHOD.so). Then PATH_PLUGINS.
        if let Some(i) = self.loaded.iter().position(|l| l.name == method) {
            let mut short = method.to_vec();
            short.extend_from_slice(b".so");
            let short = trunc127(short);
            // The same instance, set up again (the built-in methods' init() can't fail).
            let core = &mut self.core;
            match &mut self.loaded[i].method {
                Method::Nss(p) => p.init(core),
                Method::Static(p) => p.init(core),
                Method::Regex(p) => p.init(core),
            };
            self.loaded[i].refs += 1;
            self.core.log(1, &bfmt!("libnfsidmap: loaded plugin {} for method {}", short, method));
            return Some(method.to_vec());
        }
        let mut plgname = PATH_PLUGINS.to_vec();
        plgname.push(b'/');
        plgname.extend_from_slice(method);
        plgname.extend_from_slice(b".so");
        let plgname = trunc127(plgname);
        let m = match method {
            b"nsswitch" => Method::Nss(Box::default()),
            b"static" => Method::Static(Box::default()),
            b"regex" => Method::Regex(Box::default()),
            _ => {
                self.core.log(
                    1,
                    &bfmt!(
                        "libnfsidmap: Unable to load plugin: {}: {}: cannot open shared object file: No such file or directory",
                        plgname,
                        plgname
                    ),
                );
                return None;
            }
        };
        let mut m = m;
        let ret = match &mut m {
            Method::Nss(p) => p.init(&mut self.core),
            Method::Static(p) => p.init(&mut self.core),
            Method::Regex(p) => p.init(&mut self.core),
        };
        if ret != 0 {
            self.core.log(1, &bfmt!("libnfsidmap: Failed in {}'s init(), returned {}", plgname, ret));
            return None;
        }
        self.core.log(1, &bfmt!("libnfsidmap: loaded plugin {} for method {}", plgname, method));
        self.loaded.push(Loaded { name: method.to_vec(), method: m, refs: 1 });
        Some(method.to_vec())
    }

    /// `unload_plugins()`: each `dlclose()` drops a reference; the last one unloads
    /// the method (so it starts afresh when loaded again).
    fn unload_plugins(&mut self, names: Option<Vec<Vec<u8>>>) {
        for n in names.unwrap_or_default() {
            if let Some(i) = self.loaded.iter().position(|l| l.name == n) {
                self.loaded[i].refs -= 1;
                if self.loaded[i].refs == 0 {
                    self.loaded.remove(i);
                }
            }
        }
    }

    /// `load_plugins()`: every method, or none.
    fn load_plugins(&mut self, methods: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for m in methods {
            match self.load_translation_plugin(m) {
                Some(p) => out.push(p),
                None => {
                    self.core.log(0, &bfmt!("libnfsidmap: requested translation method, '{}', is not available", m));
                    self.unload_plugins(Some(out));
                    return None;
                }
            }
        }
        Some(out)
    }

    /// `nfs4_init_name_mapping()`.
    pub fn init(&mut self, conffile: Option<&[u8]>) -> i32 {
        // XXX (C): need to be able to reload configurations...
        if self.nfs4_plugins.is_some() {
            return 0;
        }
        if let Some(c) = conffile {
            self.core.conf_path = c.to_vec();
        }
        let path = self.core.conf_path.clone();
        self.core.conf = xlog::in_library_copy(|| Conf::init_file(Some(&path)));

        let mut ret = -libc::ENOENT;
        let mut dflt = false;
        self.core.default_domain = self.core.conf.get_str(b"General", b"Domain");
        if self.core.default_domain.is_none() {
            dflt = true;
            match self.core.domain_from_dns() {
                Some(d) => {
                    ret = 0;
                    self.core.default_domain = Some(d);
                }
                None => {
                    ret = -1;
                    self.core.log(
                        0,
                        &bfmt!(
                            "libnfsidmap: Unable to determine the NFSv4 domain; Using '{}' as the NFSv4 domain which means UIDs will be mapped to the 'Nobody-User' user defined in {}",
                            IDMAPD_DEFAULT_DOMAIN,
                            PATH_IDMAPDCONF
                        ),
                    );
                    self.core.default_domain = Some(IDMAPD_DEFAULT_DOMAIN.to_vec());
                }
            }
        }
        let dd = self.core.default_domain.clone().unwrap();
        self.core.log(1, &bfmt!("libnfsidmap: using{} domain: {}", if dflt { " (default)" } else { "" }, dd));

        let mut common = std::mem::take(&mut self.core.common);
        let conf = std::mem::take(&mut self.core.conf);
        let realms = common
            .get_local_realms(&conf, || self.core.nfs4_get_default_domain(NFS4_MAX_DOMAIN_LEN).unwrap_or_default())
            .clone();
        self.core.conf = conf;
        self.core.common = common;
        if self.core.verbosity >= 1 {
            let mut buf = Vec::new();
            for r in &realms {
                buf.extend_from_slice(&bfmt!("'{}' ", r));
            }
            self.core.log(1, &bfmt!("libnfsidmap: Realms list: {}", buf));
        }

        match self.core.conf.get_list(b"Translation", b"Method") {
            Some(methods) => {
                self.core.log(1, b"libnfsidmap: processing 'Method' list");
                match self.load_plugins(&methods) {
                    Some(p) => self.nfs4_plugins = Some(p),
                    None => return -libc::ENOENT,
                }
            }
            None => match self.load_plugins(&[b"nsswitch".to_vec()]) {
                Some(p) => self.nfs4_plugins = Some(p),
                None => return -libc::ENOENT,
            },
        }

        'out: {
            if let Some(gss) = self.core.conf.get_list(b"Translation", b"GSS-Methods") {
                self.core.log(1, b"libnfsidmap: processing 'GSS-Methods' list");
                match self.load_plugins(&gss) {
                    Some(p) => self.gss_plugins = Some(p),
                    // QUIRK: goes out with ret as the domain lookup left it: success
                    // (without GSS methods, and without the Nobody-User and
                    // Nobody-Group lookups) when the domain came from DNS.
                    None => break 'out,
                }
            }
            if let Some(user) = self.core.conf.get_str(b"Mapping", b"Nobody-User") {
                let l = sys::getpwnam_r(&user, sys::getpw_r_size_max());
                match l.entry {
                    Some(pw) if l.ret == 0 => self.core.nobody_uid = pw.uid,
                    _ => self
                        .core
                        .log(1, &bfmt!("libnfsidmap: Nobody-User ({}) not found: {}", user, sys::strerror(l.errno))),
                }
            }
            if let Some(group) = self.core.conf.get_str(b"Mapping", b"Nobody-Group") {
                let l = sys::getgrnam_r(&group, sys::getgr_r_size_max());
                match l.entry {
                    Some(gr) if l.ret == 0 => self.core.nobody_gid = gr.gid,
                    _ => self
                        .core
                        .log(1, &bfmt!("libnfsidmap: Nobody-Group ({}) not found: {}", group, sys::strerror(l.errno))),
                }
            }
            ret = 0;
        }
        if ret != 0 {
            let (n, g) = (self.nfs4_plugins.take(), self.gss_plugins.take());
            self.unload_plugins(n);
            self.unload_plugins(g);
        }
        if ret != 0 { -libc::ENOENT } else { 0 }
    }

    /// `nfs4_term_name_mapping()`.
    pub fn term(&mut self) {
        let (n, g) = (self.nfs4_plugins.take(), self.gss_plugins.take());
        self.unload_plugins(n);
        self.unload_plugins(g);
        self.core.common.free_local_realms();
        // conf_cleanup(). QUIRK: C's default_domain then points into the freed
        // database; this keeps the value.
        self.core.conf = Conf::default();
    }

    /// `RUN_TRANSLATIONS(funcname, prefer_gss, ...)`, logged as `caller`.
    fn run(
        &mut self,
        caller: &[u8],
        func: Func,
        prefer_gss: bool,
        mut f: impl FnMut(&mut Method, &mut Core) -> i32,
    ) -> i32 {
        let mut ret = self.init(None);
        if ret != 0 {
            return ret;
        }
        let plgns = if prefer_gss && self.gss_plugins.is_some() {
            self.gss_plugins.clone().unwrap()
        } else {
            self.nfs4_plugins.clone().unwrap()
        };
        for name in &plgns {
            let p = &mut self.loaded.iter_mut().find(|l| &l.name == name).unwrap().method;
            if self.core.logs(4) {
                self.core.log(4, &bfmt!("{}: calling {}->{}", caller, p.name(), func.name()));
            }
            ret = f(p, &mut self.core);
            if self.core.logs(4) {
                self.core.log(4, &bfmt!("{}: {}->{} returned {}", caller, p.name(), func.name(), ret));
            }
            if ret == -libc::ENOENT {
                continue;
            }
            break;
        }
        if self.core.logs(4) {
            self.core.log(4, &bfmt!("{}: final return value is {}", caller, ret));
        }
        ret
    }

    pub fn uid_to_name(&mut self, uid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
        self.run(b"nfs4_uid_to_name", Func::UidToName, false, |m, c| match m {
            Method::Nss(p) => p.uid_to_name(c, uid, domain, name, len),
            Method::Static(p) => p.uid_to_name(uid, name),
            Method::Regex(p) => p.uid_to_name(c, uid, domain, name, len),
        })
    }

    pub fn gid_to_name(&mut self, gid: u32, domain: Option<&[u8]>, name: &mut Vec<u8>, len: usize) -> i32 {
        self.run(b"nfs4_gid_to_name", Func::GidToName, false, |m, c| match m {
            Method::Nss(p) => p.gid_to_name(c, gid, domain, name, len),
            Method::Static(p) => p.gid_to_name(gid, name),
            Method::Regex(p) => p.gid_to_name(c, gid, name, len),
        })
    }

    pub fn name_to_uid(&mut self, name: &[u8], uid: &mut u32) -> i32 {
        self.run(b"nfs4_name_to_uid", Func::NameToUid, false, |m, c| match m {
            Method::Nss(p) => p.name_to_uid(c, name, uid),
            Method::Static(p) => p.name_to_uid(c, name, uid),
            Method::Regex(p) => p.name_to_uid(c, name, uid),
        })
    }

    pub fn name_to_gid(&mut self, name: &[u8], gid: &mut u32) -> i32 {
        self.run(b"nfs4_name_to_gid", Func::NameToGid, false, |m, c| match m {
            Method::Nss(p) => p.name_to_gid(c, name, gid),
            Method::Static(p) => p.name_to_gid(c, name, gid),
            Method::Regex(p) => p.name_to_gid(c, name, gid),
        })
    }

    pub fn princ_to_ids(&mut self, caller: &[u8], secname: &[u8], princ: &[u8], uid: &mut u32, gid: &mut u32) -> i32 {
        self.run(caller, Func::PrincToIds, true, |m, c| match m {
            Method::Nss(p) => p.princ_to_ids(c, secname, princ, uid, gid),
            Method::Static(p) => p.princ_to_ids(c, secname, princ, uid, gid),
            Method::Regex(p) => p.princ_to_ids(c, secname, princ, uid, gid),
        })
    }

    pub fn princ_to_grouplist(
        &mut self,
        caller: &[u8],
        secname: &[u8],
        princ: &[u8],
        groups: &mut Vec<u32>,
        ngroups: &mut i32,
    ) -> i32 {
        self.run(caller, Func::GssPrincToGrouplist, true, |m, c| match m {
            Method::Nss(p) => p.princ_to_grouplist(c, secname, princ, groups, ngroups),
            Method::Static(p) => p.princ_to_grouplist(c, secname, princ, groups, ngroups),
            Method::Regex(p) => p.princ_to_grouplist(c, secname, princ, groups, ngroups),
        })
    }

    /// `set_id_to_nobody()`: `Nobody-User`/`Nobody-Group`, else `nobody@DOMAIN`
    /// mapped, else -2; always 0.
    fn set_id_to_nobody(&mut self, id: &mut u32, is_uid: bool) -> i32 {
        let mut nobody = b"nobody@".to_vec();
        nobody.extend_from_slice(&self.core.get_default_domain());
        if is_uid && self.core.nobody_uid != u32::MAX {
            *id = self.core.nobody_uid;
            return 0;
        } else if !is_uid && self.core.nobody_gid != u32::MAX {
            *id = self.core.nobody_gid;
            return 0;
        }
        let rc = if is_uid { self.name_to_uid(&nobody, id) } else { self.name_to_gid(&nobody, id) };
        if rc != 0 {
            *id = (-2i32) as u32;
        }
        0
    }

    pub fn owner_to_uid(&mut self, name: &[u8], uid: &mut u32) -> i32 {
        let mut rc = self.name_to_uid(name, uid);
        if rc != 0 && id_as_chars(name, uid) {
            rc = 0;
        } else if rc != 0 {
            rc = self.set_id_to_nobody(uid, true);
        }
        rc
    }

    pub fn group_owner_to_gid(&mut self, name: &[u8], gid: &mut u32) -> i32 {
        let mut rc = self.name_to_gid(name, gid);
        if rc != 0 && id_as_chars(name, gid) {
            rc = 0;
        } else if rc != 0 {
            rc = self.set_id_to_nobody(gid, false);
        }
        rc
    }
}

/// `id_as_chars()`: the name as a number (`strtol()`, so "12abc" is 12), cut to an
/// int; 0 only when the name is "0".
fn id_as_chars(name: &[u8], id: &mut u32) -> bool {
    let (value, _, _) = sys::strtol10(name);
    if value == 0 && xlog::c_str(name) != b"0" {
        return false;
    }
    *id = value as i32 as u32;
    true
}
