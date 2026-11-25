//! Differential test harness: run the C program and the port in identical sandboxes,
//! with the same files and the same fake peers, and compare everything observable.
//!
//! # The sandbox
//!
//! Each run gets a fresh directory `T` under `target/difftest/<case>/<impl>`, bound onto
//! `target/difftest/.root` inside the sandbox so both implementations see the same paths
//! (`@T@` in a case stands for it). The sandbox has new user, mount, network, pid and
//! UTS namespaces (host name `nsmtest`). Ids are mapped with `newuidmap`/`newgidmap` and
//! the invoking user's subordinate ranges: id 0 is the invoking user and ids 1-65536 the
//! first subordinate ids, so there is a real root and the system's users (`nobody` for
//! the state directory) exist.
//!
//! Inside, a shell runs as pid 1. It mounts `/proc` and a tmpfs on `/run`, brings up
//! `lo`, and gives the program:
//!
//! - its own `/etc`: a tmpfs of links to the host's files, with the case's files
//!   (`hosts`, `nfs.conf`, `nfs.conf.d/...`) in place of the links;
//! - its own `/var/lib/nfs` (`T/nfs`), with the case's files;
//! - regular files over `/proc/sys/fs/nfs/nsm_local_state`, `nlm_tcpport`,
//!   `nlm_udpport` and `/proc/fs/lockd/nlm_end_grace`, so what it writes to the
//!   kernel is seen;
//! - for rpc.statd, a real rpcbind (the system's, the same in both runs; its syslog
//!   messages are left out), and the program's own sm-notify over
//!   `/usr/sbin/sm-notify`;
//! - fake peers from `nsmprobe`, started first (it says when it's ready through a FIFO);
//! - a fake clock (the shim in `tests/shim/`) whose `poll()` timeouts pass at once.
//!
//! Then it runs the program, waits for it and for any daemon()ized child to finish,
//! stops the probe, and records the state directory and `/run`. `/dev/log` is a socket
//! the harness reads. rpc.statd runs in the background while the probe works through
//! the case's commands (calls, signals, rpcbind dumps); the probe says when it's done
//! through a second FIFO, after stopping statd.
//!
//! The script forks the same processes in the same order in every run, so the pids,
//! and with them the xids and reserved ports the programs pick, come out the same.
//!
//! The C programs come from `$NFSUTILS_REFERENCE` (a build tree), by default
//! `../nfs-utils` (tools/build-reference.sh builds it there).

#![allow(dead_code)]

use std::ffi::{CString, c_char, c_int};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_dir() -> PathBuf {
    manifest_dir().join("../..").canonicalize().unwrap()
}

/// The C reference build tree.
pub fn reference_dir() -> PathBuf {
    std::env::var_os("NFSUTILS_REFERENCE").map_or_else(|| workspace_dir().join("../nfs-utils"), PathBuf::from)
}

/// A program of the reference: `sm-notify` or `statd`.
pub fn reference_binary(prog: &str) -> PathBuf {
    let p = reference_dir().join("utils/statd").join(prog);
    assert!(p.exists(), "no C reference at {} (run tools/build-reference.sh)", p.display());
    p
}

pub fn rust_sm_notify() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sm-notify"))
}

pub fn rust_statd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_statd"))
}

pub fn probe_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nsmprobe"))
}

/// Build a C helper once into target/difftest/.tools.
fn build_tool(name: &str, args: &[&str], src: &str, libs: &[&str]) -> PathBuf {
    let dir = workspace_dir().join("target/difftest/.tools");
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join(name);
    let tmp = dir.join(format!("{name}.{}", std::process::id()));
    let st = Command::new("cc")
        .args(args)
        .arg("-o")
        .arg(&tmp)
        .arg(manifest_dir().join(src))
        .args(libs)
        .status()
        .expect("cc");
    assert!(st.success(), "building {name} failed");
    std::fs::rename(&tmp, &out).unwrap();
    out
}

/// tests/shim/faketime.c, the LD_PRELOAD clock.
pub fn shim() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| build_tool("faketime.so", &["-shared", "-fPIC", "-O2"], "tests/shim/faketime.c", &["-ldl"]))
        .clone()
}

/// Where every run's `T` appears inside its sandbox.
pub fn fixed_root() -> PathBuf {
    let p = workspace_dir().join("target/difftest/.root");
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The fake clock's start: 2026-11-25 12:00:00 UTC.
pub const EPOCH: i64 = 1_795_608_000;

/// One test case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    /// The program: `sm-notify`.
    pub prog: String,
    pub args: Vec<String>,
    /// Files in the sandbox's `/etc`: (relative path, contents).
    pub etc: Vec<(String, Vec<u8>)>,
    /// Files in `/var/lib/nfs`: (relative path, contents).
    pub state: Vec<(String, Vec<u8>)>,
    /// Shell lines run before the program starts (as root, in the sandbox).
    pub setup: Vec<String>,
    /// The nsmprobe script's `peer` lines.
    pub peers: Vec<String>,
    /// Real milliseconds a `poll()` waits before its timeout passes on the fake clock.
    pub poll_ms: u32,
    /// The program's environment additions (`NAME=value`).
    pub env: Vec<String>,
    /// rpc.statd: start rpcbind first.
    pub rpcbind: bool,
    /// rpc.statd: the nsmprobe commands run once the program was started (after
    /// `ready`), before `finish`. `@T@` stands for the sandbox's `T`.
    pub probe: Vec<String>,
    /// nsmprobe commands run before the program starts (after the peers).
    pub before: Vec<String>,
}

impl Case {
    /// A case for `prog`, with an empty `sm/` and `sm.bak/` owned by `nobody`.
    pub fn new(name: &str, prog: &str, args: &[&str]) -> Case {
        Case {
            name: name.to_string(),
            prog: prog.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            etc: Vec::new(),
            state: Vec::new(),
            setup: vec!["mkdir -p /var/lib/nfs/sm /var/lib/nfs/sm.bak".into()],
            peers: Vec::new(),
            poll_ms: 1000,
            env: Vec::new(),
            rpcbind: prog == "rpc.statd",
            probe: Vec::new(),
            before: Vec::new(),
        }
        .owner_setup()
    }

    /// A case with nothing in `/var/lib/nfs`.
    pub fn bare(name: &str, prog: &str, args: &[&str]) -> Case {
        let mut c = Case::new(name, prog, args);
        c.setup.clear();
        c
    }

    fn owner_setup(self) -> Case {
        self.setup("chown nobody:nobody /var/lib/nfs/sm /var/lib/nfs/sm.bak")
    }

    pub fn setup(mut self, line: &str) -> Case {
        self.setup.push(line.to_string());
        self
    }

    pub fn etc(mut self, path: &str, contents: &[u8]) -> Case {
        self.etc.push((path.to_string(), contents.to_vec()));
        self
    }

    pub fn state(mut self, path: &str, contents: &[u8]) -> Case {
        self.state.push((path.to_string(), contents.to_vec()));
        self
    }

    pub fn peer(mut self, line: &str) -> Case {
        self.peers.push(line.to_string());
        self
    }

    /// A probe command run before the program starts.
    pub fn before(mut self, line: &str) -> Case {
        self.before.push(line.to_string());
        self
    }

    /// Wait until statd's stderr has `text` (a probe command).
    pub fn expect(self, text: &str) -> Case {
        self.probe(&format!("expect @T@/out/stderr {text}"))
    }

    /// Wait until statd's stderr has `text` `n` times (a probe command).
    pub fn expect_n(self, n: usize, text: &str) -> Case {
        self.probe(&format!("expect-n @T@/out/stderr {n} {text}"))
    }

    /// A probe command (rpc.statd).
    pub fn probe(mut self, line: &str) -> Case {
        self.probe.push(line.to_string());
        self
    }

    pub fn env(mut self, kv: &str) -> Case {
        self.env.push(kv.to_string());
        self
    }

    /// A notify-list record in `sm.bak/HOST` (owned by `nobody`, as statd writes them).
    pub fn notify(self, host: &str, lines: &[&str]) -> Case {
        let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
        self.state(&format!("sm.bak/{host}"), body.as_bytes())
            .setup(&format!("chown nobody:nobody '/var/lib/nfs/sm.bak/{host}'"))
    }
}

/// A record line: callback address, prog/vers/proc, cookie, mon_name, my_name.
pub fn record(mon_name: &str, my_name: &str) -> String {
    format!("0100007f 000186b5 00000004 00000010 {} {mon_name} {my_name}", "0123456789abcdef".repeat(2))
}

/// Everything a run produced, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: String,
    pub stdout: String,
    pub stderr: String,
    pub syslog: Vec<String>,
    pub peers: String,
    pub state: String,
    pub run: String,
    pub kernel: String,
}

fn cstr(s: impl AsRef<[u8]>) -> CString {
    CString::new(s.as_ref().to_vec()).unwrap()
}

fn path_c(p: &Path) -> CString {
    cstr(p.to_str().unwrap())
}

/// The invoking user's first subordinate id, from /etc/subuid or /etc/subgid.
fn subordinate(file: &str, name: &str, id: u32) -> u32 {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() == 3 && (f[0] == name || f[0] == id.to_string()) && f[2].parse::<u32>().unwrap_or(0) >= 65536 {
            return f[1].parse().unwrap();
        }
    }
    panic!("no subordinate range of 65536 ids for {name} in {file}: the sandbox needs one");
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

/// fork(); the child enters new user, mount, network, pid and UTS namespaces, makes the
/// binds, and forks pid 1 of the new pid namespace, which execs `sh -c script`. The
/// child exits with pid 1's status. Returns the child's pid.
///
/// Both the child and pid 1 have a parent-death signal of SIGKILL, so the sandbox
/// can't outlive the test: killing the child (the timeout in `wait`), or the test
/// process dying, kills pid 1, and with it everything in the pid namespace.
fn spawn_in_sandbox(binds: &[(CString, CString)], script: &str, stdio: [c_int; 3]) -> u32 {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let name = std::env::var("USER").unwrap_or_default();
    let subuid = subordinate("/etc/subuid", &name, uid);
    let subgid = subordinate("/etc/subgid", &name, gid);

    let sh = cstr("/bin/sh");
    let argv_s = [cstr("sh"), cstr("-c"), cstr(script)];
    let mut argv: Vec<*const c_char> = argv_s.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp_s = [cstr("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), cstr("LC_ALL=C")];
    let mut envp: Vec<*const c_char> = envp_s.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    let (up_r, up_w) = pipe();
    let (go_r, go_w) = pipe();
    let root = cstr("/");
    let host = b"nsmtest";
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };

    // SAFETY: between fork and exec the child only makes async-signal-safe system calls
    // on memory prepared above, then execs or _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::close(go_w);
            libc::close(up_r);
            let flags =
                libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;
            if libc::unshare(flags) != 0 {
                libc::_exit(120);
            }
            libc::write(up_w, b"u".as_ptr().cast(), 1);
            let mut b = [0u8; 1];
            if libc::read(go_r, b.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(121);
            }
            let none = std::ptr::null::<c_char>();
            if libc::mount(none, root.as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                libc::_exit(122);
            }
            for (src, dst) in binds {
                if libc::mount(src.as_ptr(), dst.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0 {
                    libc::_exit(123);
                }
            }
            if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
                libc::_exit(124);
            }
            if libc::sethostname(host.as_ptr().cast(), host.len()) != 0 {
                libc::_exit(130);
            }
            // Set after the credential changes, which clear it. The test thread may
            // already be gone.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
                libc::_exit(128);
            }
            let init = libc::fork();
            if init < 0 {
                libc::_exit(125);
            }
            if init == 0 {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    libc::_exit(129);
                }
                for (i, fd) in stdio.iter().enumerate() {
                    libc::dup2(*fd, i as c_int);
                }
                libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            libc::close(up_w);
            let mut st: c_int = 0;
            libc::waitpid(init, &mut st, 0);
            libc::_exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 126 });
        }
    }
    // SAFETY: closing our copies of the child's ends.
    unsafe {
        libc::close(go_r);
        libc::close(up_w);
    }
    let mut b = [0u8; 1];
    // SAFETY: reading one byte into b.
    let n = unsafe { libc::read(up_r, b.as_mut_ptr().cast(), 1) };
    assert_eq!(n, 1, "sandbox child failed before unshare");
    for (tool, host, sub) in [("newuidmap", uid, subuid), ("newgidmap", gid, subgid)] {
        let st = Command::new(tool)
            .arg(pid.to_string())
            .args(["0", &host.to_string(), "1", "1", &sub.to_string(), "65536"])
            .status()
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(st.success(), "{tool} failed");
    }
    // SAFETY: writing one byte from a static buffer, then closing.
    unsafe {
        libc::write(go_w, b"g".as_ptr().cast(), 1);
        libc::close(go_w);
        libc::close(up_r);
    }
    pid as u32
}

/// waitpid with a timeout; the status as text.
fn wait(pid: u32, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let mut st: c_int = 0;
        // SAFETY: st is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid as i32, &mut st, libc::WNOHANG) };
        if r == pid as i32 {
            return if libc::WIFEXITED(st) { format!("exit {}", libc::WEXITSTATUS(st)) } else { "killed".into() };
        }
        if Instant::now() > deadline {
            // SAFETY: killing and reaping our own child; its death takes the pid
            // namespace with it.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, &mut st, 0);
            }
            return "timeout".into();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Shell-quote a word.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The pid-1 script.
fn script(case: &Case, r: &Path) -> String {
    let r = r.display();
    let args: Vec<String> = case.args.iter().map(|a| q(a)).collect();
    let env: Vec<String> = case.env.iter().map(|a| q(a)).collect();
    let mut s = format!(
        r#"set -u
R={r}
mount -t proc proc /proc || exit 90
mount -t tmpfs -o mode=755 tmpfs /run || exit 91
ip link set lo up || exit 92
# /etc: links to the host's files, then the case's own.
mkdir -p "$R/hostetc" && mount --bind /etc "$R/hostetc" || exit 93
mount -t tmpfs -o mode=755 tmpfs /etc || exit 94
for f in "$R"/hostetc/* "$R"/hostetc/.[!.]*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  if [ -L "$f" ]; then cp -P "$f" /etc/; else ln -s "$f" /etc/; fi
done
(cd "$R/etc" && find . -type d | while read d; do mkdir -p "/etc/$d"; done
 find . -type f | while read f; do rm -f "/etc/$f"; cp "$f" "/etc/$f"; done) || exit 95
mount --bind "$R/nfs" /var/lib/nfs || exit 96
: >"$R/out/nsm_local_state"; : >"$R/out/nlm_end_grace"; : >"$R/out/nlm_tcpport"; : >"$R/out/nlm_udpport"
[ -e /proc/sys/fs/nfs/nsm_local_state ] && mount --bind "$R/out/nsm_local_state" /proc/sys/fs/nfs/nsm_local_state
[ -e /proc/fs/lockd/nlm_end_grace ] && mount --bind "$R/out/nlm_end_grace" /proc/fs/lockd/nlm_end_grace
[ -e /proc/sys/fs/nfs/nlm_tcpport ] && mount --bind "$R/out/nlm_tcpport" /proc/sys/fs/nfs/nlm_tcpport
[ -e /proc/sys/fs/nfs/nlm_udpport ] && mount --bind "$R/out/nlm_udpport" /proc/sys/fs/nfs/nlm_udpport
(cd "$R/state" && find . -type d | while read d; do mkdir -p "/var/lib/nfs/$d"; done
 find . -type f | while read f; do cp "$f" "/var/lib/nfs/$f"; done) || exit 97
"#
    );
    let statd = case.prog == "rpc.statd";
    if statd {
        // Before the case's setup, which may replace it.
        s.push_str(
            r#"[ -e /usr/sbin/sm-notify ] && mount --bind "$R/bin/sm-notify" /usr/sbin/sm-notify
"#,
        );
    }
    for l in &case.setup {
        s.push_str(l);
        s.push('\n');
    }
    if case.rpcbind {
        s.push_str(
            r#"
/sbin/rpcbind -f >"$R/out/rpcbind" 2>&1 &
RBPID=$!
"#,
        );
    }
    let launch = if statd {
        r#"mkfifo "$R/out/finish"
(env LD_PRELOAD="$R/bin/faketime.so" TEST_FAKETIME="$R/faketime" TEST_VIRTUAL_POLL={poll} {env} "$R/bin/{prog}" {args}) >"$R/out/stdout" 2>"$R/out/stderr" </dev/null &
wait $!
echo "exit $?" >"$R/out/status"
: >"$R/out/launched"
read x <"$R/out/finish""#
    } else {
        r#"(env LD_PRELOAD="$R/bin/faketime.so" TEST_FAKETIME="$R/faketime" TEST_VIRTUAL_POLL={poll} {env} "$R/bin/{prog}" {args}) >"$R/out/stdout" 2>"$R/out/stderr" </dev/null
echo "exit $?" >"$R/out/status""#
    };
    s.push_str(&format!(
        r#"
mkfifo "$R/out/ready"
"$R/bin/nsmprobe" <"$R/probe.in" >"$R/out/peers" 2>&1 &
PPID_=$!
read x <"$R/out/ready"
{launch}
pids() {{ for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = "{comm}" ] && echo ${{p#/proc/}}; done; }}
j=0
while [ -n "$(pids)" ] && [ $j -lt 3000 ]; do sleep 0.01; j=$((j+1)); done
if [ -n "$(pids)" ]; then
  echo "daemon still running" >>"$R/out/status"
  for p in $(pids); do kill -KILL $p; done
fi
: >"$R/out/stop"
wait $PPID_
(cd /var/lib/nfs && find . -mindepth 1 | sort | while read f; do
  echo "$(stat -c '%A %U %G %s' "$f") $f"
  [ -f "$f" ] && od -An -c "$f"
done) >"$R/out/state" 2>&1
(cd /run && for f in *; do [ -e "$f" ] && echo "$(stat -c '%A %U %G' "$f") $f: $(cat "$f" 2>/dev/null)"; done) >"$R/out/run" 2>&1
# Give everything back to the sandbox's root (the invoking user), so it can be removed.
chown -R 0:0 "$R/nfs" "$R/out" 2>/dev/null
chmod -R u+rwX "$R/nfs" 2>/dev/null
exit 0
"#,
        launch = launch
            .replace(
                "\"$R/bin/{prog}\"",
                if std::env::var_os("NFSUTILS_STRACE").is_some() {
                    "strace -f -tt -o \"$R/out/strace\" \"$R/bin/{prog}\""
                } else {
                    "\"$R/bin/{prog}\""
                },
            )
            .replace("{poll}", &case.poll_ms.to_string())
            .replace("{env}", &env.join(" "))
            .replace("{prog}", &case.prog)
            .replace("{args}", &args.join(" ")),
        comm = case.prog.chars().take(15).collect::<String>(),
    ));
    if case.rpcbind {
        s = s.replace("\nexit 0\n", "\nkill $RBPID 2>/dev/null; wait $RBPID 2>/dev/null\nexit 0\n");
    }
    s
}

/// Remove a previous run's directory. Files a sandbox left owned by its other users
/// are given back first, from a sandbox.
fn clean(t: &Path) {
    if !t.exists() || std::fs::remove_dir_all(t).is_ok() {
        return;
    }
    let null = std::fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let fd = null.as_raw_fd();
    let script = format!("chown -R 0:0 {p} && chmod -R u+rwX {p}", p = q(t.to_str().unwrap()));
    let pid = spawn_in_sandbox(&[], &script, [fd, fd, fd]);
    wait(pid, Duration::from_secs(30));
    std::fs::remove_dir_all(t).unwrap_or_else(|e| panic!("can't clean {}: {e}", t.display()));
}

/// A syslog datagram, normalized: `<pri>` kept, the time stamp dropped, `[pid]` replaced.
fn render_syslog(msg: &[u8]) -> String {
    let s = String::from_utf8_lossy(msg).to_string();
    let Some(end) = s.find('>') else { return s };
    let (pri, rest) = s.split_at(end + 1);
    // "Mmm dd hh:mm:ss " is 16 bytes.
    let rest = rest.get(16..).unwrap_or(rest);
    let rest = match (rest.find('['), rest.find("]: ")) {
        (Some(a), Some(b)) if a < b => format!("{}[@PID@]{}", &rest[..a], &rest[b + 1..]),
        _ => rest.to_string(),
    };
    format!("{pri}{rest}")
}

fn read(t: &Path, f: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(t.join(f)).unwrap_or_default()).to_string()
}

/// Write `files` under `dir`.
fn write_files(dir: &Path, files: &[(String, Vec<u8>)]) {
    std::fs::create_dir_all(dir).unwrap();
    for (p, c) in files {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, c).unwrap();
    }
}

/// Run one implementation of the case's program.
pub fn run(case: &Case, bins: &[(&str, PathBuf)], label: &str) -> Outcome {
    let base = workspace_dir().join("target/difftest").join(&case.name);
    let t = base.join(label);
    clean(&t);
    for d in ["bin", "out", "nfs"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    // Hard links, not copies: a copy is open for writing for a moment, and a parallel
    // test's fork() in that moment makes exec fail with ETXTBSY.
    let link = |src: &Path, dst: &str| {
        let d = t.join(dst);
        if std::fs::hard_link(src, &d).is_err() {
            std::fs::copy(src, &d).unwrap();
        }
    };
    for (name, bin) in bins {
        link(bin, &format!("bin/{name}"));
    }
    link(&probe_binary(), "bin/nsmprobe");
    link(&shim(), "bin/faketime.so");
    std::fs::write(t.join("faketime"), format!("{EPOCH:020} 000000000\n")).unwrap();
    // The programs move the clock after dropping privileges.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(t.join("faketime"), std::fs::Permissions::from_mode(0o666)).unwrap();
    write_files(&t.join("etc"), &case.etc);
    write_files(&t.join("state"), &case.state);
    let root = fixed_root();
    let mut probe: Vec<String> = case.peers.iter().map(|l| format!("peer {l}")).collect();
    if case.rpcbind {
        probe.insert(0, "await-rpcbind".into());
    }
    let at_t = |l: &String| l.replace("@T@", root.to_str().unwrap());
    probe.extend(case.before.iter().map(at_t));
    probe.push(format!("ready {}/out/ready", root.display()));
    if case.prog == "rpc.statd" {
        probe.push(format!("await-statd {}/out/launched", root.display()));
        probe.extend(case.probe.iter().map(at_t));
        probe.push(format!("finish {}/out/finish", root.display()));
    }
    probe.push(format!("serve {}/out/stop", root.display()));
    std::fs::write(t.join("probe.in"), probe.join("\n") + "\n").unwrap();

    let binds = vec![(path_c(&t), path_c(&root))];
    let devlog = t.join("devlog");
    let log = UnixDatagram::bind(&devlog).unwrap();
    log.set_nonblocking(true).unwrap();
    let mut binds = binds;
    binds.push((path_c(&devlog), cstr("/dev/log")));

    let err = std::fs::File::create(t.join("out/sandbox")).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let pid = spawn_in_sandbox(&binds, &script(case, &root), [null.as_raw_fd(), err.as_raw_fd(), err.as_raw_fd()]);
    let st = wait(pid, Duration::from_secs(120));
    assert_eq!(st, "exit 0", "{}/{label}: sandbox {st}:\n{}", case.name, read(&t, "out/sandbox"));

    let mut syslog = Vec::new();
    let mut buf = vec![0u8; 65536];
    while let Ok(n) = log.recv(&mut buf) {
        let m = render_syslog(&buf[..n]);
        // The sandbox's rpcbind is the same in both runs.
        if !m.contains("> rpcbind[") && !m.contains(">rpcbind[") {
            syslog.push(m);
        }
    }
    let peers = read(&t, "out/peers");
    assert!(peers.ends_with("probe done\n"), "{}/{label}: the probe failed:\n{peers}", case.name);
    let fix = |s: String| s.replace(root.to_str().unwrap(), "@T@");
    Outcome {
        status: read(&t, "out/status").trim().to_string(),
        stdout: fix(read(&t, "out/stdout")),
        stderr: fix(read(&t, "out/stderr")),
        syslog: syslog.into_iter().map(fix).collect(),
        peers,
        state: read(&t, "out/state"),
        run: read(&t, "out/run"),
        kernel: format!(
            "nsm_local_state={:?} nlm_end_grace={:?} nlm_tcpport={:?} nlm_udpport={:?}",
            read(&t, "out/nsm_local_state"),
            read(&t, "out/nlm_end_grace"),
            read(&t, "out/nlm_tcpport"),
            read(&t, "out/nlm_udpport")
        ),
    }
}

/// Run both and compare; returns the C outcome.
pub fn check(case: Case) -> Outcome {
    let (c_bins, r_bins) = match case.prog.as_str() {
        "sm-notify" => (vec![("sm-notify", reference_binary("sm-notify"))], vec![("sm-notify", rust_sm_notify())]),
        "rpc.statd" => (
            vec![("rpc.statd", reference_binary("statd")), ("sm-notify", reference_binary("sm-notify"))],
            vec![("rpc.statd", rust_statd()), ("sm-notify", rust_sm_notify())],
        ),
        p => panic!("unknown program {p}"),
    };
    let c = run(&case, &c_bins, "c");
    let r = run(&case, &r_bins, "r");
    if std::env::var_os("NFSUTILS_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{c:#?}", case.name);
    }
    compare(&case.name, &c, &r);
    c
}

fn compare(name: &str, c: &Outcome, r: &Outcome) {
    if c != r {
        let mut msg = format!("case {name} differs:\n");
        macro_rules! field {
            ($f:ident) => {
                if c.$f != r.$f {
                    msg.push_str(&format!("--- {}\n  C:    {:?}\n  Rust: {:?}\n", stringify!($f), c.$f, r.$f));
                }
            };
        }
        field!(status);
        field!(stdout);
        field!(stderr);
        field!(syslog);
        field!(peers);
        field!(state);
        field!(run);
        field!(kernel);
        panic!("{msg}");
    }
}
