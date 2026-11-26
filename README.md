# nfs-utils-rs

A drop-in port/reimplementation of the NFS client's helper daemons from nfs-utils, in
Rust: `rpc.statd` and `sm-notify` (NSM, the lock-recovery side of NFSv3), and
`rpc.idmapd`, `nfsidmap` and `libnfsidmap` (NFSv4 id mapping). Currently just something
fun for me to tinker with in Claude, and the follow-on to
[rpcbind-rs](https://github.com/scottfk/rpcbind-rs).

## Goals

- **Drop-in compatible with nfs-utils 2.8.5** (Gentoo's `net-fs/nfs-utils`), for the
  programs it covers: the same options, `/etc/nfs.conf` and `/etc/idmapd.conf` handling,
  messages, syslog lines and exit statuses; the same files under `/var/lib/nfs` (`state`,
  `sm/`, `sm.bak/`, with their owners, modes and contents); the same RPC registrations;
  byte-for-byte the same replies to every NSM request, malformed ones included, and the
  same `SM_NOTIFY` calls to peers and to the kernel's lockd; the same id-mapping answers.
  Upstream quirks are reproduced on purpose and listed in QUIRKS.md. Improvements come
  later, as deliberate changes.
- **No libtirpc.** `rpc.statd` is a root-started daemon that parses untrusted network
  input. Its XDR, RPC messages, transports and `/etc/netconfig` come from the `tirpc` crate
  of rpcbind-rs, which reimplements the parts of libtirpc 1.3.7 that show on the wire or
  in messages, and gets more of it here (server registration, the select-based loop).
- **Linux only.**
- **Small and boring:** `libc` as the only outside crate dependency, no async, and
  `unsafe` confined to `sys` modules.

The rest of nfs-utils (`mount.nfs`, `rpc.mountd`, `rpc.nfsd`, `exportfs`, `nfsdcld`, the
GSS daemons, ...) is out of scope and stays C.

## Status

Phases 1 to 5 are done. `sm-notify` (PR #2) and `rpc.statd` (PR #3) are ported and
merged, with the shared support code under them, phase 3 (PR #4) put both through
hostile input, and phase 4 (PR #5) ported `libnfsidmap`, with its three methods built
in, and `nfsidmap`. Phase 5 (branch `phase5-idmapd`, PR #6) ports `rpc.idmapd`, with
the parts of libevent it uses. They give the same results as C in all 60 sm-notify, 74
statd, 27 hostile-input, 41 libnfsidmap, 59 nfsidmap and 59 rpc.idmapd differential
cases. Next: phase 6 (packaging, and the rehearsal on the test VM).

Phase 1, groundwork and `sm-notify`:

- `crates/support`: `xlog.c` (stderr and syslog, debug facilities, the `SIGUSR1` and
  `SIGUSR2` toggles), the reading side of `conffile.c` (`/etc/nfs.conf`, `/usr/etc`,
  the `.d` directories in version order, `include`, sections and subsections, quotes,
  continuations, `$name` values, every parse warning, and the hash buckets and
  transaction queue whose order decides overrides), `support/nsm/file.c` (the `state`
  file, retiring `sm/` to `sm.bak/`, reading, adding and removing records with
  `sscanf()`'s and `fgets()`'s behavior, the privilege drop), `support/nsm/rpc.c` (the
  hand-built `PMAPPROC_GETPORT`, `RPCBPROC_GETADDR`, `SM_NOTIFY` and NLM calls, reply
  parsing), and the path and universal-address helpers;
- `sm-notify.c`: options and `[sm-notify]` settings, the pid file, `-v` names checked
  with `getnameinfo()`, the IPv6 socket that also reaches IPv4 peers, the reserved
  port, the notify list in send order, at most ten calls at once, exponential backoff
  up to two minutes, a fresh port lookup and the next address after four tries (C
  drops the first address instead of rotating it; see [QUIRKS.md](QUIRKS.md)), the
  retry without the domain, giving up after `-m` minutes, and `daemon()`.
- In rpcbind-rs ([PR #11](https://github.com/scottfk/rpcbind-rs/pull/11)): `tirpc`
  gained `bindresvport_sa()` at a given address and public reply decoding, and a fix
  for the reserved port picked for pids over 65535.

Phase 2, `rpc.statd`:

- `statd.c`: options and `[statd]`/`[lockd]` settings, `RPC_STATD_NO_NOTIFY`, the
  check for a running statd (`nfs_probe_statd()`: a portmap lookup and a NULL call,
  from `getport.c` and `rpc_socket.c`), lockd's ports through `/proc`, `daemon_init()`
  and `daemon_ready()` (`mydaemon.c`, `closeall.c`), the pid file, running sm-notify
  (and `-N`), unregistering, the privilege drop, and the signal handlers and exit
  handlers in C's order;
- `svc_create.c`: a listener on each visible `/etc/netconfig` transport, at `-p`, the
  services database's port, or a random one, registered with rpcbind;
- `monitor.c`, `stat.c`, `simu.c`, `callback.c` and the rpcgen dispatcher: `SM_MON`,
  `SM_UNMON`, `SM_UNMON_ALL`, `SM_STAT`, `SM_SIMU_CRASH` and `SM_NOTIFY`, with the
  loopback and reserved-port checks, name checks, the static results, the records, and
  `-H` callouts;
- `hostname.c` (canonical names and matching by name or address), `notlist.c` (the
  linked lists, as C links them), `rmtcall.c` (the callback socket, the port lookup and
  NLM callbacks with five tries) and `svc_run.c` (the `select()` loop);
- In rpcbind-rs ([PR #12](https://github.com/scottfk/rpcbind-rs/pull/12)): `tirpc`
  gained `svc_tli_create()` with its own socket, `svc_reg()` registering with rpcbind,
  `rpcb_set()`, and `svc_fdset`/`svc_getreqset()`.

Phase 3, hostile input (tests only; the port needed no changes):

- malformed calls: `SM_MON` cut at every field over UDP (completed from the
  transport's buffer) and TCP, the other procedures cut short, strings at and past
  `SM_MAXSTRLEN` and absurd lengths, bad RPC headers (a reply, RPC version 3,
  `AUTH_SYS` and unknown credentials, credentials over 400 bytes, short, empty and
  oversized messages), and record marking (fragments, zero-length and oversized
  records, half records);
- hostile names: canonical names from the resolver that are `..`, `.`, `a/b`, format
  directives, 300 bytes long, `sm.bak` or `-rf` (records are named after them),
  records with such names loaded at startup, control characters, high bytes, quotes
  and shell syntax in `mon_name` and `my_name`, and hostile `SM_NOTIFY` names passed
  to an ha-callout;
- `SM_NOTIFY` floods (twenty state changes against a silent lockd, fifty repeats, forty
  sources) and spoofed senders, and callback replies from another port, another
  address, or garbage; in sm-notify, replies from another address;
- the state directory read-only, on a read-only mount, out of space or inodes, and
  records that are directories, symlinks, or hold a NUL;
- connection floods: past the descriptor limit (32, and statd's own cap of 1024) on a
  stopped clock, where descriptors run out and name lookups fail; the idle sweep on a
  moving clock, which holds statd at 820; and connections holding half a record.

The probe gained persistent TCP connections (`conn`, `send`, `recv`, `alive`,
`close`), spoofed replies (`ACTION@ADDR`), a clock step and a descriptor count; cases
can set a descriptor limit and collapse a busy loop's repeated log lines. Three
mutants (no `/` check on record names, the record appended at the end instead of at
a NUL, callback replies taken from any address) each fail a case.

The statd suite has 74 cases: options and usage, bad ports, `nfs.conf` (ports, name,
`no-notify`, `ha-callout`, state directory, debug to syslog), lockd's ports, starting
and stopping (fixed, random and privileged ports, no rpcbind, already running, a stale
registration, daemon mode, `sm/` owned by root, records loaded at startup, sm-notify
run with `-p`/`-v` or failing to run), each procedure from lockd, from remote hosts
and over TCP (duplicates, new cookies, aliases and addresses, IPv6, unknown hosts,
bad names, white space and NULs in names), callbacks (by name and by address, two
monitors, lockd unregistered, silent or answering with an error), ha-callouts,
`SM_SIMU_CRASH`, `SIGUSR1`/`SIGUSR2`/`SIGHUP`/`SIGTERM`, and odd calls (unknown
procedure, version or program, garbage arguments). The rpcbind table is compared
after start and after exit. Mutating five behaviors that C has and the port copies
(the stale `SM_UNMON_ALL` result, the try count, the state check before callbacks, the
callout message, the white space fix) each fails a case.

The sm-notify suite has 60 cases, all passing: options and usage, the state
directory (missing, relative, read-only, `state` as a directory, short and even
`state` files, `sm/` owned by root or missing), records (malformed, hex variants, a
short line reading the line before it, long lines, bad file names, two records in one
file), peers over IPv4 and IPv6 (lookups answered, refused, unregistered, with bad
ports or addresses; silent peers and statds; two and three addresses; unknown names; twelve
peers at once; denied, failed, garbage, short and spoofed replies), `-v` and `-p`, and
`nfs.conf` (settings, errors, includes, `nfs.conf.d`, environment values,
continuations, debug facilities). Five mutants that undo reproduced quirks are
caught: list fields trimmed, the parser's NUL not left for the next line, ties in the
notify list not broken by age, the name cut at its last dot, and `0x` not taken.

Phase 4, `libnfsidmap` and `nfsidmap`:

- `crates/nfsidmap` (`support/nfsidmap`): `libnfsidmap.c` (setup, the default domain
  from `Domain` or else DNS: the host's name, then the `_nfsv4idmapdomain` TXT record
  parsed as C parses it; loading the `Method` and `GSS-Methods` lists; the calls run
  through the methods in order until one doesn't say `-ENOENT`; owners as numbers and
  `nobody`), `nfsidmap_common.c` (`Local-Realms`, `No-Strip`, `Reformat-Group`), and
  the `nsswitch`, `static` and `regex` methods, each with its own copy of the
  configuration as C's plugins have. User and group lookups, `getgrouplist()`, the
  resolver and POSIX regular expressions are glibc's, called directly. It is a Rust
  library with no C ABI: on hydra only `rpc.idmapd` and `nfsidmap` link
  `libnfsidmap.so.1`.
- `nfsidmap.c`: answering `uid:`, `gid:`, `user:` and `group:` keys (with the clear and
  retry when the keyring is full), `-t`, `-v`, `-c`, `-l`, `-u`/`-g`/`-r` and `-d`, and
  libkeyutils' calls as it makes them, its `/proc/keys` search included.

The libnfsidmap suite (41 cases) drives the library's calls through two small drivers,
one over each library: the default domain (configured, from the host's name, from TXT
records good, odd and malformed, before setup, too long), setup (twice, after
`term`, a missing file, realms, `Nobody-User`/`Nobody-Group`), the method lists
(unknown names, order, repeats, empty, GSS methods, a failed setup retried), and each
method's mappings (`No-Strip` and `Reformat-Group`, name forms, buffer lengths, big
entries, principals and group lists; `static` sections and environment values;
`regex` prefixes and suffixes, and the settings that crash it), with the library's
log at each level. The nfsidmap suite (59 cases) covers each key type, owners as
numbers and `nobody`, names too long, bad key descriptions and argument counts,
options and usage, not running as root, full keyrings, failed key calls, and `-c`,
`-l`, `-u`/`-g`/`-r` and `-d` against fake keyrings. Seven mutants (the domain split
at the first `@`, the method list not moving on, `0` taken for any owner, `ENFILE` not
a full keyring, a TXT name not skipped, the whole regex match taken, the first static
mapping taken) each fail a case.

Phase 5, `rpc.idmapd`:

- `idmapd.c` (`crates/idmapd/src/idmapd/main.rs`): both passes over the options, the
  deprecated `-c` and the `[General]`/`[Mapping]` settings from `nfs.conf` and
  `idmapd.conf`, `daemon_init()`, nfsd's two channels under `/proc/net/rpc` (text
  upcalls with `\ooo` escapes, answers with an expiry, the cache flush), the NFS
  client's `idmap` pipes under `rpc_pipefs/nfs/clnt*` (binary `struct idmap_msg`s,
  answered in place), the scans by inotify, one-shot watches for pipes not there yet,
  `SIGUSR1`/`SIGUSR2`/`SIGHUP`/`SIGTERM`/`SIGINT`, and the client cache timeout;
- what it uses of libevent 2.1 (`ev.rs`): the epoll backend, with its descriptors
  opened in the same order (descriptor numbers matter here: the `SIGUSR1` rescan reads
  descriptor 10, see QUIRKS.md), its `epoll_ctl()` calls and warnings, the signal
  self-pipe, timers due at once, the order ready events run in, `loopexit`, and its
  errors when descriptors run out.

The suite (59 cases) runs the program in the background while the probe plays the
kernel: options and usage, `-c` (missing, a directory, twice), the settings and where
each is read from, `-p` up to and past `PATH_MAX`, unknown `nobody` users and groups in
the foreground and as a daemon, a failing method, verbosity, cache expiries, server-
and client-only modes and their signals, nfsd's channels (present, half present,
without flush files, reset, at end of file, reopened by `SIGHUP`), nfsd's upcalls
(each direction and type, failures and `nobody`, escapes and bad escapes, bad and
missing fields, field and answer lengths, no newline, odd ids), the client's messages
(lookups, unknown conversions and types, bytes after the name, 127- and 128-byte
names, a reset pipe), and the scans (new clients, removed ones, the order, odd
entries, a regular file for a pipe, waiting for a pipe, long names, the pipefs
directory removed, `SIGUSR1` reading descriptor 10 in the layouts where that blocks
and where it doesn't, forty clients), with the program's descriptors compared after
each step. Ten mutants (the first scan not run at once, the signal number not passed as the descriptor, an escape moving on three bytes, the room check for an escape, the NUL check on the name itself, a 30-byte client id, both nfsd channels always opened, `LOOKUPFAIL` left alone, libevent's warning text, and the expiry written for any non-zero value) each fail a case.

The plan and its status live in the [roadmap](#roadmap) below, which is updated as each
step lands.

The reference is the `nfs-utils-2.8.5` release tarball, built as Gentoo's
`net-fs/nfs-utils-2.8.5-r1` builds it ([tools/build-reference.sh](tools/build-reference.sh)),
against the system libtirpc 1.3.7, libevent 2.1 and keyutils:

- USE="-caps -junction -kerberos -ldap +libmount -nfsdctl +nfsv3 +nfsv4 -sasl -selinux
  -tcpd +uuid": no capabilities, no TCP wrappers, no LDAP or GUMS id mapping, no GSS;
- state directory `/var/lib/nfs`, id-mapping plugins in `/usr/lib64/libnfsidmap`;
- `/sbin/rpc.statd`, `/sbin/sm-notify`, `/usr/sbin/rpc.idmapd`, `/usr/sbin/nfsidmap`,
  `libnfsidmap.so.1` and its `nsswitch`, `static` and `regex` plugins.

The reference build imports exactly the same libc, libtirpc, libevent and keyutils
symbols as the installed programs and plugins, and `libnfsidmap.so` exports the same
symbols as the installed one.

How hydra uses these today: `rpcbind`, `nfsclient` and `autofs` are in the default
runlevel; `nfsclient` runs `sm-notify` and needs `rpc.statd` (started with
`--no-notify`, running as `nobody`, the owner of `/var/lib/nfs/sm`) and `rpc.idmapd`;
the kernel calls `nfsidmap` through request-key for NFSv4 id lookups.

## Layout

Upstream's code for these programs is about 9,000 lines of C, plus the parts of
`support/` they use. The port follows the files (packaging is still to come):

| Path | What |
|---|---|
| `crates/support/` | the shared parts of nfs-utils' `support/`: `xlog.c`, `conffile.c` (`nfs.conf`, includes and `nfs.conf.d`), `support/nsm/file.c` (the state file, monitor records, privilege drop) and `support/nsm/rpc.c` (NSM calls built by hand), and the bits of `support/misc` and `support/nfs` they need |
| `crates/support/src/sys.rs` | every libc call |
| `crates/statd/` | `utils/statd`: `sm-notify` (`src/sm_notify.rs`) and `rpc.statd` (`src/statd/`: `statd.c` and `svc_run.c` in `main.rs`, `monitor.c` with `stat.c`, `simu.c` and `callback.c`, `notlist.c`, `rmtcall.c`, `hostname.c`); the binary is built as `statd` and installed as `rpc.statd` |
| `crates/nfsidmap/` | `support/nfsidmap`: the library and its `nsswitch`, `static` and `regex` methods |
| `crates/idmapd/` | `utils/nfsidmap/nfsidmap.c` (`src/nfsidmap.rs`) and `utils/idmapd/idmapd.c` (`src/idmapd/`: `main.rs`, and `ev.rs` for libevent); the binary is built as `idmapd` and installed as `rpc.idmapd` |
| `crates/statd/tests/` | differential tests and the harness (adapted from rpcbind-rs); `nsmprobe/` is the fake-peer tool |
| `crates/idmapd/tests/` | the id-mapping differential tests (with the harness from `crates/statd/tests/`), the fake keyring (`shim/fakekeys.c`) and kernel channels (`shim/fakepipes.c`), and the C library driver (`tools/idmaptest.c`; `tools/idmaptest.rs` is the Rust one) |
| `contrib/gentoo/` | packaging |
| `tools/` | the reference build, and the checks run on the test VM |

The `tirpc` crate comes from rpcbind-rs as a git dependency pinned to a commit. What
`rpc.statd` needs that rpcbind didn't (`svc_create()`-style registration with rpcbind,
`pmap_unset()`, `svc_getreqset()`, `rpc_control()`) goes into rpcbind-rs first, as its own
PR, so rpcbind's differential suite keeps checking it.

## Testing

```sh
make check
```

This builds the C reference into `../nfs-utils` if it isn't there, then runs the unit
tests and the differential suites ([crates/statd/tests/](crates/statd/tests/) and
[crates/idmapd/tests/](crates/idmapd/tests/)). As in
rpcbind-rs, each case runs the C program and then the port in a private user, mount,
network, pid and UTS namespace (ids mapped from your subordinate ranges, so there's a
real root and `nobody` exists), with its own loopback, `/run`, `/var/lib/nfs` (with
the case's records), `/etc` (links to the host's files, plus the case's `hosts`,
`nfs.conf` and `nfs.conf.d`), `/dev/log` captured, and regular files bound over
`/proc/sys/fs/nfs/nsm_local_state` and `/proc/fs/lockd/nlm_end_grace`. It compares:

- every call the program makes, which fake peers record byte for byte with the source
  address and port (`nsmprobe`: scripted rpcbind and statd answers, from refusals and
  garbage to silence);
- stdout, stderr, the exit status and every syslog line (time stamps and pids
  normalized);
- the files under `/var/lib/nfs` and `/run` (names, modes, owners, contents), and what
  was written to the kernel's files.

The programs run on a fake clock (the LD_PRELOAD shim in `crates/statd/tests/shim/`)
whose `poll()` timeouts pass at once, so fifteen minutes of retries take a moment. The
script forks the same processes in the same order every time, so pids, and with them
the xids and reserved ports, come out the same in both runs; the probe answers in the
order calls arrived. To see what each case produced:
`NFSUTILS_DIFF_SHOW=1 cargo test -- --nocapture`. Each run's files stay in
`target/difftest/<case>/{c,r}/`.

For `rpc.statd` the sandbox adds the system's rpcbind (rpcbind-rs on hydra, the same
in both runs) and the implementation's own sm-notify; the probe stands in for lockd
(registered with rpcbind, answering callbacks), sends the SM calls, signals statd once
it's idle in `select()`, and dumps rpcbind's table. The clock's `select()` timeouts pass
at once too. For the hostile-input cases the probe also holds TCP connections open
(hundreds at once, half records, records split oddly), sends replies from other
addresses, steps the clock, and counts statd's descriptors.

For id mapping the sandbox has its own `passwd`, `group`, `hosts`, `nsswitch.conf`,
`resolv.conf` (pointing at a fake DNS server in the probe, which logs every query) and
`idmapd.conf`. The C runs load the reference `libnfsidmap.so.1` and have its plugins
bound over `/usr/lib64/libnfsidmap` (which must exist on the host). Keys can't come
from the kernel in a sandbox, so a second LD_PRELOAD shim (`crates/idmapd/tests/shim/`)
answers libkeyutils' and the port's `keyctl()` and `request_key()` calls from a file of
fake keys, with failures injected on request, and logs each call for comparison;
`/proc/keys` is a file bound over it.

For `rpc.idmapd` the probe plays the kernel. nfsd's channels and the client's pipes are
Unix `SOCK_SEQPACKET` sockets the probe listens on, at the paths the program opens: a
third LD_PRELOAD shim (`crates/idmapd/tests/shim/fakepipes.c`) turns a read-write
`open()` of a socket into a connection to it (a regular file or a FIFO can't stand in:
epoll refuses the one, and the other hands the program its own answer back), and moves
`/proc/net/rpc`, which can't be mounted over, to a directory of the run. The probe
makes the `rpc_pipefs` tree (client directories, pipes, odd entries), sends upcalls
and messages and logs the answers, closes and resets connections, signals the program,
and lists its descriptors. After each step it waits until the program has handled it:
woken (its count of voluntary context switches moved) and back in `epoll_wait()`, or
else blocked somewhere, which is logged. A file is bound over
`/proc/sys/fs/nfs/idmap_cache_timeout`, and the cache flush files are compared.

## Roadmap

1. **Groundwork and sm-notify (done, PR #2):** the workspace and the `tirpc` dependency;
   `crates/support` (`xlog`, `nfs.conf` parsing, `support/nsm`); the test harness; and
   `sm-notify`: options and `[sm-notify]` settings, the state number bump, the lock and
   the `-f` check, privilege drop, the `sm` to `sm.bak` move, and the `SM_NOTIFY` calls
   (address lookup, `PMAPPROC_GETPORT` and retries with backoff, `-m`, `-n`, `-p`,
   `-v`, `-P`, `-d`), against fake peers.
2. **rpc.statd (done, PR #3):** startup (options, `[statd]` settings, `-p`/`-o` ports,
   `-n`, `-P`, `-H` ha-callout, `-T`/`-U` lockd ports, `-N`, `-F`/`-d`, the pid file,
   the privilege drop to the `sm/` owner, unregistering stale entries, running
   `sm-notify` unless `--no-notify`), and the protocol: `SM_STAT`, `SM_MON`,
   `SM_UNMON`, `SM_UNMON_ALL`, `SM_SIMU_CRASH` and `SM_NOTIFY`, with the loopback-only
   checks, `mon_name` validation and the monitor records on disk, the callbacks to lockd
   and the notify list with its retry timer, and `SIGUSR1` (restart the loop and rerun
   sm-notify), `SIGTERM` and `SIGHUP`. The probe stands in for the kernel's lockd, both its
   `SM_MON` calls and the callbacks statd makes to it.
3. **Hostile input (done, PR #4):** malformed and truncated NSM calls, hostile `mon_name`s
   (path tricks, overlong, odd characters), `SM_NOTIFY` floods and spoofed peers, a full
   or read-only state directory, and connection floods on statd's TCP socket.
4. **libnfsidmap and nfsidmap (done, PR #5):** `idmapd.conf` (`[General]`, `[Mapping]`,
   `[Translation]`, `[Static]`, `[Regex]`), the default domain (from `Domain`, else DNS),
   the `nsswitch`, `static` and `regex` methods built in, `Local-Realms`, and the
   `nfsidmap` request-key helper (`-t`, `-c`, `-l`, `-r`, `-u`, `-g`, `-d`) with its
   keyring writes, against the C library and helper.
5. **rpc.idmapd (done, PR #6):** the `rpc_pipefs` client directories found by `inotify`, the
   upcall and downcall formats, the nfsd channels under `/proc/net/rpc` (both missing, as
   on a client, and faked), `-S`/`-C`, `-p`, `-c`, `-U`/`-G`, `-v`, `-f`, the
   `[General]` and `[Mapping]` settings, `SIGUSR1`/`SIGUSR2`/`SIGHUP` rescans, and the
   libevent loop's behavior, against fake pipefs trees.
6. **Packaging (planned):** a Gentoo ebuild and a way to swap these programs in while
   the rest of nfs-utils stays C (nfs-utils is one package, so how to do this is decided
   in this phase), rehearsed on the test VM with rpcbind-rs, a real NFS server and client,
   NFSv3 locks across a server reboot (statd and sm-notify doing lock recovery) and
   NFSv4 id mapping, then rolled back through a binary package of the C build.

Open questions, to settle in the phase where they come up:

- ~~Whether `libnfsidmap.so.1` also needs a C ABI.~~ Settled in phase 4: no. It is a
  Rust library with the three methods built in, since on hydra only `rpc.idmapd` and
  `nfsidmap` link it. A `Method` naming another plugin (`umich_ldap`, `gums`, a
  third-party `.so`) fails the way C fails to `dlopen()` a missing plugin (see
  QUIRKS.md).
- Phase 6's packaging approach (a trimmed nfs-utils ebuild in localrepo that leaves these
  programs to `nfs-utils-rs`, or something else).

Not planned unless needed: the build options hydra doesn't use (capabilities, TCP
wrappers, LDAP and GUMS mapping, GSS principals beyond what `libnfsidmap`'s API passes
through), and the rest of nfs-utils.

## License

GPL-2.0, as nfs-utils (see [LICENSE](LICENSE), upstream's `COPYING`). Some of the ported
files carry their own permissive notices, kept in [LICENSES/](LICENSES/): the University of
Michigan's for `libnfsidmap` and `rpc.idmapd`, and Niklas Hallqvist's and Håkan Olsson's
for `conffile.c`. The `tirpc` crate from rpcbind-rs is BSD-3-Clause.
