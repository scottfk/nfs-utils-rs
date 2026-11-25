# Contributing

Thanks for stopping by. This is a personal project, a Rust port of parts of
[nfs-utils](https://git.linux-nfs.org/?p=steved/nfs-utils.git) (`rpc.statd`, `sm-notify`,
`rpc.idmapd`, `nfsidmap` and `libnfsidmap`) that I tinker with in my spare time, but
contributions are welcome. Here's how things work.

## What this project is

nfs-utils-rs aims to be a **drop-in replacement** for those programs. Given the same
options, configuration files, state directory and requests, each should register the same
RPC services, send the same replies and calls byte for byte, write the same files, log the
same lines and exit the same way. It is not a redesign: if upstream has an odd edge case,
we copy the odd edge case and list it in QUIRKS.md.

The upstream release we track is pinned in `tools/REFERENCE_TAG`, built the way Gentoo
builds it (see the README). Behavior is checked against a build of that release, not
against the man pages, the NSM specification or what seems sensible. Where libtirpc decides
the behavior (XDR, error replies, transports, netconfig), we follow the libtirpc version
the reference links, 1.3.7, through the `tirpc` crate shared with
[rpcbind-rs](https://github.com/scottfk/rpcbind-rs).

The layout follows upstream's sources (`statd.c`, `monitor.c`, `sm-notify.c`,
`libnfsidmap.c` and so on); the README describes it as it grows.

## What's useful to contribute

- **Behavior differences.** If nfs-utils-rs does something different from C nfs-utils at
  the pinned release, that's a bug. Please send the options, the configuration, the state
  directory's contents, the request (a packet capture is ideal), and both results. A new
  differential test case is even better.
- **Quirk fixes, as separate changes.** Fixing something listed in QUIRKS.md is welcome,
  but as its own PR that says which quirk it fixes. Ideally it gets fixed upstream too.
- **Reference bumps.** Moving `tools/REFERENCE_TAG` to a newer upstream release, plus the
  fixes needed so the tests pass again.
- **Documentation.** Corrections or additions, especially install notes for other distros
  and init systems.

## What doesn't fit

- **"Improvements" that change behavior quietly.** New options, changed defaults and nicer
  messages belong upstream in nfs-utils first. Once they ship in a release, we'll match
  them.
- **New dependencies** without a strong reason. The only outside crate is `libc`, and I'd
  like to keep it that way. In particular, the port doesn't link libtirpc or libevent.
- **`unsafe` outside the `sys` modules.** If you need a new syscall, add a safe wrapper
  there.
- **Changes to the `tirpc` crate here.** It lives in rpcbind-rs; send those there.

## Building and testing

You need Rust 1.88 or newer (edition 2024). For the tests you also need a C compiler, the
libtirpc, libevent and keyutils headers and libraries, `rpcgen` and the autotools to build
upstream nfs-utils, unprivileged user namespaces, and a subordinate id range of at least
65536 for your user in `/etc/subuid` and `/etc/subgid` (with `newuidmap`/`newgidmap` from
shadow).

```sh
make                # release build
make reference      # build the C reference at the pinned release into ../nfs-utils
make check          # build the reference if needed and run everything
make clippy         # cargo clippy --all-targets -D warnings
make fmt            # cargo fmt
```

**Before sending a PR, please make sure `make check`, `make clippy` and `make fmt` are
clean.**

### Differential tests

Most testing is done by running the C reference and nfs-utils-rs side by side on the same
input, the way rpcbind-rs and [logrotate-rs](https://github.com/scottfk/logrotate-rs) do
it:

- Each program runs in a private user, mount, network and pid namespace with real users
  mapped from your subordinate ids, its own `/run`, `/etc` and `/var/lib/nfs`, and
  rpcbind running inside.
- The same requests are sent to each, and every reply and every call the program makes is
  compared byte for byte, along with stdout, stderr, syslog lines, the exit status, the
  registrations, and the files it leaves behind.

When you fix a difference or change behavior, add cases that cover it, including error
paths and malformed input. Unit tests are fine for internal helpers, but a differential
test is what shows the behavior matches.

## Code conventions

- **Port, don't paraphrase.** Each function's doc comment names the upstream function it
  ports (e.g. `` `sm_mon_1_svc()` `` or `` `nsm_insert_monitored_host()` ``). Keep the
  structure close enough to the C that someone can read the two side by side.
- **Bytes, not strings.** Host names, file names, configuration values and id-mapping
  names are `Vec<u8>`/`&[u8]`, as they are in C. Don't round-trip through `String` where
  non-UTF-8 input could show up (it can: it comes off the network and out of files).
- **Bounds before trust.** Every length read from the wire is checked against what's left
  in the buffer and against upstream's limits before anything is allocated.
- **Mark quirks.** Reproduced upstream bugs get a `QUIRK:` comment in the code and a row in
  QUIRKS.md.
- **Every `unsafe` block gets a `// SAFETY:` comment.** The lints enforce this
  (`undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`).
- **US-English spelling** in comments, docs and identifiers, except where a name or string
  must match upstream.
- **Script headers.** Shell scripts, C probes and the Makefile have a changelog comment at
  the top, one line per change: `YYYYMMDD - <description> - <author>`. Please add a line
  when you change one.

## How to submit changes

The repo lives at <https://github.com/scottfk/nfs-utils-rs>.

1. Fork the repo and create a branch.
2. Make your change, with tests.
3. In the PR description, explain **what** changed and **why**. For a behavior fix,
   include the input that showed the difference.
4. If you bumped or tested against a different upstream release or libtirpc, say which.

There's no CLA. Contributions are accepted under the project's license (see
[LICENSE](LICENSE)), the same as upstream nfs-utils'.

## Issues

You can open issues for questions, not just bugs. If something about the build or the
reference setup is confusing, ask. I can't promise a fast response, but I do read them.

## Code of conduct

Be straightforward and respectful. That's the whole policy. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
