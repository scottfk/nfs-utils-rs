# Security

nfs-utils-rs reimplements `rpc.statd`, `sm-notify`, `rpc.idmapd`, `nfsidmap` and
`libnfsidmap`. `rpc.statd` is started as root, keeps root only as long as upstream does,
listens on UDP and TCP on every interface and parses requests from anyone who can reach
it; it writes files named after hosts its callers name, and the kernel's lock recovery
trusts what it reports. `sm-notify` sends to and reads from the network as root at boot.
`nfsidmap` runs as root for the kernel, and `rpc.idmapd` answers the kernel's id-mapping
upcalls. Security bugs here matter, even though this is a hobby project.

## Status and supported versions

nfs-utils-rs is pre-release (0.x). There are no maintained release branches: only the
latest `main` gets fixes.

## What counts as a security issue

These are the kinds of bugs I most want to hear about:

- **Untrusted input.** Crashes, panics, hangs, unbounded memory or descriptor use, or
  amplification from requests a remote or local client can send: malformed XDR, huge
  lengths, connection floods, `SM_NOTIFY` floods.
- **File system tricks.** A `mon_name` or other name that makes `rpc.statd` or
  `sm-notify` create, read, rename or remove files outside its state directory, or follow
  a link C wouldn't.
- **Monitoring tampering.** `SM_MON`, `SM_UNMON`, `SM_UNMON_ALL` or `SM_SIMU_CRASH`
  accepted from callers C refuses (non-loopback, unprivileged ports), or spoofed
  `SM_NOTIFY` calls that make lockd drop locks when C wouldn't pass them on.
- **Wrong id mappings.** A name mapped to a different uid or gid than C maps it to (root
  in particular), or a mapping that fails open where C falls back to the nobody ids.
- **Privilege boundaries.** The privilege drop, the pid and lock files, descriptors
  leaking into the ha-callout or `sm-notify` children, or keyring writes.
- **Memory safety.** Unsoundness in the `unsafe` code, or anything reachable from safe code
  that causes undefined behavior.
- **Divergence from upstream that weakens security.** For example, a check that C does and
  nfs-utils-rs skips.

Upstream behavior that is reproduced on purpose will be listed in QUIRKS.md. Reports about
it are still welcome, especially if the impact is worse than described. It will be fixed as
deliberate changes.

If the same bug is also present in **upstream nfs-utils or libtirpc**, please report it to
the [linux-nfs list](https://linux-nfs.org) maintainers as well. Upstream's fix is what
nfs-utils-rs will follow. Bugs in the shared `tirpc` crate belong to
[rpcbind-rs](https://github.com/scottfk/rpcbind-rs); the same address below works for both.

## How to report

For anything that could be exploited, **please don't put the details in a public issue.**
Email them to me instead:

    scone-void-baggage (at) duck (dot) com

(Replace `(at)` with `@` and `(dot)` with `.`, and remove the spaces.)

If you don't get a reply, open an issue on <https://github.com/scottfk/nfs-utils-rs/issues>
that only says you've sent a security report, without any details.

For low-risk problems, such as hardening suggestions or issues that need root already (a
malicious `/etc/nfs.conf` or `/etc/idmapd.conf`, for instance), a normal public issue is
fine.

Useful things to include:

- The commit you tested.
- The options and configuration the program ran with, the state directory's contents, and
  the requests (a packet capture or a script is ideal).
- What happened, and what C nfs-utils does at the pinned release (`tools/REFERENCE_TAG`).

## What to expect

This is a spare-time project, so I can't promise a response time, but I'll acknowledge
security reports as soon as I can, fix confirmed bugs on `main`, and credit you in the
commit unless you'd rather I didn't.
