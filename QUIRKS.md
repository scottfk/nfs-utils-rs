# Upstream quirks, kept on purpose

nfs-utils-rs reproduces nfs-utils **2.8.5** (with libtirpc 1.3.7), as Gentoo builds it,
exactly, including behavior that looks like a bug. Each item here is marked `QUIRK` in the
source, or described where the code follows C step by step. Fixing one is a deliberate,
separate change (ideally upstream as well), not something to slip into the port. Quirks of
the shared `tirpc` crate are listed in rpcbind-rs's QUIRKS.md.

Severity: **high** means a remote or local client can change or break lock recovery or id
mapping, or get wrong answers; **medium** means it's surprising and user-visible; **low**
means it's cosmetic or hard to hit.

## nfs.conf (support/nfs/conffile.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | When `/etc/nfs.conf` exists, loading it throws away everything read before it: `/usr/etc/nfs.conf` and `/usr/etc/nfs.conf.d/*.conf` never count. The `.d` directories add to (and override) what is loaded, the main files replace it. | `conffile::Conf::load_file` | `conf_includes_and_dir`, `conf_dir_overrides_main` (no `/usr/etc` on hydra, so that half is untested) |
| low | `conf_get_list()` never trims trailing white space from a field: its loop starts at the NUL that `strsep()` left in place of the comma. `debug = general, all` works; `debug = general ,all` asks for the facility `general ` and warns. | `conffile::Conf::get_list` | unit `list_trimming`; `conf_debug_to_syslog` |
| low | Messages logged while the configuration is read come before `xlog_open()`: on stderr with an empty program name (`: config error at ...`), and to syslog as `LOG_USER` without a pid. `Invalid debug facility: X` has an extra newline in the format, so stderr shows a blank line and the syslog message ends in a newline. | `xlog::xlog`, `xlog::xlog_sconfig` | `conf_errors`, `conf_debug_to_syslog` |
| low | An override of `[section] tag` removes the first binding of that tag in the section whatever its `"arg"`, so a plain `tag` can delete a `[section "arg"] tag`. The configuration code also logs with `LOG_INFO` as the kind, which `xlog()` reads as the `call` and `auth` debug facilities. | `conffile::Conf::remove_now` | - |
| low | A value `$name` is looked up in the environment, then in `[environment]`; a value that names itself (`[environment] a = $a`) loops forever. | `conffile::Conf::get_section` | `conf_environment_values` (the working cases) |
| low | A short read of a configuration file logs the buffer's address (`%p`); the port prints `(buffer)`, as no address could match. | `conffile::conf_readfile` | - |

## The state directory (support/nsm/file.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | Record lines are parsed with `sscanf("%8x ...")` and then a fixed offset: the four numbers may have blanks, a sign or `0x` (all within eight characters), but the cookie is always read from column 36 and the names from column 69. A line whose numbers aren't exactly that wide is misread or rejected. | `nsm_file::nsm_parse_line`, `scan_hex` | unit `scanf_hex_edges`; `records_hex_variants`, `records_malformed` |
| medium | The line buffer is reused without clearing, and parsing writes NULs into it. A short line's cookie and names come from the line before it: after a full record, `1 2 3 4` is a second record for the same `mon_name` with an empty `my_name`, and sm-notify sends that host an `SM_NOTIFY` with an empty name. C's buffer starts as uninitialized stack, so a short first line is undefined there; the port's starts zeroed. | `nsm_file::nsm_load_host`, `nsm_delete_host` | `records_short_line_leftovers` |
| low | A line longer than the buffer (1,095 bytes) is read as several lines. Removing a notified host from such a file then fails ("could not parse original file") and leaves the file as it was. | `nsm_file::fgets` | `records_long_line` |
| low | Rewriting a record file after a removal reformats the remaining records (`%08x`, lowercase cookie), and fails ("could not construct output record") if that comes out longer than the file was. | `nsm_file::nsm_create_monitor_record` | `records_hex_variants` |
| low | After a short read of the `state` file, the warning's `%m` is whatever `errno` was before (`No such file or directory`, from an earlier lookup). | `nsm_file::nsm_get_state` | `state_short_file` |
| low | Adding a record to a file that contains a NUL byte puts the new line at the NUL (`strcat()`), and the bytes after it are written as zeros. | `nsm_file::nsm_append_monitored_host` | phase 3 |

## sm-notify (utils/statd/sm-notify.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| high | Replies are matched by xid alone, not by the address they came from: anyone who can guess the (sequential, clock-seeded) xid of a pending call can answer it, and point the `SM_NOTIFY` at another port or end a host's notification. | `sm_notify::Smn::recv_reply` | - |
| medium | "Rotating" a peer's addresses after four unanswered tries drops the first one instead of moving it to the end (the loop that looks for the end starts at the removed entry's own link, which it then points at itself). The first try already counts as a rotation, so a host with addresses `a b c` is tried at `b`, then after four tries only at `c`, and `a` never. | `Smn::notify_host` | `notify_rotates_addresses` |
| low | The check that the reserved port isn't a known service passes the port to `getservbyport()` in host order, which wants network order, so the byte-swapped port is looked up. If one matches, the retry binds the same port again (the pid picks it), up to 100 times. | `sm_notify::Smn::smn_create_socket` | - |
| low | `nlm_end_grace` is written only when there is no one to notify. With hosts, lockd's grace period ends on its own. | `main` | `no_hosts_syslog`, `notify_one_peer` |
| low | `/run/sm-notify.pid` is created whenever the state directory is the default one, `-f` or not, and never removed. With `-f` or `-n` an existing one is ignored. With `-P` (or `state-directory-path`) somewhere else there is no pid file at all. | `record_pid` | `already_running*`, `state_dir_other` |
| low | `Backgrounding to notify hosts...` has a newline in its format, so the syslog message ends in one. | `main` | `notify_backgrounded` |
| low | After a successful `SM_NOTIFY`, the name sent (the record's `my_name`, or `-v`'s) is cut at its first dot and sent again, so `a.b.c` is tried as `a.b.c`, then as `a`, never as `a.b`. | `Smn::recv_reply` | `notify_one_peer` |
| low | `generic_setup_basedir()`'s errors (`-P`) go to stderr with the full `argv[0]` and without a newline. | `misc::generic_setup_basedir` | `state_dir_missing`, `state_dir_relative`, `state_dir_too_long` |

## rpc.statd (utils/statd/)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | When exec'ing sm-notify fails, the forked child's `exit(2)` runs statd's own exit handlers: it empties `/run/rpc.statd.pid`, and in the loop after `SM_SIMU_CRASH` (by then `statd_unregister` is one of them) it also removes statd's registrations from rpcbind while statd keeps running. | `run_sm_notify` | `sm_notify_missing` |
| medium | A callback to lockd gets five tries in all, and asking the portmapper for lockd's port uses one: lockd is called at most four times. | `rmtcall::process_entry` | `callback_retries_give_up` |
| low | A refused (remote) `SM_UNMON_ALL` returns the static result as the last call left it: state 0 before any local call, the state number after. | `monitor::sm_unmon_all` | `unmon_all_remote_stale_state` |
| low | After `SM_SIMU_CRASH` statd runs sm-notify again, but as the owner of `sm/`; sm-notify finds the first run's `/run/sm-notify.pid`, can't replace it, and exits ("Already notifying clients"): the hosts are never notified again. | `main` | `simu_crash` |
| low | `my_svc_run()` loops while a callback is due at or before now, but `process_notify_list()` only sends those due strictly before now: each retry first spins on `time()` for up to a second. (Not observable in the tests: the fake clock's `select()` moves on to where the spin would end.) | `my_svc_run` | - |
| low | If no reserved port can be bound for the callback socket, statd goes on with the socket unbound (lockd then sees calls from an unprivileged port). | `rmtcall::statd_get_socket` | - |
| low | The listeners are made after dropping privileges, so `-p` (or `port`) below 1024 fails without capabilities (this build has none) and statd exits. | `main` | `privileged_port` |
| low | `SM_MON` and `SM_UNMON` turn white space in `my_name` into `_`; `SM_UNMON_ALL` doesn't. | `monitor` | `mon_white_space` |
| low | An `SM_MON` with a new cookie whose record can't be written drops the existing entry from the monitor list (its record was already deleted). | `monitor::sm_mon` | - |
| low | `ha callout returned %d\n` has a newline in its format (a blank line on stderr), and reports 255 if the fork failed. | `monitor::ha_callout` | `ha_callout` |
| low | A call whose arguments are cut short is decoded with what earlier datagrams left in the transport's buffer (zeros at first): a short `SM_MON` gets `my_name` "", program 0. This is tirpc's `svc_dg` (see rpcbind-rs's QUIRKS.md). | `tirpc::svc` | `garbage_arguments` |
| low | A transport whose `svc_reg()` (registration with rpcbind) fails stays open and is served anyway; statd only exits if none succeeded. | `svc_create` | `no_rpcbind` |
