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
| low | Adding a record to a file that contains a NUL byte puts the new line at the NUL (`strcat()`), and the bytes after it are written as zeros. | `nsm_file::nsm_append_monitored_host` | `record_with_nul`, `record_symlink` |

## sm-notify (utils/statd/sm-notify.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| high | Replies are matched by xid alone, not by the address they came from: anyone who can guess the (sequential, clock-seeded) xid of a pending call can answer it, and point the `SM_NOTIFY` at another port or end a host's notification. | `sm_notify::Smn::recv_reply` | `reply_spoofed_address` |
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
| high | `SM_NOTIFY` is believed from anyone. A call naming a monitored host, from any address, counts as that host's reboot (lockd is told, and drops its locks), and so does one from a monitored host's address whatever name it gives: one datagram from peer-b naming peer-a reboots both. | `monitor::sm_notify` | `notify_spoofed_name`, `notify_flood_sources` |
| medium | `SM_MON` checks `mon_name` for `/` and a leading `.`, but the record file is named after the canonical name the resolver returns. A canonical name with `/` or white space is refused; `..` and `.` are not, so statd unlinks and appends to `sm/..` (the state directory itself) and `sm/.`, which fails only because they are directories. Names such as `sm.bak` or `-rf` become record files as they are. | `monitor::sm_mon`, `nsm_file::nsm_make_record_pathname` | `mon_canonical_hostile`, `load_hostile_records` |
| low | Replies on the callback socket are taken from any port on 127.0.0.1 (only the address and the xid are checked), so any local process that sees or guesses the xid can answer lockd's callback, or point it at another port through a forged `PMAP_GETPORT` answer. | `rmtcall::recv_rply` | `callback_reply_other_port`, `callback_reply_other_address` |
| low | A record that is a symlink is skipped at startup as a non-regular file, but followed when a record is added: the target's bytes start the new record file, which then replaces the link (and the NUL quirk above applies to them). A dangling link fails the `SM_MON`. | `nsm_file::nsm_append_monitored_host` | `record_symlink` |
| low | When a record can't be removed (`sm/` not writable), `SM_UNMON` still drops the host from the list and answers as usual; the record stays, so the host is monitored again after a restart, and notified by sm-notify. | `monitor::sm_unmon` | `sm_read_only` |
| low | statd lowers its descriptor limit to `FD_SETSIZE` (1024). The idle sweep it inherits from tirpc (see rpcbind-rs's QUIRKS.md) runs only after an accept succeeds, so once a flood has used every descriptor (possible when no connection is less active than another), nothing closes them: accept() fails on every pass through the loop, which then spins, and every name lookup fails (`SM_STAT` answers `STAT_FAIL`) until clients close. On a clock that moves, the sweep keeps statd at 820 descriptors. | `main`, `tirpc::svc` | `tcp_flood_descriptors`, `tcp_flood_sweep`, `tcp_flood_low_fd_limit` |

## libnfsidmap (support/nfsidmap/)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | A `Method` list with no names in it (`Method = ,`) loads no methods, and every lookup then succeeds without an answer: the caller's own starting value comes back. nfsidmap starts its ids at 0, so it answers every `uid:` and `gid:` key, for any name, with root. For a name key it sends its uninitialized buffer (the port sends nothing). `Method =` with no value is the default, `nsswitch`. | `core::Lib::run` | `methods_empty_list`, `empty_method_list` |
| medium | The `nsswitch` method fails a name in another domain with `-EINVAL`, not `-ENOENT`, and only `-ENOENT` moves on to the next method: with `Method = nsswitch,static`, the `static` mappings never see names whose domain isn't the local one, which is what they are for. | `nss::Nss::getpwnam`, `name_to_gid_1` | `methods_order_*` |
| medium | The default domain from DNS takes the first record of the answer section as TXT data, whatever its type: after a CNAME, the domain is built from the CNAME target's bytes (its first label's length byte read as the text's length). A record cut short is read on into the zeroed buffer (an empty domain); far enough past the end (near 64 KiB) C reads past its buffer, where the port reads zeros. The text is used as it is, so a domain can hold spaces, `/` or any byte but NUL. | `core::Core::dns_txt_query` | `domain_txt_variants`, `domain_txt_malformed` |
| medium | The `regex` method's setup never fails. Without a `User-Regex` or `Group-Regex`, or with one that doesn't compile, it is loaded with empty expressions and unset prefixes, and the first lookup that uses them crashes (`SIGSEGV` in glibc's `regexec()`, or `strlen(NULL)`). A bad `Group-Name-No-Prefix-Regex` frees both expressions: names still go out, and the first name coming in crashes. The port dies of `SIGSEGV` at the same points. | `regex::RegexMethod::init` | `regex_bad_settings`, `regex_without_expressions_crashes` |
| low | An unknown `GSS-Methods` name fails the whole setup when `Domain` is set. When the domain came from DNS, the setup succeeds without the GSS methods, and also skips the `Nobody-User` and `Nobody-Group` lookups. | `core::Lib::init` | `gss_methods` |
| low | A setup that fails (an unknown method) is tried again by every later call: the configuration is read and the domain looked up again, and the same messages are logged again. | `core::Lib::run` | `failed_init_retried_each_call` |
| low | The library and each method keep their own copy of the configuration (and of `nfsidmap_common.c`'s caches), each read when that copy loads: errors in `idmapd.conf` are logged once per copy, by a copy of `xlog.c` that was never opened, with an empty program name, on stderr and in syslog, whatever the program set. | `xlog::in_library_copy`, each method's `init` | `conf_errors_logged_per_copy` (both suites) |
| low | A method named twice, or in both `Method` and `GSS-Methods`, is one instance: `dlopen("METHOD.so")` finds the plugin already loaded by its soname. The second load is logged without the path and sets the instance up again. | `core::Lib::load_translation_plugin` | `methods_order_3` |
| low | A `Domain` longer than 511 bytes doesn't fit `nfs4_get_default_domain()`'s buffer: it fails with `-ERANGE`, and the methods then use an empty domain (names go out as `user@`, the default realm is empty). nfsidmap's `-d` prints `Unknown error -34`. | `core::Core::nfs4_get_default_domain` | `domain_too_long` (both suites) |
| low | The `static` and `regex` methods report a group list that doesn't fit as `+ERANGE` (they negate `-ERANGE` on the way out); `nsswitch` gives `-ERANGE`. | `staticmap::Static::princ_to_grouplist`, `regex::RegexMethod::princ_to_grouplist` | `static_mappings`, `regex_mappings` |
| low | User lookups use `sysconf(_SC_GETPW_R_SIZE_MAX)`'s 1,024-byte buffer and never grow it: a bigger passwd entry fails with `ERANGE` (and from `nsswitch`'s id lookup, `-ENOENT`), which also stops the method list. Group lookups double their buffer and retry. | `nss`, `staticmap`, `regex` | `nss_big_entries` |
| low | An owner that no method maps is read as a number with `strtol()`, cut to an `int`: `12abc` is 12, `-1` is 4294967295, `99999999999` wraps, and only `0` itself gives 0. Otherwise it maps to `Nobody-User`, else `nobody@DOMAIN`, else 4294967294. | `core::id_as_chars`, `set_id_to_nobody` | `owner_numbers`, `nobody`, `uid_numbers` |
| low | `static`'s name for an id is copied without checking the caller's length (`strcpy()`), overrunning it for a principal of the buffer's size or more. The port returns the whole principal. | `staticmap::Static::uid_to_name` | `static_long_principal` (with a buffer big enough for C) |
| low | After `nfs4_term_name_mapping()`, C's default domain points into the freed configuration until the next setup; the port keeps the old value. | `core::Lib::term` | - |

The methods are built in rather than loaded. A `Method` that names anything else
(`umich_ldap`, `gums`, a plugin of one's own) fails as C fails to `dlopen()` a missing
plugin, with the same messages. C would also load a plugin found on the library search
path, or one reached by a path in the method name (`./nsswitch`); the port matches the
three names exactly.

## nfsidmap (utils/nfsidmap/nfsidmap.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | `Verbosity` in `idmapd.conf` is never seen: nfsidmap asks its own copy of the configuration code, which nothing reads into (the library reads its own). | `nfsidmap::main` | `verbosity_setting_ignored` |
| low | A key of an unknown type (`foo:bar`) leaves the result at the setup's 0: nfsidmap gives the key its timeout but no answer, and exits 0. | `nfsidmap::main` | `unknown_key_type` |
| low | `-u`, `-g` and `-r` invalidate the first key whose id starts with the argument (`-u al` takes `uid:alice`), and with `-r` the first of each kind. `uid:` and `gid:` count anywhere in a `/proc/keys` line, and a line with `keyring` anywhere is skipped. | `nfsidmap::key_invalidate` | `invalidate`, `invalidate_line_matching` |
| low | A failed answer other than a full keyring (`EDQUOT`, `ENFILE`, `ENOMEM`, which clear `.id_resolver` and retry) exits 1 without a message. | `nfsidmap::id_lookup` | `instantiate_other_error` |
| low | Errors are fatal wherever they come: `-l` stops at the first key it can't describe, and a failed name lookup reports a negative errno (`Unknown error -2`). | `nfsidmap::list_key`, `name_lookup` | `list_describe_fails`, `user_key_unknown_uid` |
| low | A `/proc/keys` line without a newline makes libkeyutils' search dereference NULL, and with `-v`, so does `key_invalidate()`; the port dies of `SIGSEGV` there too. The kernel always ends its lines. | `nfsidmap::find_key_by_type_and_desc`, `key_invalidate` | - |

## rpc.idmapd (utils/idmapd/idmapd.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | The `SIGUSR1` rescan is libevent's signal event, which passes the signal number where `dirscancb()` expects the inotify descriptor: the rescan first reads descriptor 10 dry. In the usual layouts 10 is a client's directory (`EISDIR`) or the inotify descriptor itself, and nothing happens. When 10 is a channel or a client's pipe (one nfsd channel and a client in the foreground, say), the read blocks: every later request waits, and that pipe's requests are swallowed (logged as inotify events at `-vvv`). The first `SIGTERM` is restarted past (`SA_RESTART`); a second one exits. | `Idmapd::dirscancb` | `sigusr1_reads_fd_10`, `sigusr1_reads_fd_10_verbose`, `sigusr1_fd_10_harmless` |
| medium | A `-c` file that doesn't exist (or can't be read) is skipped with nothing else read: not `idmapd.conf`, not `nfs.conf`. The cache expiry is then 0, not 600, and written to `/proc/sys/fs/nfs/idmap_cache_timeout`; nfsd's entries expire as they're made. | `main` | `c_missing_file` |
| low | With `-S` (or `server-only`) no signal is handled: `SIGTERM` and `SIGINT` kill it without the "exiting" message, `SIGHUP` kills it instead of reopening nfsd's channels, and `SIGUSR1`/`SIGUSR2` are xlog's debug toggles. | `main` | `server_only`, `server_only_signals` |
| low | With `-C` (or `client-only`) nfsd's channels aren't opened, but `SIGHUP` "reopens" them, and from then on nfsd is served. | `Idmapd::nfsdreopen` | `client_only_hup_opens_nfsd` |
| low | Without `-c`, `Pipefs-Directory` comes from `nfs.conf` only (`idmapd.conf`'s is ignored); with `-c`, from that file only. | `main` | `default_files`, `c_file` |
| low | nfsd's channels are opened name-to-id first, and id-to-name only if that worked. With just name-to-id present it is served but the caches aren't flushed, and with `-S` the program then exits for "neither" having been found. A flush that fails is fatal, after the first one may have been written. | `Idmapd::nfsdopen`, `main` | `nfsd_half_present`, `flush_missing` |
| low | In client mode a pipefs directory that can't be watched (missing, or a name too long) is fatal. A `-p` or `Pipefs-Directory` of 4,092 bytes or more aborts in the fortified `strncat()` (`*** buffer overflow detected ***`), a longer one after being cut to 4,095. | `main` | `no_pipefs`, `p_too_long` |
| low | In nfsd's upcalls an escape always moves on four bytes, even when `%03o` took fewer digits (`\7`): past the end of the field and into the next, whose bytes are then read twice. `%o` takes a sign (`\-01` is too big), and `\000` ends a field early. | `getfield` | `escapes` |
| low | The upcall's last byte is taken for its newline, whatever it is. | `Idmapd::nfsdcb` | `no_newline` |
| low | A type other than `user` is a group. An id that isn't a number is 0 (`abc` is root), `+5` is 5, and only ids over 2^32 - 1 are refused. | `Idmapd::nfsdcb` | `name_to_id`, `id_to_name`, `id_parsing` |
| low | The check "for NULL termination" looks at the byte after the name's NUL: when that isn't 0 (an escaped `\000` in nfsd's upcall, or a client message with bytes there), nothing is looked up. nfsd gets a negative entry; the client gets its message back as it came, with `LOOKUPFAIL` turned into `SUCCESS`. | `Idmapd::imconv` | `escapes`, `client_odd_messages` |
| low | An answer that doesn't fit nfsd's 257-byte buffer (escaped spaces take four bytes) loses the fields that don't fit, without a message; the newline goes over the last space written. | `addfield` | `reply_overflow` |
| low | A `Nobody-User` or `Nobody-Group` of 128 bytes or more answers id-to-name failures as `nobody`, while name-to-id failures still get its id. Ids over 2^31 - 1 are logged as negative numbers. | `Idmapd::idtonameres` | `long_nobody`, `client_lookups` |
| low | An end of file on a channel or a pipe is "no upcall": the descriptor stays readable and the loop spins, logging the last `errno` again for a client at `-v`. When it spins logging, `SIGTERM` can deadlock: `sig_die()` logs from the signal handler, and if that interrupts the loop's own `syslog()` call, the lock is already held. The port makes the same calls. | `Idmapd::nfsdcb`, `nfscb`, `sig_die` | `channel_eof_spins`, `client_reset` |
| low | `ic_clid` holds 29 bytes: a client directory whose name is longer never matches its own entry, so every scan drops the client and opens it again. | `Idmapd::dirscancb` | `long_client_names` |
| low | Every entry whose name starts with `clnt` is tried, `clnt` alone being a client with an empty id. One that can't be opened (a socket) ends the scan there, and the clients that went away aren't dropped. A regular file for the pipe is opened, and epoll refuses it (libevent says so on stderr): a client with no events. | `Idmapd::dirscancb` | `odd_entries`, `file_as_pipe` |
| low | When the pipefs directory goes away, every scan fails and no client is dropped. `SIGUSR2` reopens the clients whose pipe is closed, which none ever is. | `Idmapd::dirscancb`, `clntscancb` | `pipefs_removed`, `sigusr2_and_sigint` |
| low | `-:` "requires an argument" (`strchr()` finds `:` in the option string). | `main` | `colon_option` |

libevent is reproduced as rpc.idmapd uses it ([`ev`](crates/idmapd/src/idmapd/ev.rs)):
its epoll backend with the same descriptors in the same order, the same `epoll_ctl()`
calls and warnings, the self-pipe and handler for signals, the order in which ready
events run, and what happens when descriptors run out at the start. Not reproduced:
libevent's environment variables (`EVENT_NOEPOLL` and the others, which choose another
backend or turn on its debug output), and its `poll()` and `select()` backends, which
it uses only when epoll isn't there. `event_base_loopexit()` from `sig_die()` sets a
flag the loop checks, where libevent adds an event to its queue from the handler (and
could corrupt it, if the signal came in the middle of the loop changing it).
