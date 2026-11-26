#!/bin/bash
# vm-nfscheck.sh - exercise rpc.statd, sm-notify, rpc.idmapd and nfsidmap with
# real NFS servers and clients in the test VMs
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261126 - Run the shell functions through bash; metalog's log; wait out the grace period after the statd restart - Claude - scottfk
# 20261126 - The server crashes rather than reboots - Claude - scottfk
#
# Run as root in a guest: vm-nfscheck.sh STEP OUTDIR
#
# Two VMs on one network: nfs-a (10.77.0.1), the server, and nfs-b
# (10.77.0.2), the client; each exports /srv/nfs and has users alice (2001)
# and bob (2002), group staff (2050), and "Domain = nfstest" in idmapd.conf.
# The host runs the steps in this order, the same for the C and the Rust
# build, and compares the *.norm files:
#
#   both   prep      stop everything, clear the monitor lists, start rpcbind,
#                    nfs and nfsclient, turn on NFSv4 id mapping, sit out
#                    nfsd's grace period
#   nfs-a  single    loopback: v3 locks (statd monitoring), v4.2 id mapping
#                    (rpc.idmapd answering nfsd, nfsidmap answering the
#                    client's keys), idmapd and statd restarts
#   nfs-b  hold      mount nfs-a over v3 and v4.2, take a v3 lock and keep it
#                    (in the background), names over v4 both ways
#   nfs-a  held      the lock is held for nfs-b; who monitors whom
#   (host resets nfs-a: a crash, so at boot its sm-notify tells nfs-b, whose
#   lockd reclaims; after a clean shutdown there'd be nothing to tell, as
#   stopping nfsd makes lockd unmonitor its clients)
#   nfs-a  reclaimed after the grace period: the lock is held again
#   nfs-b  client    what the client saw: the holder alive, its monitor list
#   (host resets nfs-b: a crash, so its sm-notify tells nfs-a at boot)
#   nfs-a  released  nfs-a's statd heard, and lockd dropped nfs-b's lock
#   both   finish    unmount, stop the services, the programs' log lines
#
# Ports, pids, times and the NSM state number (which only goes up from boot to
# boot) differ from run to run: the *.norm copies hide them.

step=${1:?usage: vm-nfscheck.sh STEP OUTDIR}
out=${2:?usage: vm-nfscheck.sh STEP OUTDIR}
mkdir -p "$out"
exec 3>>"$out/log"
n=$(ls "$out" | grep -c '^[0-9]')

note() { echo "== $(hostname) $step: $*" >&3; }
# run NAME CMD...: record CMD's output and status in OUTDIR/NN-NAME
run() {
	local name=$1; shift
	n=$((n + 1))
	local f; f=$(printf '%s/%02d-%s-%s' "$out" "$n" "$step" "$name")
	# Through bash, so that CMD can be one of the functions here.
	timeout 150 bash -c '"$@"' run "$@" >"$f" 2>&1
	echo "exit $?" >>"$f"
	echo "$(basename "$f"): $*" >&3
}
# A POSIX lock attempt from this host on the export (it conflicts with NLM's
# locks; flock() would not).
trylock() {
	python3 -c 'import fcntl,os,sys
f = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT)
try:
    fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB); print("lock free")
except OSError as e:
    print("lock held:", os.strerror(e.errno))' "$1"
}
programs() {
	for b in /sbin/rpc.statd /usr/sbin/sm-notify /usr/sbin/rpc.idmapd /usr/sbin/nfsidmap; do
		if grep -qa /rustc/ "$b"; then echo "$b rust"; else echo "$b C"; fi
	done
}
monitors() {
	(cd /var/lib/nfs && for d in sm sm.bak; do
		for f in $d/*; do [ -e "$f" ] && echo "$f: $(stat -c '%U %a' "$f") $(cut -d' ' -f6- "$f")"; done
	done)
	echo "state $(( $(od -An -tu4 /var/lib/nfs/state) % 2 ? 1 : 0 )) (odd: up)"
}
idmap_on() {
	modprobe nfsd 2>/dev/null; modprobe nfs 2>/dev/null
	echo N >/sys/module/nfsd/parameters/nfs4_disable_idmapping
	echo N >/sys/module/nfs/parameters/nfs4_disable_idmapping
	cat /sys/module/nfsd/parameters/nfs4_disable_idmapping /sys/module/nfs/parameters/nfs4_disable_idmapping
}
# Names over a v4 mount M of an export E (a path on the server): files made
# on the server side as each user, then shown and changed through the mount.
names() {
	local m=$1 tag=$2
	run "$tag-ls" sh -c "ls -l $m | awk 'NR > 1 { print \$3, \$4, \$9 }' | sort"
	run "$tag-stat" sh -c "stat -c '%U %G %u %g %n' $m/* | sort"
	run "$tag-chown" sh -c "f=$m/chown-$tag; rm -f \$f; touch \$f &&
		chown bob:staff \$f && stat -c '%U %G %u %g' \$f &&
		chown 4242:4343 \$f && stat -c '%U %G %u %g' \$f &&
		chown alice \$f && stat -c '%U %G %u %g' \$f"
	run "$tag-as-alice" su alice -s /bin/sh -c "f=$m/alice-$tag; rm -f \$f; echo hi >\$f && stat -c '%U %G' \$f; chgrp staff \$f && stat -c '%U %G' \$f; chgrp bob \$f; stat -c '%U %G' \$f"
	run "$tag-keys" sh -c "nfsidmap -l 2>&1 | sed -E 's/^ *[0-9a-f]+ //' | sort"
}
serverfiles() {
	rm -rf /srv/nfs/*
	mkdir -p /srv/nfs
	chmod 1777 /srv/nfs
	for u in alice:alice bob:staff 4242:4343 root:root; do
		touch /srv/nfs/own-${u%%:*}; chown "$u" /srv/nfs/own-${u%%:*}
	done
}
logs() {
	# metalog's log: "Mmm dd hh:mm:ss [program] message".
	run log sh -c 'grep -ah -E "rpc\.statd|sm-notify|rpc\.idmapd|nfsidmap" /var/log/everything/current | sed -E -e "s/^.{16}//" -e "s/\[[0-9]+\]/[PID]/" | sort | uniq -c'
	run dmesg sh -c 'dmesg | grep -iE "lockd|statd|nfs4|idmap|NFSD" | sed -E "s/^\[[ 0-9.]+\] //" | sort -u'
}

export -f trylock programs monitors idmap_on

case $step in
prep)
	note prep
	run programs programs
	rc-service nfsclient stop >/dev/null 2>&1; rc-service nfs stop >/dev/null 2>&1
	rc-service rpc.idmapd stop >/dev/null 2>&1; rc-service rpc.statd stop >/dev/null 2>&1
	umount -a -t nfs,nfs4 >/dev/null 2>&1
	pkill -f '[l]ockhold' 2>/dev/null
	rm -rf /var/lib/nfs/sm/* /var/lib/nfs/sm.bak/*
	nfsidmap -c 2>/dev/null
	: >/var/log/everything/current
	serverfiles
	mkdir -p /mnt/v3 /mnt/v4
	run start-rpcbind rc-service rpcbind start
	run start-nfs rc-service nfs start
	run idmap-on idmap_on
	run start-nfsclient rc-service nfsclient start
	sleep 95
	run status sh -c 'rc-status -a | grep -E "rpc|nfs" | sed "s/ *\[.*\]//" | sort'
	run rpcinfo sh -c 'rpcinfo -p | awk "{print \$1, \$2, \$3, \$5}" | sort -u'
	run monitors monitors
	;;
single)
	note single
	run mount-v3 mount -t nfs -o vers=3 127.0.0.1:/srv/nfs /mnt/v3
	run mount-v4 mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/v4
	run v3-lock sh -c '
		flock /mnt/v3/lk-single sleep 4 & sleep 1
		flock -n /mnt/v3/lk-single true; echo contended=$?
		flock -w 20 /mnt/v3/lk-single true; echo waited=$?
		wait'
	run monitors-v3 monitors
	names /mnt/v4 v4
	run idmapd-hup sh -c 'pkill -HUP -x rpc.idmapd; sleep 1; pgrep -c -x rpc.idmapd'
	names /mnt/v4 v4-hup
	run idmapd-restart rc-service rpc.idmapd restart
	run keys-clear nfsidmap -c
	names /mnt/v4 v4-restart
	run statd-restart rc-service rpc.statd restart
	# The restart restarted nfsd too: another grace period.
	sleep 95
	run v3-lock2 sh -c 'flock /mnt/v3/lk-single sleep 2 & sleep 1; flock -n /mnt/v3/lk-single true; echo contended=$?; wait; flock -n /mnt/v3/lk-single true; echo free=$?'
	run monitors-restart monitors
	run umount sh -c 'umount /mnt/v3 /mnt/v4; grep -c " /mnt/v" /proc/mounts'
	;;
hold)
	note hold
	run mount-v3 mount -t nfs -o vers=3 nfs-a:/srv/nfs /mnt/v3
	run mount-v4 mount -t nfs -o vers=4.2 nfs-a:/ /mnt/v4
	run mounts sh -c 'grep -E " /mnt/v[34] " /proc/mounts | sed -E "s/,(addr|clientaddr|mountaddr|mountport|port)=[^,]*//g"'
	# The holder: a lock on lk-ab kept until killed (or the VM dies).
	run lock sh -c 'setsid sh -c "exec -a lockhold flock /mnt/v3/lk-ab sleep 100000" </dev/null >/dev/null 2>&1 &
		sleep 3; pgrep -f "[l]ockhold" >/dev/null && echo holding'
	run contend sh -c 'flock -n /mnt/v3/lk-ab true; echo contended=$?'
	run monitors monitors
	names /mnt/v4 ab-v4
	;;
held)
	note held
	run trylock trylock /srv/nfs/lk-ab
	run monitors monitors
	;;
reclaimed)
	note reclaimed
	run programs programs
	run status sh -c 'rc-status -a | grep -E "rpc|nfs" | sed "s/ *\[.*\]//" | sort'
	run idmap-on idmap_on
	run trylock trylock /srv/nfs/lk-ab
	run monitors monitors
	;;
client)
	note client
	run holder sh -c 'pgrep -f "[l]ockhold" >/dev/null && echo holding || echo gone'
	run contend sh -c 'flock -n /mnt/v3/lk-ab true; echo contended=$?'
	run monitors monitors
	;;
released)
	note released
	# Wait for nfs-b's notification (at most two minutes).
	run trylock sh -c "for i in \$(seq 1 60); do r=\$(python3 -c 'import fcntl,os
f = os.open(\"/srv/nfs/lk-ab\", os.O_RDWR)
try:
    fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB); print(\"free\")
except OSError: print(\"held\")'); [ \$r = free ] && break; sleep 2; done; echo lock \$r"
	run monitors monitors
	;;
finish)
	note finish
	run programs programs
	pkill -f '[l]ockhold' 2>/dev/null
	run umount sh -c 'umount -a -t nfs,nfs4; grep -c " /mnt/v" /proc/mounts'
	run monitors monitors
	run stop-nfsclient rc-service nfsclient stop
	run stop-nfs rc-service nfs stop
	run stop-idmapd rc-service rpc.idmapd stop
	run stop-statd rc-service rpc.statd stop
	run left sh -c 'pgrep -l -x "rpc.statd|rpc.idmapd|sm-notify"; echo none'
	logs
	;;
*)
	echo "unknown step $step" >&2
	exit 2
	;;
esac

# Normalized copies.
for f in "$out"/[0-9]*; do
	case $f in *.norm) continue ;; esac
	sed -E -e 's/\b(port|mountport)=[0-9]+/\1=PORT/g' \
		-e 's/\b[0-9]{10}\b/TIME/g' \
		-e 's/(^ *[0-9]+ +[0-9]+ +(tcp|udp) +)[0-9]+/\1PORT/' \
		"$f" >"$f.norm"
done
echo "done $step" >&3
# Before the host resets a VM: what was written must survive.
sync
