#!/bin/bash
# build-reference.sh - build upstream C rpc.statd, sm-notify, rpc.idmapd, nfsidmap and libnfsidmap at the pinned release, for the differential tests
#
# 20261125 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/build-reference.sh [DIR]
#
# DIR defaults to ../nfs-utils (next to this checkout), which is where the
# tests will look (override with NFSUTILS_REFERENCE=/path/to/nfs-utils).
# The sources are the nfs-utils-2.8.5 release tarball, the one Gentoo's
# net-fs/nfs-utils-2.8.5-r1 builds. The configure flags are the ebuild's for
# hydra's USE="-caps -junction -kerberos -ldap +libmount -nfsdctl +nfsv3
# +nfsv4 -sasl -selinux -tcpd +uuid". Only the parts this port covers are
# built (support/, utils/statd, utils/idmapd, utils/nfsidmap).

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$here/../nfs-utils}
rel=$(cat "$here/tools/REFERENCE_TAG")
distdir=${DISTDIR:-/var/cache/distfiles}
tarball=$distdir/$rel.tar.bz2
url=https://downloads.sourceforge.net/nfs/$rel.tar.bz2

if [[ ! -f $dir/configure.ac ]]; then
	if [[ ! -f $tarball ]]; then
		tarball=$(mktemp -d)/$rel.tar.bz2
		curl -fsSL -o "$tarball" "$url"
	fi
	mkdir -p "$dir"
	tar -xjf "$tarball" -C "$dir" --strip-components=1
fi
cd "$dir"
if [[ ! -f Makefile ]]; then
	# As the ebuild does: its DEPEND guarantees these.
	libsqlite3_cv_is_recent=yes \
	ac_cv_header_keyutils_h=yes \
	ac_cv_header_sasl_h=no \
	ac_cv_header_sasl_sasl_h=no \
	CFLAGS="${CFLAGS:--O3 -pipe -march=native}" \
	LDFLAGS="${LDFLAGS:--Wl,-O1 -Wl,--as-needed -Wl,-z,pack-relative-relocs}" \
	./configure -q --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
		--disable-static \
		--with-statedir=/var/lib/nfs \
		--enable-tirpc --with-tirpcinclude=/usr/include/tirpc/ \
		--with-pluginpath=/usr/lib64/libnfsidmap \
		--with-rpcgen --with-systemd=no --without-gssglue \
		--disable-caps --enable-ipv6 --disable-junction \
		--disable-gss --disable-svcgss --disable-ldap \
		--enable-libmount-mount --disable-nfsdctl \
		--enable-nfsv4 --enable-blkmapd --enable-nfsdcld \
		--enable-nfsdcltrack --enable-nfsv4server --enable-uuid \
		--without-tcp-wrappers
fi
make -s -C support
for d in utils/statd utils/idmapd utils/nfsidmap; do
	make -s -C "$d"
done
echo "reference: $dir (utils/statd/{statd,sm-notify} utils/idmapd/idmapd utils/nfsidmap/nfsidmap support/nfsidmap/.libs)"
