# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261126 - Run rust_pkg_setup from pkg_setup - Claude - scottfk
# 20261126 - Rollback notes: unsigned quickpkgs, restarting the daemons - Claude - scottfk

# net-fs/nfs-utils 2.8.5 with rpc.statd, sm-notify, rpc.idmapd and nfsidmap
# replaced by nfs-utils-rs's (a strict-compatibility Rust port, built live
# from git).  Everything else is net-fs/nfs-utils-2.8.5-r1, built and
# installed as that ebuild does it: the other programs, libnfsidmap.so.1
# and its plugins (which the Rust programs don't use: their methods are
# built in), man pages, init scripts and configuration files.
# nfs-utils-rs ports 2.8.5 only; pin it with a package.mask of
# >net-fs/nfs-utils-2.8.5_p9999.  To go back to C:
# emerge -1 =net-fs/nfs-utils-2.8.5-r1, or from a binary package made with
# quickpkg: emerge -1K --getbinpkg=n =net-fs/nfs-utils-2.8.5-r1 (a quickpkg is
# unsigned: with FEATURES=binpkg-request-signature, add
# FEATURES=-binpkg-request-signature for this emerge).  Then restart
# rpc.statd and rpc.idmapd: restarting nfs or nfsclient leaves them running.

EAPI=8

MY_P="nfs-utils-2.8.5"
# nfs-utils-rs's Cargo.lock: update together.
CRATES="libc@0.2.191"
declare -A GIT_CRATES=(
	[tirpc]="https://github.com/scottfk/rpcbind-rs;570ed926efbdba862016e736524d452c1c90e804;rpcbind-rs-%commit%/crates/tirpc"
)
RUST_MIN_VER="1.88.0"

inherit autotools cargo git-r3 linux-info systemd

DESCRIPTION="NFS client and server daemons (nfs-utils-rs programs)"
HOMEPAGE="https://github.com/scottfk/nfs-utils-rs http://linux-nfs.org/"

EGIT_REPO_URI="https://github.com/scottfk/nfs-utils-rs.git"
SRC_URI="
	https://downloads.sourceforge.net/nfs/${MY_P}.tar.bz2
	${CARGO_CRATE_URIS}
"
S="${WORKDIR}/${MY_P}"
# The nfs-utils-rs checkout.
RS="${WORKDIR}/nfs-utils-rs"
EGIT_CHECKOUT_DIR="${RS}"

LICENSE="GPL-2"
# Dependent crate licenses; tirpc is rpcbind-rs's (BSD).
LICENSE+=" BSD || ( Apache-2.0 MIT )"
SLOT="0"
IUSE="caps junction kerberos ldap +libmount nfsdctl +nfsv3 +nfsv4 sasl selinux tcpd +uuid"
# nfs-utils-rs ports the programs as built without capabilities or TCP
# wrappers (rpc.statd), and libnfsidmap's nsswitch, static and regex methods
# only (no LDAP).  The GSS daemons stay C, but the port's library has no GSS
# extras either.
REQUIRED_USE="|| ( nfsv3 nfsv4 ) kerberos? ( nfsv4 ) !caps !kerberos !ldap !tcpd"
# bug #315573; the nfs-utils-rs differential tests need the C build and user
# namespaces.
RESTRICT="test"

# kth-krb doesn't provide the right include
# files, and nfs-utils doesn't build against heimdal either,
# so don't depend on virtual/krb.
# (04 Feb 2005 agriffis)
COMMON_DEPEND="
	dev-libs/libxml2:=
	net-libs/libtirpc:=
	sys-fs/e2fsprogs
	dev-db/sqlite:3
	dev-libs/libevent:=
	caps? ( sys-libs/libcap )
	ldap? (
		net-nds/openldap:=
		sasl? (
			app-crypt/mit-krb5
			dev-libs/cyrus-sasl:2
		)
	)
	libmount? ( sys-apps/util-linux )
	nfsdctl? (
		>=dev-libs/libnl-3.1:3
		sys-libs/readline:=
	)
	nfsv3? ( >=net-nds/rpcbind-0.2.4 )
	nfsv4? (
		>=sys-apps/keyutils-1.5.9:=
		sys-fs/lvm2
		kerberos? (
			>=net-libs/libtirpc-0.2.4-r1[kerberos]
			app-crypt/mit-krb5
		)
	)
	tcpd? ( sys-apps/tcp-wrappers )
	uuid? ( sys-apps/util-linux )"
DEPEND="${COMMON_DEPEND}
	elibc_musl? ( sys-libs/queue-standalone )
"
RDEPEND="${COMMON_DEPEND}
	!net-libs/libnfsidmap
	selinux? (
		sec-policy/selinux-rpc
		nfsv3? ( sec-policy/selinux-rpcbind )
	)
"
BDEPEND="
	net-libs/rpcsvc-proto
	virtual/pkgconfig
"

PATCHES=(
	"${FILESDIR}"/${PN}-2.5.2-no-werror.patch
	"${FILESDIR}"/${PN}-udev-sysctl.patch
	"${FILESDIR}"/${PN}-2.6.4-C99-inline.patch
)

pkg_setup() {
	# This replaces cargo.eclass's pkg_setup too.
	rust_pkg_setup
	linux-info_pkg_setup

	if use nfsv4 && linux_config_exists && ! linux_chkconfig_present CRYPTO_MD5 ; then
		ewarn "Your NFS server will be unable to track clients across server restarts!"
		ewarn "Please enable CONFIG_CRYPTO_MD5 in your kernel to"
		ewarn "support the legacy, in-kernel client tracker."
	fi
}

src_unpack() {
	cargo_src_unpack
	git-r3_src_unpack
}

src_prepare() {
	default

	sed \
		-e "/^sbindir/s:= := \"${EPREFIX}\":g" \
		-i utils/*/Makefile.am || die

	eautoreconf
}

src_configure() {
	# Our DEPEND forces this.
	export libsqlite3_cv_is_recent=yes
	export ac_cv_header_keyutils_h=$(usex nfsv4)

	# SASL is consumed in a purely automagic way
	export ac_cv_header_sasl_h=no
	export ac_cv_header_sasl_sasl_h=$(usex sasl)

	local myeconfargs=(
		--disable-static
		--with-statedir="${EPREFIX}"/var/lib/nfs
		--enable-tirpc
		--with-tirpcinclude="${ESYSROOT}"/usr/include/tirpc/
		--with-pluginpath="${EPREFIX}"/usr/$(get_libdir)/libnfsidmap
		--with-rpcgen
		--with-systemd="$(systemd_get_systemunitdir)"
		--without-gssglue
		$(use_enable caps)
		--enable-ipv6
		$(use_enable junction)
		$(use_enable kerberos gss)
		$(use_enable kerberos svcgss)
		$(use_enable ldap)
		$(use_enable libmount libmount-mount)
		$(use_enable nfsdctl)
		$(use_enable nfsv4)
		$(use_enable nfsv4 blkmapd)
		$(use_enable nfsv4 nfsdcld)
		$(use_enable nfsv4 nfsdcltrack)
		$(use_enable nfsv4 nfsv4server)
		$(use_enable uuid)
		$(use_with kerberos krb5 "${ESYSROOT}"/usr)
		$(use_with tcpd tcp-wrappers)
	)
	econf "${myeconfargs[@]}"

	pushd "${RS}" >/dev/null || die
	cargo_src_configure
	popd >/dev/null || die
}

src_compile() {
	# Remove compiled files bundled in the tarball
	emake clean

	default

	pushd "${RS}" >/dev/null || die
	# Not the workspace: nsmprobe, idprobe and idmaptest are test tools.
	cargo_src_compile -p statd -p idmapd --bin statd --bin sm-notify --bin idmapd --bin nfsidmap
	popd >/dev/null || die
}

src_install() {
	default
	rm linux-nfs/Makefile* || die
	dodoc -r linux-nfs README

	# Don't overwrite existing xtab/etab, install the original
	# versions somewhere safe...  more info in pkg_postinst
	keepdir /var/lib/nfs/{,sm,sm.bak}
	mv "${ED}"/var/lib/nfs "${ED}"/usr/$(get_libdir)/ || die

	# Install some client-side binaries in /sbin
	dodir /sbin
	mv "${ED}"/usr/sbin/rpc.statd "${ED}"/sbin/ || die

	if use nfsv4 ; then
		insinto /etc
		doins support/nfsidmap/idmapd.conf

		# Install a config file for idmappers in newer kernels. bug #415625
		insinto /etc/request-key.d
		echo 'create id_resolver * * /usr/sbin/nfsidmap -t 600 %k %d' > id_resolver.conf
		doins id_resolver.conf
	fi

	insinto /etc
	doins "${FILESDIR}"/exports
	keepdir /etc/exports.d

	local f list=()
	if use nfsv4 ; then
		list+=( rpc.idmapd rpc.pipefs )
		use kerberos && list+=( rpc.gssd rpc.svcgssd )
	fi

	local sedexp=( -e '#placehoder' )
	use nfsv3 || sedexp+=( -e '/need portmap/d' )

	mkdir -p "${T}/init.d" || die
	for f in nfs nfsclient rpc.statd "${list[@]}" ; do
		sed "${sedexp[@]}" "${FILESDIR}/${f}.initd" > "${T}/init.d/${f}" || die
		doinitd "${T}/init.d/${f}"
	done

	for f in nfs nfsclient ; do
		newconfd "${FILESDIR}"/${f}.confd ${f}
	done

	local systemd_systemunitdir="$(systemd_get_systemunitdir)"
	sed -i \
		-e 's:/usr/sbin/rpc.statd:/sbin/rpc.statd:' \
		"${ED}${systemd_systemunitdir}"/* || die

	# Remove legacy service if not requested (as it will be broken without rpcbind)
	if ! use nfsv3; then
		rm "${ED}${systemd_systemunitdir}/nfs-server.service" || die
	fi

	# bug #368505
	keepdir /var/lib/nfs
	# bug #603628
	keepdir /var/lib/nfs/v4recovery

	# No static archives
	find "${ED}" -name '*.la' -delete || die

	# The Rust programs over the C ones, where C put them.
	local bin="${RS}/$(cargo_target_dir)"
	exeinto /sbin
	newexe "${bin}"/statd rpc.statd
	exeinto /usr/sbin
	doexe "${bin}"/sm-notify
	if use nfsv4 ; then
		newexe "${bin}"/idmapd rpc.idmapd
		doexe "${bin}"/nfsidmap
	fi
	docinto nfs-utils-rs
	dodoc "${RS}"/{README,QUIRKS}.md
}

pkg_postinst() {
	elog "rpc.statd, sm-notify, rpc.idmapd and nfsidmap are now nfs-utils-rs's."
	elog "Their known differences from C are in"
	elog "${EROOT}/usr/share/doc/${PF}/nfs-utils-rs/QUIRKS.md*."
	elog "Running daemons keep the old programs until they are restarted"
	elog "(rc-service rpc.statd restart; rc-service rpc.idmapd restart)."
	elog "To go back, emerge the C release: emerge -1 =net-fs/nfs-utils-2.8.5-r1"
	elog "(or emerge -1K --getbinpkg=n =net-fs/nfs-utils-2.8.5-r1 from a quickpkg,"
	elog "with FEATURES=-binpkg-request-signature if binary packages must be signed),"
	elog "then restart rpc.statd and rpc.idmapd again."

	# Install default xtab and friends if there's none existing.  In
	# src_install we put them in /usr/lib/nfs for safe-keeping, but
	# the daemons actually use the files in /var/lib/nfs.  #30486
	local f
	for f in "${EROOT}"/usr/$(get_libdir)/nfs/*; do
		[[ -e ${EROOT}/var/lib/nfs/${f##*/} ]] && continue
		einfo "Copying default ${f##*/} from ${EPREFIX}/usr/$(get_libdir)/nfs to ${EPREFIX}/var/lib/nfs"
		cp -pPR "${f}" "${EROOT}"/var/lib/nfs/
	done
}
