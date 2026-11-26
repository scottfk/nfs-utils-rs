/*
 * idmaptest.c - drive libnfsidmap's calls from the command line, for the differential
 * tests (tools/idmaptest.rs is the same driver over the Rust library)
 *
 * 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * Each argument starts a command; its operands follow (- for NULL):
 *
 *   init PATH            nfs4_init_name_mapping(PATH)
 *   term                 nfs4_term_name_mapping()
 *   debug N log|syslog   nfs4_set_debug(N, a logger to stderr | the current one)
 *   domain LEN           nfs4_get_default_domain(NULL, buf, LEN)
 *   uid2name ID DOM LEN  nfs4_uid_to_name() (and gid2name, uid2owner, gid2owner)
 *   name2uid NAME        nfs4_name_to_uid() (and name2gid, owner2uid, group2gid)
 *   princ SEC PRINC      nfs4_gss_princ_to_ids() (princ_ex: the _ex call)
 *   groups SEC PRINC N   nfs4_gss_princ_to_grouplist() with room for N (groups_ex)
 *   conf SECTION TAG     nfsidmap_config_get()
 *   path                 nfsidmap_conf_path
 *
 * Each prints one line. Out-parameters start as "(untouched)" or 4242424242.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "nfsidmap.h"

extern const char *nfsidmap_conf_path;
extern const char *nfsidmap_config_get(const char *section, const char *tag);

static void elog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("log: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static char *opt(char *s)
{
	return strcmp(s, "-") == 0 ? NULL : s;
}

int main(int argc, char **argv)
{
	static char buf[8192];
	int i = 1;

	while (i < argc) {
		char *cmd = argv[i++];
		int rc;

		strcpy(buf, "(untouched)");
		if (strcmp(cmd, "init") == 0) {
			rc = nfs4_init_name_mapping(opt(argv[i++]));
			printf("init = %d\n", rc);
		} else if (strcmp(cmd, "term") == 0) {
			nfs4_term_name_mapping();
			printf("term\n");
		} else if (strcmp(cmd, "debug") == 0) {
			int n = atoi(argv[i++]);
			nfs4_set_debug(n, strcmp(argv[i++], "log") == 0 ? elog : NULL);
			printf("debug %d\n", n);
		} else if (strcmp(cmd, "domain") == 0) {
			size_t len = strtoul(argv[i++], NULL, 10);
			rc = nfs4_get_default_domain(NULL, buf, len);
			printf("domain = %d '%s'\n", rc, buf);
		} else if (strcmp(cmd, "uid2name") == 0 || strcmp(cmd, "gid2name") == 0 ||
			   strcmp(cmd, "uid2owner") == 0 || strcmp(cmd, "gid2owner") == 0) {
			unsigned id = strtoul(argv[i], NULL, 10);
			char *dom = opt(argv[i + 1]);
			size_t len = strtoul(argv[i + 2], NULL, 10);
			i += 3;
			if (strcmp(cmd, "uid2name") == 0)
				rc = nfs4_uid_to_name(id, dom, buf, len);
			else if (strcmp(cmd, "gid2name") == 0)
				rc = nfs4_gid_to_name(id, dom, buf, len);
			else if (strcmp(cmd, "uid2owner") == 0)
				rc = nfs4_uid_to_owner(id, dom, buf, len);
			else
				rc = nfs4_gid_to_group_owner(id, dom, buf, len);
			printf("%s %u = %d '%s'\n", cmd, id, rc, buf);
		} else if (strcmp(cmd, "name2uid") == 0 || strcmp(cmd, "name2gid") == 0 ||
			   strcmp(cmd, "owner2uid") == 0 || strcmp(cmd, "group2gid") == 0) {
			char *name = argv[i++];
			unsigned id = 4242424242u;
			if (strcmp(cmd, "name2uid") == 0)
				rc = nfs4_name_to_uid(name, &id);
			else if (strcmp(cmd, "name2gid") == 0)
				rc = nfs4_name_to_gid(name, &id);
			else if (strcmp(cmd, "owner2uid") == 0)
				rc = nfs4_owner_to_uid(name, &id);
			else
				rc = nfs4_group_owner_to_gid(name, &id);
			printf("%s '%s' = %d %u\n", cmd, name, rc, id);
		} else if (strcmp(cmd, "princ") == 0 || strcmp(cmd, "princ_ex") == 0) {
			char *sec = argv[i], *princ = argv[i + 1];
			uid_t uid = 4242424242u;
			gid_t gid = 4242424242u;
			i += 2;
			if (strcmp(cmd, "princ") == 0)
				rc = nfs4_gss_princ_to_ids(sec, princ, &uid, &gid);
			else
				rc = nfs4_gss_princ_to_ids_ex(sec, princ, &uid, &gid, NULL);
			printf("%s %s '%s' = %d %u %u\n", cmd, sec, princ, rc, uid, gid);
		} else if (strcmp(cmd, "groups") == 0 || strcmp(cmd, "groups_ex") == 0) {
			char *sec = argv[i], *princ = argv[i + 1];
			int room = atoi(argv[i + 2]), n = room;
			gid_t groups[1024];
			for (int k = 0; k < 1024; k++)
				groups[k] = 4242424242u;
			i += 3;
			if (strcmp(cmd, "groups") == 0)
				rc = nfs4_gss_princ_to_grouplist(sec, princ, groups, &n);
			else
				rc = nfs4_gss_princ_to_grouplist_ex(sec, princ, groups, &n, NULL);
			printf("%s %s '%s' = %d %d:", cmd, sec, princ, rc, n);
			for (int k = 0; k < n && k < room; k++)
				printf(" %u", groups[k]);
			printf("\n");
		} else if (strcmp(cmd, "conf") == 0) {
			const char *v = nfsidmap_config_get(argv[i], argv[i + 1]);
			printf("conf %s %s = '%s'\n", argv[i], argv[i + 1], v ? v : "(null)");
			i += 2;
		} else if (strcmp(cmd, "path") == 0) {
			printf("path = '%s'\n", nfsidmap_conf_path);
		} else {
			fprintf(stderr, "unknown command %s\n", cmd);
			return 2;
		}
		fflush(stdout);
	}
	return 0;
}
