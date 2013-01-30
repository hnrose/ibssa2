/*
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013 Lawrence Livermore National Securities.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */


#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <infiniband/verbs.h>

#include "ibssa_mad.h"
#include "ibssaclient.h"


/* local port information specified on the command line
 * This is resolved to a umad_port_t via resolve_umad_port
 */
enum LP_MODE { LP_GID, LP_GUID, LP_UMAD };
struct local_port
{
	union ibv_gid   gid;
	uint64_t        guid;
	char          * ca;
	uint8_t         port;
	enum LP_MODE    mode;
};
char *lp_to_str(struct local_port *p, char *buf, size_t n)
{
	char gidbuf[256];
	switch (p->mode) {
		case LP_GID:
			n += snprintf(buf, n, "%s",
				inet_ntop(AF_INET6, p->gid.raw, gidbuf, 256));
			break;
		case LP_GUID:
			n += snprintf(buf, n, "0x%" PRIx64 , p->guid);
			break;
		case LP_UMAD:
			n += snprintf(buf, n, "%s:%d",
				p->ca ? p->ca : "(null)",
				p->port);
			break;
	}
	return (buf);
}

static int resolve_guid_gid(struct local_port *lport,
			umad_port_t *umad_port)
{
	int rc = -1;
	char cas[64][UMAD_CA_NAME_LEN];
	int num_cas = -1;
	int i,j;
	uint64_t guid = lport->guid;

	if (lport->mode == LP_GID)
		guid = lport->gid.global.interface_id;

	num_cas = umad_get_cas_names(cas, 64);
	for (i = 0 ; i < num_cas; i++) {
		umad_ca_t ca;
		if (umad_get_ca(cas[i], &ca) < 0)
			continue;
		for (j = 0; j < ca.numports; j++) {
			if (umad_get_port(cas[i], j, umad_port) < 0)
				continue;
			if (umad_port->port_guid == guid) {
				if (lport->mode == LP_GUID ||
				    umad_port->gid_prefix
				     == lport->gid.global.subnet_prefix) {
					rc = 0;
				}
			}
			if (rc != 0)
				umad_release_port(umad_port);
		}
		umad_release_ca(&ca);
		if (rc == 0)
			break;
	}
	return (rc);
}

static int resolve_umad_port(struct local_port *lport,
			umad_port_t *umad_port)
{
	int rc = -1;
	switch (lport->mode) {
		case LP_GID:
		case LP_GUID:
			rc = resolve_guid_gid(lport, umad_port);
			break;
		case LP_UMAD:
			rc = umad_get_port(lport->ca, lport->port, umad_port);
			break;
	}
	return (rc);
}

#if 0
struct query_cmd {
	const char *cmd,
	const char *usage
	// handler...  yada yada
};

static const struct query_cmd query_cmds[] = {
	{ "NodeRecord", "query all node records" }
};
#endif

static struct option long_options[] = {
	{"gid",        1, 0, 'g'},
	{"guid",       1, 0, 'G'},
	{"Ca",         1, 0, 'C'},
	{"Port",       1, 0, 'P'},
	{"mad-debug",  0, 0,  0},
	{"help",       0, 0, 'h'},
	//{"parent-lid", 1, 0,  0},
};

void show_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [options] query\n", argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  --help, -h      print this help message\n");
	fprintf(stderr, "Connect to local port via gid,guid,Ca[Port]:\n");
	fprintf(stderr, "  --gid,  -g <gid>\n");
	fprintf(stderr, "  --guid, -G <guid>\n");
	fprintf(stderr, "  --Ca,   -C <ca>\n");
	fprintf(stderr, "  --Port, -P <port>\n");
	fprintf(stderr, "  Note: the last option specified is used\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Debugging:\n");
	fprintf(stderr, "  --mad-debug     Enable mad debugging\n");
	fprintf(stderr, "\n");
#if 0
	fprintf(stderr, "  --parent-lid <lid>  Connect to parent specified by <lid>\n");
	fprintf(stderr, "                      This skips the normal connection sequence\n");
	fprintf(stderr, "                      requires additional options...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Queries:\n");
	for (i = 0; i < sizeof query_cmds; i++) {
		fprintf(stderr, "  %30s %s\n", query_cmds[i].cmd,
					query_cmds[i].usage);
	}
#endif
}

int main(int argc, char **argv)
{
	char buf[512];
	int rc = -1;
        int ch;
	struct local_port local_port;
	int umaddebug = 0;
	umad_port_t umad_port;
	struct ibssaclient *client;

	memset(&local_port, 0, sizeof(local_port));
	local_port.mode = LP_UMAD;

        while ((ch = getopt_long(argc, argv, "hg:G:C:P:",
				long_options, NULL)) != -1) {
                switch (ch) {
			case 0:
				umaddebug++;
				break;
			case 'g':
				inet_pton(AF_INET6, optarg, local_port.gid.raw);
				local_port.mode = LP_GID;
				break;
			case 'G':
				local_port.guid = strtoull(optarg, NULL, 0);
				local_port.mode = LP_GUID;
				break;
			case 'C':
				if (local_port.ca)
					free(local_port.ca);
				local_port.ca = strdup(optarg);
				local_port.mode = LP_UMAD;
				break;
			case 'P':
				local_port.port = (uint8_t)strtoul(optarg, NULL, 0);
				local_port.mode = LP_UMAD;
				break;
			case 'h':
			case '?':
				rc = 0;
				/* fall through */
			default:
				show_usage(argv[0]);
				exit(-1);
				break;
		}
	}

	umad_debug(umaddebug);

	if ((rc = resolve_umad_port(&local_port, &umad_port)) < 0) {
		fprintf(stderr, "Failed to resolve local port: %s\n",
			lp_to_str(&local_port, buf, 512));
		show_usage(argv[0]);
		exit(rc);
	}

	if ((client = ibssa_alloc_client(&umad_port)) == NULL) {
		fprintf(stderr, "Failed to allocate client\n");
		exit(-1);
	}

	if ((rc = ibssa_open_client(client)) < 0) {
		fprintf(stderr, "Failed to open client on port: %s\n",
			lp_to_str(&local_port, buf, 512));
		goto ReleasePort;
	}

	{
		struct service service = {
			/* FIXME We should use the CM to get a service ID before this */
			local_service_id : 1,
			service_guid : SSA_SERVICE_DATABASE,
			/* FIXME for now use default pkey */
			pkey : htons(umad_port.pkeys[0]),
			/* FIXME we want this utility to be more than just a consumer */
			node_type : SSA_NODE_CONSUMER,
		};
		if ((rc = ibssa_join_client_service(client, &service)) < 0) {
			goto CloseClient;
		}
	}

	do {
		if (ibssa_process_client(client) < 0) {
			fprintf(stderr, "Client failed to process client\n");
			rc = -1;
			break;
		}
	} while(1);
	sleep(1);

CloseClient:
	ibssa_close_client(client);
	ibssa_free_client(client);

ReleasePort:
	umad_release_port(&umad_port);
	return (rc);
}
