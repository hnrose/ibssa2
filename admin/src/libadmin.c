/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

#include <stdio.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <rdma/rsocket.h>
#include <infiniband/ib.h>
#include <infiniband/umad.h>
#include <infiniband/umad_sm.h>

#include "libadmin.h"
#include <osd.h>
#include <ssa_admin.h>
#include <infiniband/ssa_mad.h>

static int rsock = -1;
static int loopback;
static short admin_port = 7477;
static char dest_addr[64];
static const char *local_gid = "::1";

static int open_port(const char *dev, int port)
{
	int port_id;

	if (umad_init() < 0) {
		printf("ERROR - unable to init UMAD library\n");
		return -1;
	}

	if ((port_id = umad_open_port(dev, port)) < 0) {
		printf("ERROR - can't open UMAD port\n");
		return -1;
	}

	return port_id;
}

static void close_port(int port_id)
{
	umad_close_port(port_id);
	umad_done();
}

/* first physical port in active state is queried for sm lid and sm sl */
static int get_sm_info(uint16_t *sm_lid, int *sm_sl)
{
	struct ibv_device **dev_arr, *dev;
	struct ibv_context *verbs;
	struct ibv_port_attr port_attr;
	struct ibv_device_attr attr;
	int  d, p, ret, status = -1;
	int dev_cnt, port_cnt;

	dev_arr = ibv_get_device_list(&dev_cnt);
	if (!dev_arr) {
		printf("ERROR - unable to get device list\n");
		return -1;
	}

	for (d = 0; d < dev_cnt; d++) {
		dev = dev_arr[d];
		if (dev->transport_type != IBV_TRANSPORT_IB ||
		    dev->node_type != IBV_NODE_CA)
			continue;

		verbs = ibv_open_device(dev);
		if (!verbs) {
			printf("ERROR - unable to open a device\n");
			goto out;
		}

		ret = ibv_query_device(verbs, &attr);
		if (ret) {
			printf("ERROR - ibv_query_device (%s) %d\n",
			       dev->name, ret);
			goto out;
		}

		port_cnt = attr.phys_port_cnt;

		for (p = 1; p <= port_cnt; p++) {
			ret = ibv_query_port(verbs, p, &port_attr);
			if (ret) {
				printf("ERROR - ibv_query_port (%s) %d\n",
				       dev->name, ret);
				goto out;
			}

			if (port_attr.link_layer != IBV_LINK_LAYER_INFINIBAND)
				continue;

			if (port_attr.state == IBV_PORT_ACTIVE) {
				*sm_lid = port_attr.sm_lid;
				*sm_sl = port_attr.sm_sl;
				break;
			}
		}

		if (p <= port_cnt)
			break;
	}

	if (d == dev_cnt)
		printf("ERROR - no proper device with active port found\n");
	else
		status = 0;

out:
	ibv_free_device_list(dev_arr);

	return status;
}

static int get_gid(int port_id, uint16_t dlid, union ibv_gid *dgid)
{
	struct sa_path_record *mad;
	struct ibv_path_record *path;
	struct sa_umad umad;
	uint16_t sm_lid = 0;
	int sm_sl = 0;
	int agent_id = -1;
	int ret, len, status = 0;
	static int tid;

	while (!tid) {
		srand(time(NULL));
		tid = rand();
	}

	agent_id = umad_register(port_id, UMAD_CLASS_SUBN_ADM,
				 UMAD_SA_CLASS_VERSION, 0, NULL);
	if (agent_id < 0) {
		printf("ERROR - unable to register SSA class on local port\n");
		status = -1;
		goto err;
	}

	if (get_sm_info(&sm_lid, &sm_sl)) {
		status = -1;
		goto err;
	}

	memset(&umad, 0, sizeof umad);
	umad_set_addr(&umad.umad, sm_lid, 1, sm_sl, UMAD_QKEY);
	mad = &umad.sa_mad.path_rec;

	mad->mad_hdr.base_version	= UMAD_BASE_VERSION;
	mad->mad_hdr.mgmt_class		= UMAD_CLASS_SUBN_ADM;
	mad->mad_hdr.class_version	= UMAD_SA_CLASS_VERSION;
	mad->mad_hdr.method		= UMAD_METHOD_GET;
	mad->mad_hdr.tid		= htonll(tid++);
	mad->mad_hdr.attr_id		= htons(UMAD_SA_ATTR_PATH_REC);

	mad->comp_mask = htonll(((uint64_t)1) << 4 |    /* DLID */
				((uint64_t)1) << 11 |   /* Reversible */
				((uint64_t)1) << 13);   /* P_Key */

	path = &mad->path;
	path->dlid = htons(dlid);
	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
	path->pkey = 0xFFFF;    /* default partition */

	ret = umad_send(port_id, agent_id, (void *) &umad,
			sizeof umad.sa_mad.packet, -1 /* timeout */, 0);
	if (ret) {
		printf("ERROR - failed to send path query to SA\n");
		status = -1;
		goto err;
	}

	len = sizeof umad.sa_mad.packet;
	ret = umad_recv(port_id, (void *) &umad, &len, -1 /* timeout */);
	if (ret < 0 || ret != agent_id) {
		printf("ERROR - failed to receive path record from SA\n");
		status = -1;
		goto err;
	}

	if (umad.sa_mad.path_rec.mad_hdr.status == UMAD_SA_STATUS_SUCCESS) {
		path = &umad.sa_mad.path_rec.path;
		memcpy(dgid->raw, path->dgid.raw, 16);
	} else {
		printf("ERROR - specified LID (%u) doesn't exists\n", dlid);
		status = -1;
	}

err:
	if (agent_id >= 0)
		umad_unregister(port_id, agent_id);

	return status;
}

int admin_connect(void *dest, int type, struct admin_opts *opts)
{
	char *dgid_str = NULL;
	struct sockaddr_ib dst_addr;
	union ibv_gid dgid;
	int ret, val, port_id;
	int port = opts->server_port ? opts->server_port : admin_port;

	rsock = rsocket(AF_IB, SOCK_STREAM, 0);
	if (rsock < 0) {
		printf("rsocket ERROR %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	val = 1;
	ret = rsetsockopt(rsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
	if (ret) {
		printf("rsetsockopt rsock %d SO_REUSEADDR ERROR %d (%s)\n",
		       rsock, errno, strerror(errno));
		goto err;
	}

	ret = rsetsockopt(rsock, IPPROTO_TCP, TCP_NODELAY,
			  (void *) &val, sizeof(val));
	if (ret) {
		printf("rsetsockopt rsock %d TCP_NODELAY ERROR %d (%s)\n",
		       rsock, errno, strerror(errno));
		goto err;
	}

	dst_addr.sib_family	= AF_IB;
	dst_addr.sib_pkey	= 0xFFFF;
	dst_addr.sib_flowinfo	= 0;
	dst_addr.sib_sid	=
		htonll(((uint64_t) RDMA_PS_TCP << 16) + port);
	dst_addr.sib_sid_mask	= htonll(RDMA_IB_IP_PS_MASK);
	dst_addr.sib_scope_id	= 0;

	if (type == ADMIN_ADDR_TYPE_GID) {
		if (!strncmp((char *) dest, local_gid, strlen(local_gid))) {
			snprintf(dest_addr, 10, "localhost");
			loopback = 1;
		} else {
			snprintf(dest_addr, max(64, strlen(dgid_str)),
				 "%s", dgid_str);
		}

		dgid_str = (char *) dest_addr;

		ret = inet_pton(AF_INET6, dgid_str, &dgid);
		if (!ret)
			printf("ERROR - wrong server GID specified\n");
		else if (ret < 0)
			printf("ERROR - not supported address family\n");

		if (ret <= 0)
			goto err;
	} else if (type == ADMIN_ADDR_TYPE_LID) {
		port_id = open_port(opts->dev, opts->src_port);
		if (port_id < 0)
			goto err;

		ret = get_gid(port_id, *(uint16_t *) dest, &dgid);
		if (ret) {
			printf("ERROR - unable to get GID for LID %u\n",
			       *(uint16_t *) dest);
			close_port(port_id);
			goto err;
		}
		close_port(port_id);

		sprintf(dest_addr, "%u", *(uint16_t *) dest);
	}

	memcpy(&dst_addr.sib_addr, &dgid, sizeof(dgid));

	ret = rconnect(rsock, (const struct sockaddr *) &dst_addr,
		       sizeof(dst_addr));
	if (ret && (errno != EINPROGRESS)) {
		printf("rconnect rsock %d ERROR %d (%s)\n",
		       rsock, errno, strerror(errno));
		goto err;
	}

	return 0;

err:
	rclose(rsock);
	rsock = -1;
	return -1;
}

void admin_disconnect()
{
	if (rsock == -1)
		return;

	rclose(rsock);
}
