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

#include <stdio.h>
#include <string.h>
#include <infiniband/umad.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <glib.h>
#include <assert.h>

#include "ibssa_helper.h"
#include "ibssa_mad.h"
#include "ibssaclient.h"

#define DEF_CLIENT_TIMEOUT 100
#define DEF_CLIENT_RETRY 3

struct ibssaservice
{
	uint64_t             guid;
	enum service_state   state;
};

struct ibssaclient
{
	GHashTable      * services;
	/* umad */
	umad_port_t       umad_port;
	int               mad_fd;
	int               agent_id;
	int               timeout_ms;
	int               retries;
	int               umaddebug;
	uint32_t          tid;
};

guint hash_uint64(gconstpointer key)
{
	uint64_t k = *(uint64_t *)key;
	return ((guint)k);
}

gboolean hash_equal(gconstpointer a, gconstpointer b)
{
	uint64_t aa = *(uint64_t *)a;
	uint64_t bb = *(uint64_t *)b;
	return (aa == bb);
}

void free_ibssaservice(void *s)
{
	free(s);
}

struct ibssaclient * ibssa_alloc_client(umad_port_t *umad_port)
{
	struct ibssaclient *client = calloc(1, sizeof(*client));
	if (!client) {
		return (NULL);
	}

	/* This is an expensive way to copy the umad_port but it is easy */
	umad_get_port(umad_port->ca_name, umad_port->portnum, &client->umad_port);
	client->mad_fd = -1;
	client->agent_id = -1;

	client->timeout_ms = DEF_CLIENT_TIMEOUT;
	client->retries = DEF_CLIENT_RETRY;
	client->services = g_hash_table_new_full(hash_uint64, hash_equal,
					free, free_ibssaservice);
	client->tid = 1;

	return (client);
}

void ibssa_set_client_timeout(struct ibssaclient *client, int timeout_ms)
{
	client->timeout_ms = timeout_ms;
}
void ibssa_set_client_retries(struct ibssaclient *client, int retries)
{
	client->retries = retries;
}

int ibssa_open_client(struct ibssaclient *client)
{
	int id = -1;

	client->mad_fd = umad_open_port(client->umad_port.ca_name,
					client->umad_port.portnum);
	if (client->mad_fd < 0) {
		fprintf(stderr, "Failed to open port %s:%d\n",
			client->umad_port.ca_name,
			client->umad_port.portnum);
		return (client->mad_fd);
	}

	id = umad_register(client->mad_fd, IB_SSA_CLASS, IB_SSA_CLASS_VERSION, 0, NULL);
	if (id < 0) {
		fprintf(stderr, "Failed to register class %d\n", IB_SSA_CLASS);
		umad_close_port(client->mad_fd);
		return (id);
	}
	client->agent_id = id;
	return (0);
}

void ibssa_close_client(struct ibssaclient *client)
{
	umad_unregister(client->mad_fd, client->agent_id);
	umad_close_port(client->mad_fd);
	umad_release_port(&client->umad_port);
}

void ibssa_free_client(struct ibssaclient *client)
{
	free(client);
}

enum service_state ibssa_get_service_state(struct ibssaclient *client,
			uint64_t service_guid)
{
	struct ibssaservice *service = g_hash_table_lookup(client->services, &service_guid);
	return (service->state);
}

static void init_ssa_mad_hdr(struct ibssaclient *client, struct ib_mad_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->base_version = 1;
	hdr->mgmt_class = IB_SSA_CLASS;
	hdr->class_version = IB_SSA_CLASS_VERSION;
}

static uint32_t get_tid(struct ibssaclient *client)
{
	uint32_t rc = client->tid;
	client->tid++;
	if (!client->tid) {
		client->tid = 1;
	}
	return (rc);
}

int ibssa_join_client_service(struct ibssaclient *client, struct service *service)
{
	int rc = 0;
	char strbuf[256];
	char buf[UMAD_ALLOC_SIZE];
	ib_user_mad_t * umad = (ib_user_mad_t *)buf;

	struct ib_ssa_mad *mad = umad_get_mad((void *)umad);
	struct ib_ssa_member_record *mr = (struct ib_ssa_member_record *)&mad->data;

	struct ibssaservice *new_service = NULL;

	if (!client || client->mad_fd < 0 || !service)
		return (-EINVAL);

	new_service = calloc(1, sizeof(*new_service));
	if (!new_service)
		return (-ENOMEM);

	memset(umad, 0, UMAD_ALLOC_SIZE);

	init_ssa_mad_hdr(client, &mad->hdr);
	mad->hdr.method = IB_SSA_METHOD_SET;
	mad->hdr.attr_id = htons(IB_SSA_ATTR_SSAMemberRecord);
	mad->hdr.tid = htonll(get_tid(client));

	mr->port_gid.global.subnet_prefix = htonll(client->umad_port.gid_prefix);
	mr->port_gid.global.interface_id = htonll(client->umad_port.port_guid);
	mr->service_id = htonll(service->local_service_id);
	mr->pkey = htons(service->pkey);

	mr->node_type = service->node_type;
	mr->ssa_version = IB_SSA_VERSION;
	mr->service_guid = htonll(service->service_guid);

	umad_set_addr(umad, client->umad_port.sm_lid, 1,
			client->umad_port.sm_sl, 0x80010000);

	if ((rc = umad_send(client->mad_fd, client->agent_id, umad, IB_SSA_MAD_SIZE,
			client->timeout_ms, client->retries)) == 0) {
		uint64_t *hid = calloc(1, sizeof(*hid));
		*hid = service->service_guid;
		fprintf(stderr, "Join sent from %s to %d\n",
			net_gid_2_str(&mr->port_gid, strbuf, 256),
			client->umad_port.sm_lid);
		new_service->guid = service->service_guid;
		new_service->state = IBSSA_STATE_JOINING;
		g_hash_table_insert(client->services, hid, new_service);
	} else {
		fprintf(stderr, "Send Join failed : %d\n", rc);
		free(service);
	}

	return (rc);
}

static int handle_getresp_member_rec(struct ibssaclient *client,
		struct ib_ssa_mad *mad)
{
	int rc = 0;
	if (mad->hdr.status == 0) {
		uint64_t hid;
		struct ibssaservice * ser;
		struct ib_ssa_member_record * mr = (struct ib_ssa_member_record *)mad->data;

		fprintf(stderr, "Join succeeded\n");
		hid = ntohll(mr->service_guid);
		ser = g_hash_table_lookup(client->services, &hid);
		if (!ser) {
			fprintf(stderr, "Service not found???  0x%"PRIx64"\n", hid);
			rc = -1;
		} else {
			ser->state = IBSSA_STATE_ORPHAN;
		}
	} else {
		rc = -1;
	}
	return (rc);
}

static int handle_set_info_rec(struct ibssaclient * client, struct ib_ssa_mad * mad)
{
	fprintf(stderr, "Parent info\n");
}

static int ibssa_process_mad(struct ibssaclient *client, struct ib_ssa_mad *mad)
{
	int rc = 0;
	switch ((mad->hdr.method << 16) | ntohs(mad->hdr.attr_id))
	{
		case ((IB_SSA_METHOD_SET << 16) | IB_SSA_ATTR_SSAInfoRecord):
			rc = handle_set_info_rec(client, mad);
			break;
		case ((IB_SSA_METHOD_GETRESP << 16) | IB_SSA_ATTR_SSAMemberRecord):
			rc = handle_getresp_member_rec(client, mad);
			break;
		case ((IB_SSA_METHOD_DELETE << 16) | IB_SSA_ATTR_SSAMemberRecord):
			break;
		case IB_SSA_METHOD_GET:
		case IB_SSA_METHOD_DELETERESP:
		default:
			break;
	}
	return (rc);
}

int ibssa_process_client(struct ibssaclient *client)
{
	int rc = 0;
	char buf[UMAD_ALLOC_SIZE];
	int len = IB_SSA_MAD_SIZE;

	rc = umad_recv(client->mad_fd, buf, &len, 0);
	if (rc >= 0) {
		assert(rc == client->agent_id);
		rc = ibssa_process_mad(client, umad_get_mad(buf));
	} else if (rc == -EWOULDBLOCK) {
		rc = 0;
	}
	return (rc);
}



