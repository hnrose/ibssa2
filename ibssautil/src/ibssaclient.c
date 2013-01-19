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

#include <glib.h>

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
	mad->hdr.method = UMAD_METHOD_SET;
	mad->hdr.attr_id = htons(IB_SSA_ATTR_SSAMemberRecord);

	mr->port_gid.global.subnet_prefix = client->umad_port.gid_prefix;
	mr->port_gid.global.interface_id = client->umad_port.port_guid;
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
			inet_ntop(AF_INET6, mr->port_gid.raw, strbuf, 256),
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

int ibssa_process_client(struct ibssaclient *client)
{
	int rc = 0;

	/* FIXME Read umad layer and process state machine as needed */
	return (rc);
}




