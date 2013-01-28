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

#ifndef __IBSSA_CLIENT_H__
#define __IBSSA_CLIENT_H__

#include <infiniband/verbs.h>
#include <ibssa_control.h>

/* This should be treated as opaque by callers */
struct ibssaclient;

struct ibssaclient * ibssa_alloc_client(umad_port_t *umad_port);
void ibssa_free_client(struct ibssaclient *client);

int  ibssa_open_client(struct ibssaclient *client);
void ibssa_close_client(struct ibssaclient *client);

void ibssa_set_client_timeout(struct ibssaclient *client, int timeout_ms);
void ibssa_set_client_retries(struct ibssaclient *client, int retries);

enum service_state ibssa_get_service_state(struct ibssaclient *client,
				uint64_t service_guid);

struct service {
	uint64_t local_service_id;
	uint64_t service_guid; /* enum service_guid */
	uint16_t pkey;
	uint8_t  node_type;
};
int ibssa_join_client_service(struct ibssaclient *client, struct service *service);

/* user calls this to process client state machine */
int ibssa_process_client(struct ibssaclient *client);



#endif /* __IBSSA_CLIENT_H__ */
