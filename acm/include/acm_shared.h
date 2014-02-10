/*
 * Copyright (c) 2009-2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(ACM_SHARED_H)
#define ACM_SHARED_H

#include <infiniband/acm.h>
#include <dlist.h>

#define MAX_EP_ADDR 4
#define MAX_EP_MC   2

/* Map to ACM_EP_INFO_* */
#define ACM_ADDRESS_INVALID    0x00
#define ACM_ADDRESS_NAME       0x01
#define ACM_ADDRESS_IP         0x02
#define ACM_ADDRESS_IP6        0x03
#define ACM_ADDRESS_GID        0x04
#define ACM_ADDRESS_LID        0x05
#define ACM_ADDRESS_RESERVED   0x06  /* start of reserved range */

enum acm_state {
	ACM_INIT,
	ACM_QUERY_ADDR,
	ACM_ADDR_RESOLVED,
	ACM_QUERY_ROUTE,
	ACM_READY
};

/*
 * Nested locking order: dest -> ep, dest -> port
 */
struct acm_dest {
	uint8_t                address[ACM_MAX_ADDRESS]; /* keep first */
	char                   name[ACM_MAX_ADDRESS];
	struct ibv_ah          *ah;
	struct ibv_ah_attr     av;
	struct ibv_path_record path;
	union ibv_gid          mgid;
	uint64_t               req_id;
	DLIST_ENTRY            req_queue;
	uint32_t               remote_qpn;
	pthread_mutex_t        lock;
	enum acm_state         state;
	atomic_t               refcnt;
	uint64_t	       addr_timeout;
	uint64_t	       route_timeout;
	uint8_t                addr_type;
};

/* Maintain separate virtual send queues to avoid deadlock */
struct acm_send_queue {
	int                   credits;
	DLIST_ENTRY           pending;
};

struct acm_ep {
	struct acm_port	      *port;
	struct ibv_cq         *cq;
	struct ibv_qp         *qp;
	struct ibv_mr         *mr;
	uint8_t               *recv_bufs;
	DLIST_ENTRY           entry;
	union acm_ep_info     addr[MAX_EP_ADDR];
	char                  name[MAX_EP_ADDR][ACM_MAX_ADDRESS];
	uint8_t               addr_type[MAX_EP_ADDR];
	void                  *dest_map[ACM_ADDRESS_RESERVED - 1];
	struct acm_dest       mc_dest[MAX_EP_MC];
	int                   mc_cnt;
	uint16_t              pkey_index;
	uint16_t              pkey;
	pthread_mutex_t       lock;
	struct acm_send_queue resolve_queue;
	struct acm_send_queue sa_queue;
	struct acm_send_queue resp_queue;
	DLIST_ENTRY           active_queue;
	DLIST_ENTRY           wait_queue;
	enum acm_state        state;
};
#endif /* ACM_SHARED_H */
