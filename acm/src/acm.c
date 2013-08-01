/*
 * Copyright (c) 2009-2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <osd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <syslog.h>
#include <rdma/rsocket.h>
#include <infiniband/verbs.h>
#include <infiniband/ssa_mad.h>
#include <search.h>
#include <common.h>
#include <ssa_log.h>
#include <inttypes.h>
#include "acm_mad.h"
#include <acm_shared.h>
#include <infiniband/ssa_db.h>
#include <infiniband/ssa_db_helper.h>
#include <infiniband/ssa_prdb.h>

#define src_out     data[0]

#define IB_LID_MCAST_START 0xc000

#define GET_PORT_FIELD_PTR(ptr, type, field) \
	((type *)((acm_mode == ACM_MODE_ACM) ? \
		  ((void *) ptr + offsetof(struct acm_port, field)) : \
		  ((void *) ptr + offsetof(struct ssa_port, field))))

enum acm_addr_prot {
	ACM_ADDR_PROT_ACM
};

enum acm_route_prot {
	ACM_ROUTE_PROT_ACM,
	ACM_ROUTE_PROT_SA
};

enum acm_loopback_prot {
	ACM_LOOPBACK_PROT_NONE,
	ACM_LOOPBACK_PROT_LOCAL
};

enum acm_route_preload {
	ACM_ROUTE_PRELOAD_NONE,
	ACM_ROUTE_PRELOAD_OSM_FULL_V1,
	ACM_ROUTE_PRELOAD_ACCESS_V1
};

enum acm_mode {
	ACM_MODE_ACM,
	ACM_MODE_SSA
};

struct acm_port {
	struct acm_device   *dev;
	DLIST_ENTRY         ep_list;
	pthread_mutex_t     lock;
	int                 mad_portid;
	int                 mad_agentid;
	struct acm_dest     sa_dest;
	enum ibv_port_state state;
	enum ibv_mtu        mtu;
	enum ibv_rate       rate;
	int                 subnet_timeout;
	int                 gid_cnt;
	uint16_t            pkey_cnt;
	uint16_t            lid;
	uint16_t            lid_mask;
	uint8_t             port_num;
};

struct acm_device {
	struct ibv_context      *verbs;
	struct ibv_comp_channel *channel;
	struct ibv_pd           *pd;
	uint64_t                guid;
	DLIST_ENTRY             entry;
	int                     port_cnt;
	struct acm_port         port[0];
};

struct acm_send_msg {
	DLIST_ENTRY          entry;
	struct acm_ep        *ep;
	struct acm_dest      *dest;
	struct ibv_ah        *ah;
	void                 *context;
	void                 (*resp_handler)(struct acm_send_msg *req,
	                                     struct ibv_wc *wc, struct acm_mad *resp);
	struct acm_send_queue *req_queue;
	struct ibv_mr        *mr;
	struct ibv_send_wr   wr;
	struct ibv_sge       sge;
	uint64_t             expires;
	int                  tries;
	uint8_t              data[ACM_SEND_SIZE];
};

struct acm_client {
	pthread_mutex_t lock;   /* acquire ep lock first */
	int             sock;
	int             index;
	atomic_t        refcnt;
};

struct acm_request {
	struct acm_client *client;
	DLIST_ENTRY       entry;
	struct acm_msg    msg;
};

union socket_addr {
	struct sockaddr     sa;
	struct sockaddr_in  sin;
	struct sockaddr_in6 sin6;
};

static struct ssa_class ssa;
static pthread_t event_thread, retry_thread, comp_thread, ctrl_thread, query_thread;

static DLIST_ENTRY device_list;

static atomic_t tid;
static DLIST_ENTRY timeout_list;
static event_t timeout_event;
static atomic_t wait_cnt;

static int listen_socket;
static struct acm_client client_array[FD_SETSIZE - 1];

static atomic_t counter[ACM_MAX_COUNTER];

static int acm_issue_query_done;

enum acm_addr_preload {
	ACM_ADDR_PRELOAD_NONE,
	ACM_ADDR_PRELOAD_HOSTS
};

/*
 * Service options - may be set through ibacm_opts.cfg file.
 */
static char *acme = BINDIR "/ib_acme -A";
static char *opts_file = RDMA_CONF_DIR "/" ACM_OPTS_FILE;
static char *addr_file = RDMA_CONF_DIR "/" ACM_ADDR_FILE;
static char route_data_file[128] = RDMA_CONF_DIR "/ibacm_route.data";
static char route_data_dir[128] = RDMA_CONF_DIR "/ssa_db";
static char addr_data_file[128] = RDMA_CONF_DIR "/ibacm_hosts.data";
static char log_file[128] = "/var/log/ibacm.log";
static char lock_file[128] = "/var/run/ibacm.pid";
static enum acm_addr_prot addr_prot = ACM_ADDR_PROT_ACM;
static int addr_timeout = 1440;
static enum acm_route_prot route_prot = ACM_ROUTE_PROT_SA;
static int route_timeout = -1;
static enum acm_loopback_prot loopback_prot = ACM_LOOPBACK_PROT_LOCAL;
static short server_port = 6125;
static int timeout = 2000;
static int retries = 2;
static int resolve_depth = 1;
static int sa_depth = 1;
static int send_depth = 1;
static int recv_depth = 1024;
static uint8_t min_mtu = IBV_MTU_2048;
static uint8_t min_rate = IBV_RATE_10_GBPS;
static enum acm_route_preload route_preload;
static enum acm_addr_preload addr_preload;
static enum acm_mode acm_mode = ACM_MODE_SSA;
static uint64_t *lid2guid_cached = NULL;
static useconds_t acm_query_timeout = ACM_DEFAULT_QUERY_TIMEOUT;
static int acm_query_retries = ACM_DEFAULT_QUERY_RETRIES;

extern int log_flush;
extern int accum_log_file;
extern int prdb_dump;
extern char prdb_dump_dir[128];
extern short prdb_port;
extern int keepalive;
extern int reconnect_timeout;
extern int reconnect_max_count;
extern int rejoin_timeout;

static void
acm_format_name(int level, char *name, size_t name_size,
		uint8_t addr_type, uint8_t *addr, size_t addr_size)
{
	enum ssa_addr_type at;

	switch (addr_type) {
	case ACM_EP_INFO_NAME:
		at = SSA_ADDR_NAME;
		break;
	case ACM_EP_INFO_ADDRESS_IP:
		at = SSA_ADDR_IP;
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		at = SSA_ADDR_IP6;
		break;
	case ACM_ADDRESS_GID:
		at = SSA_ADDR_GID;
		break;
	case ACM_EP_INFO_PATH:
		at = SSA_ADDR_PATH;
		break;
	case ACM_ADDRESS_LID:
		at = SSA_ADDR_LID;
		break;
	default:
		at = 0;
		break;
	}

	ssa_sprint_addr(level, name, name_size, at, addr, addr_size);
}

static int ib_any_gid(union ibv_gid *gid)
{
	return ((gid->global.subnet_prefix | gid->global.interface_id) == 0);
}

static int acm_compare_dest(const void *dest1, const void *dest2)
{
	return memcmp(dest1, dest2, ACM_MAX_ADDRESS);
}

static int acm_compare_dest_by_lid(const void *dest1, const void *dest2)
{
	return *(uint16_t *)dest1 - *(uint16_t *)dest2;
}

static int acm_compare_dest_by_gid(const void *dest1, const void *dest2)
{
	return memcmp(dest1, dest2, sizeof(union ibv_gid));
}

void
acm_set_dest_addr(struct acm_dest *dest, uint8_t addr_type, uint8_t *addr, size_t size)
{
	memcpy(dest->address, addr, size);
	dest->addr_type = addr_type;
	acm_format_name(SSA_LOG_DEFAULT, dest->name, sizeof dest->name, addr_type, addr, size);
}

void
acm_init_dest(struct acm_dest *dest, uint8_t addr_type, uint8_t *addr, size_t size)
{
	DListInit(&dest->req_queue);
	atomic_init(&dest->refcnt);
	atomic_set(&dest->refcnt, 1);
	pthread_mutex_init(&dest->lock, NULL);
	if (size)
		acm_set_dest_addr(dest, addr_type, addr, size);
}

static struct acm_dest *
acm_alloc_dest(uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest;

	dest = calloc(1, sizeof *dest);
	if (!dest) {
		ssa_log_err(0, "unable to allocate dest\n");
		return NULL;
	}

	acm_init_dest(dest, addr_type, addr, ACM_MAX_ADDRESS);
	ssa_log(SSA_LOG_CTRL, "%s\n", dest->name);
	return dest;
}

/* Caller must hold ep lock. */
static struct acm_dest *
acm_get_dest(struct acm_ep *ep, uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest, **tdest;

	if (addr_type == ACM_ADDRESS_LID)
		tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_lid);
	else if (addr_type == ACM_ADDRESS_GID)
		tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_gid);
	else
		tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest);
	if (tdest) {
		dest = *tdest;
		(void) atomic_inc(&dest->refcnt);
		ssa_log(SSA_LOG_CTRL, "%s\n", dest->name);
	} else {
		dest = NULL;
		acm_format_name(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
				log_data, sizeof log_data,
				addr_type, addr, ACM_MAX_ADDRESS);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "%s not found\n", log_data);
	}
	return dest;
}

static void
acm_put_dest(struct acm_dest *dest)
{
	ssa_log(SSA_LOG_CTRL, "%s\n", dest->name);
	if (atomic_dec(&dest->refcnt) == 0) {
		free(dest);
	}
}

static struct acm_dest *
acm_acquire_dest(struct acm_ep *ep, uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest;

	acm_format_name(SSA_LOG_CTRL, log_data, sizeof log_data,
			addr_type, addr, ACM_MAX_ADDRESS);
	ssa_log(SSA_LOG_CTRL, "%s\n", log_data);
	pthread_mutex_lock(&ep->lock);
	dest = acm_get_dest(ep, addr_type, addr);
	if (!dest) {
		dest = acm_alloc_dest(addr_type, addr);
		if (dest) {
			if (addr_type == ACM_ADDRESS_LID)
				tsearch(dest, &ep->dest_map[addr_type - 1], acm_compare_dest_by_lid);
			else if (addr_type == ACM_ADDRESS_GID)
				tsearch(dest, &ep->dest_map[addr_type - 1], acm_compare_dest_by_gid);
			else
				tsearch(dest, &ep->dest_map[addr_type - 1], acm_compare_dest);
			(void) atomic_inc(&dest->refcnt);
		}
	}
	pthread_mutex_unlock(&ep->lock);
	return dest;
}

static struct acm_dest *
acm_acquire_sa_dest(void *port)
{
	struct acm_dest *dest = NULL;
	enum ibv_port_state *state;
	pthread_mutex_t *lock;

	lock = GET_PORT_FIELD_PTR(port, pthread_mutex_t, lock);
	pthread_mutex_lock(lock);
	state = GET_PORT_FIELD_PTR(port, enum ibv_port_state, state);
	if (*state == IBV_PORT_ACTIVE) {
		dest = GET_PORT_FIELD_PTR(port, struct acm_dest, sa_dest);
		atomic_inc(&dest->refcnt);
	}
	pthread_mutex_unlock(lock);
	return dest;
}

static void acm_release_sa_dest(struct acm_dest *dest)
{
	atomic_dec(&dest->refcnt);
}

static void acm_update_sa_dest(struct ssa_port *port)
{
	uint16_t old_sm_lid;
	be16_t sm_lid;

	if (!port || port->sa_dest.av.dlid == port->sm_lid)
		return;

	old_sm_lid = port->sa_dest.av.dlid;

	/* We wait for the SA destination to be released */
	while (atomic_get(&port->sa_dest.refcnt) > 1)
		sleep(0);

	pthread_mutex_lock(&port->lock);
	ibv_destroy_ah(port->sa_dest.ah);

	port->sa_dest.av.src_path_bits = 0;
	port->sa_dest.av.dlid = port->sm_lid;
	port->sa_dest.av.sl = port->sm_sl;
	port->sa_dest.av.port_num = port->port_num;
	port->sa_dest.remote_qpn = 1;
	sm_lid = htons(port->sm_lid);
	acm_set_dest_addr(&port->sa_dest, ACM_ADDRESS_LID,
			  (uint8_t *) &sm_lid, sizeof(sm_lid));

	port->sa_dest.ah = ibv_create_ah(port->dev->pd,
					 &port->sa_dest.av);
	if (!port->sa_dest.ah) {
		pthread_mutex_unlock(&port->lock);
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to create %s port SA dest address handle\n",
			    port->name);
		return;
	}

	pthread_mutex_unlock(&port->lock);

	ssa_log(SSA_LOG_DEFAULT,
		"%s SA dest SM LID was updated to %u (previous SM LID %u)\n",
		port->name, ntohs(sm_lid), old_sm_lid);
}

/* Caller must hold ep lock. */
//static void
//acm_remove_dest(struct acm_ep *ep, struct acm_dest *dest)
//{
//	ssa_log(SSA_LOG_VERBOSE, "%s\n", dest->name);
//	if (dest->addr_type == ACM_ADDRESS_LID)
//		tdelete(dest->address, &ep->dest_map[dest->addr_type - 1], acm_compare_dest_by_lid);
//	else if (dest->addr_type == ACM_ADDRESS_GID)
//		tdelete(dest->address, &ep->dest_map[dest->addr_type - 1], acm_compare_dest_by_gid);
//	else
//		tdelete(dest->address, &ep->dest_map[dest->addr_type - 1], acm_compare_dest);
//	acm_put_dest(dest);
//}

static struct acm_request *
acm_alloc_req(struct acm_client *client, struct acm_msg *msg)
{
	struct acm_request *req;

	req = calloc(1, sizeof *req);
	if (!req) {
		ssa_log_err(0, "unable to alloc client request\n");
		return NULL;
	}

	(void) atomic_inc(&client->refcnt);
	req->client = client;
	memcpy(&req->msg, msg, sizeof(req->msg));
	ssa_log(SSA_LOG_VERBOSE, "client %d, req %p\n", client->index, req);
	return req;
}

static void
acm_free_req(struct acm_request *req)
{
	ssa_log(SSA_LOG_VERBOSE, "%p\n", req);
	(void) atomic_dec(&req->client->refcnt);
	free(req);
}

static struct acm_send_msg *
acm_alloc_send(struct acm_ep *ep, struct acm_dest *dest, size_t size)
{
	struct acm_send_msg *msg;
	struct ibv_pd *pd;

	if (acm_mode == ACM_MODE_ACM)
		pd = ((struct acm_port *)ep->port)->dev->pd;
	else /* ACM_MODE_SSA */
		pd = ((struct ssa_port *)ep->port)->dev->pd;

	msg = (struct acm_send_msg *) calloc(1, sizeof *msg);
	if (!msg) {
		ssa_log_err(0, "unable to allocate send buffer\n");
		return NULL;
	}

	msg->ep = ep;
	msg->mr = ibv_reg_mr(pd, msg->data, size, 0);
	if (!msg->mr) {
		ssa_log_err(0, "failed to register send buffer\n");
		goto err1;
	}

	if (!dest->ah) {
		msg->ah = ibv_create_ah(pd, &dest->av);
		if (!msg->ah) {
			ssa_log_err(0, "unable to create ah\n");
			goto err2;
		}
		msg->wr.wr.ud.ah = msg->ah;
	} else {
		msg->wr.wr.ud.ah = dest->ah;
	}

	ssa_log(SSA_LOG_VERBOSE, "get dest %s\n", dest->name);
	(void) atomic_inc(&dest->refcnt);
	msg->dest = dest;

	msg->wr.next = NULL;
	msg->wr.sg_list = &msg->sge;
	msg->wr.num_sge = 1;
	msg->wr.opcode = IBV_WR_SEND;
	msg->wr.send_flags = IBV_SEND_SIGNALED;
	msg->wr.wr_id = (uintptr_t) msg;
	msg->wr.wr.ud.remote_qpn = dest->remote_qpn;
	msg->wr.wr.ud.remote_qkey = ACM_QKEY;

	msg->sge.length = size;
	msg->sge.lkey = msg->mr->lkey;
	msg->sge.addr = (uintptr_t) msg->data;
	ssa_log(SSA_LOG_VERBOSE, "%p\n", msg);
	return msg;

err2:
	ibv_dereg_mr(msg->mr);
err1:
	free(msg);
	return NULL;
}

static void
acm_init_send_req(struct acm_send_msg *msg, void *context, 
	void (*resp_handler)(struct acm_send_msg *req,
		struct ibv_wc *wc, struct acm_mad *resp))
{
	ssa_log(SSA_LOG_VERBOSE, "%p\n", msg);
	msg->tries = retries + 1;
	msg->context = context;
	msg->resp_handler = resp_handler;
}

static void acm_free_send(struct acm_send_msg *msg)
{
	ssa_log(SSA_LOG_VERBOSE, "%p\n", msg);
	if (msg->ah)
		ibv_destroy_ah(msg->ah);
	ibv_dereg_mr(msg->mr);
	acm_put_dest(msg->dest);
	free(msg);
}

static void acm_post_send(struct acm_send_queue *queue, struct acm_send_msg *msg)
{
	struct acm_ep *ep = msg->ep;
	struct ibv_send_wr *bad_wr;

	msg->req_queue = queue;
	pthread_mutex_lock(&ep->lock);
	if (queue->credits) {
		ssa_log(SSA_LOG_VERBOSE, "posting send to QP\n");
		queue->credits--;
		DListInsertTail(&msg->entry, &ep->active_queue);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	} else {
		ssa_log(SSA_LOG_VERBOSE, "no sends available, queuing message\n");
		DListInsertTail(&msg->entry, &queue->pending);
	}
	pthread_mutex_unlock(&ep->lock);
}

static void acm_post_recv(struct acm_ep *ep, uint64_t address)
{
	struct ibv_recv_wr wr, *bad_wr;
	struct ibv_sge sge;

	wr.next = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = address;

	sge.length = ACM_RECV_SIZE;
	sge.lkey = ep->mr->lkey;
	sge.addr = address;

	ibv_post_recv(ep->qp, &wr, &bad_wr);
}

/* Caller must hold ep lock */
static void acm_send_available(struct acm_ep *ep, struct acm_send_queue *queue)
{
	struct acm_send_msg *msg;
	struct ibv_send_wr *bad_wr;
	DLIST_ENTRY *entry;

	if (DListEmpty(&queue->pending)) {
		queue->credits++;
	} else {
		ssa_log(SSA_LOG_VERBOSE, "posting queued send message\n");
		entry = queue->pending.Next;
		DListRemove(entry);
		msg = container_of(entry, struct acm_send_msg, entry);
		DListInsertTail(&msg->entry, &ep->active_queue);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	}
}

static void acm_complete_send(struct acm_send_msg *msg)
{
	struct acm_ep *ep = msg->ep;
	int *subnet_timeout;

	pthread_mutex_lock(&ep->lock);
	DListRemove(&msg->entry);
	if (msg->tries) {
		subnet_timeout = GET_PORT_FIELD_PTR(ep->port, int, subnet_timeout);
		ssa_log(SSA_LOG_VERBOSE, "waiting for response\n");
		msg->expires = time_stamp_ms() + *subnet_timeout + timeout;
		DListInsertTail(&msg->entry, &ep->wait_queue);
		if (atomic_inc(&wait_cnt) == 1)
			event_signal(&timeout_event);
	} else {
		ssa_log(SSA_LOG_VERBOSE, "freeing\n");
		acm_send_available(ep, msg->req_queue);
		acm_free_send(msg);
	}
	pthread_mutex_unlock(&ep->lock);
}

static struct acm_send_msg *acm_get_request(struct acm_ep *ep, uint64_t tid, int *free)
{
	struct acm_send_msg *msg, *req = NULL;
	struct acm_mad *mad;
	DLIST_ENTRY *entry, *next;

	ssa_log(SSA_LOG_VERBOSE, "\n");
	pthread_mutex_lock(&ep->lock);
	for (entry = ep->wait_queue.Next; entry != &ep->wait_queue; entry = next) {
		next = entry->Next;
		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) msg->data;
		if (mad->tid == tid) {
			ssa_log(SSA_LOG_VERBOSE, "match found in wait queue\n");
			req = msg;
			DListRemove(entry);
			(void) atomic_dec(&wait_cnt);
			acm_send_available(ep, msg->req_queue);
			*free = 1;
			goto unlock;
		}
	}

	for (entry = ep->active_queue.Next; entry != &ep->active_queue; entry = entry->Next) {
		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) msg->data;
		if (mad->tid == tid && msg->tries) {
			ssa_log(SSA_LOG_VERBOSE, "match found in active queue\n");
			req = msg;
			req->tries = 0;
			*free = 0;
			break;
		}
	}
unlock:
	pthread_mutex_unlock(&ep->lock);
	return req;
}

static uint8_t acm_gid_index(void *port, union ibv_gid *gid)
{
	union ibv_gid cmp_gid;
	struct ibv_context *verbs;
	int *gid_cnt;
	uint8_t *port_num;
	uint8_t i;

	if (acm_mode == ACM_MODE_ACM)
		verbs = ((struct acm_port *)port)->dev->verbs;
	else /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)port)->dev->verbs;

	gid_cnt = GET_PORT_FIELD_PTR(port, int, gid_cnt);
	port_num = GET_PORT_FIELD_PTR(port, uint8_t, port_num);
	for (i = 0; i < *gid_cnt; i++) {
		ibv_query_gid(verbs, *port_num, i, &cmp_gid);
		if (!memcmp(&cmp_gid, gid, sizeof cmp_gid))
			break;
	}
	return i;
}

static int acm_mc_index(struct acm_ep *ep, union ibv_gid *gid)
{
	int i;

	for (i = 0; i < ep->mc_cnt; i++) {
		if (!memcmp(&ep->mc_dest[i].address, gid, sizeof(*gid)))
			return i;
	}
	return -1;
}

/* Multicast groups are ordered lowest to highest preference. */
static int acm_best_mc_index(struct acm_ep *ep, struct acm_resolve_rec *rec)
{
	int i, index;

	for (i = min(rec->gid_cnt, ACM_MAX_GID_COUNT) - 1; i >= 0; i--) {
		index = acm_mc_index(ep, &rec->gid[i]);
		if (index >= 0) {
			return index;
		}
	}
	return -1;
}

static void
acm_record_mc_av(struct acm_port *port, struct ib_mc_member_rec *mc_rec,
	struct acm_dest *dest)
{
	uint32_t sl_flow_hop;

	sl_flow_hop = ntohl(mc_rec->sl_flow_hop);

	dest->av.dlid = ntohs(mc_rec->mlid);
	dest->av.sl = (uint8_t) (sl_flow_hop >> 28);
	dest->av.src_path_bits = port->sa_dest.av.src_path_bits;
	dest->av.static_rate = mc_rec->rate & 0x3F;
	dest->av.port_num = port->port_num;

	dest->av.is_global = 1;
	dest->av.grh.dgid = mc_rec->mgid;
	dest->av.grh.flow_label = (sl_flow_hop >> 8) & 0xFFFFF;
	dest->av.grh.sgid_index = acm_gid_index(port, &mc_rec->port_gid);
	dest->av.grh.hop_limit = (uint8_t) sl_flow_hop;
	dest->av.grh.traffic_class = mc_rec->tclass;

	dest->path.dgid = mc_rec->mgid;
	dest->path.sgid = mc_rec->port_gid;
	dest->path.dlid = mc_rec->mlid;
	dest->path.slid = htons(port->lid) | port->sa_dest.av.src_path_bits;
	dest->path.flowlabel_hoplimit = htonl(sl_flow_hop & 0xFFFFFFF);
	dest->path.tclass = mc_rec->tclass;
	dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	dest->path.pkey = mc_rec->pkey;
	dest->path.qosclass_sl = htons((uint16_t) (sl_flow_hop >> 28));
	dest->path.mtu = mc_rec->mtu;
	dest->path.rate = mc_rec->rate;
	dest->path.packetlifetime = mc_rec->packet_lifetime;
}

/* Always send the GRH to transfer GID data to remote side */
static void
acm_init_path_av(struct acm_port *port, struct acm_dest *dest)
{
	uint32_t flow_hop;

	dest->av.dlid = ntohs(dest->path.dlid);
	dest->av.sl = ntohs(dest->path.qosclass_sl) & 0xF;
	dest->av.src_path_bits = dest->path.slid & 0x7F;
	dest->av.static_rate = dest->path.rate & 0x3F;
	dest->av.port_num = port->port_num;

	flow_hop = ntohl(dest->path.flowlabel_hoplimit);
	dest->av.is_global = 1;
	dest->av.grh.flow_label = (flow_hop >> 8) & 0xFFFFF;
	dest->av.grh.sgid_index = acm_gid_index(port, &dest->path.sgid);
	dest->av.grh.hop_limit = (uint8_t) flow_hop;
	dest->av.grh.traffic_class = dest->path.tclass;
}

static void acm_process_join_resp(struct acm_ep *ep, struct ib_user_mad *umad)
{
	struct acm_dest *dest;
	struct ib_mc_member_rec *mc_rec;
	struct ib_sa_mad *mad;
	int index, ret;

	mad = (struct ib_sa_mad *) umad->data;
	ssa_log(SSA_LOG_VERBOSE, "response status: 0x%x, mad status: 0x%x\n",
		umad->status, mad->status);
	if (umad->status) {
		ssa_log_err(0, "send join failed 0x%x\n", umad->status);
		return;
	}
	if (mad->status) {
		ssa_log_err(0, "join response status 0x%x\n", mad->status);
		return;
	}

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	pthread_mutex_lock(&ep->lock);
	index = acm_mc_index(ep, &mc_rec->mgid);
	if (index < 0) {
		ssa_log_err(0, "MGID in join response not found\n");
		goto out;
	}

	dest = &ep->mc_dest[index];
	dest->remote_qpn = IB_MC_QPN;
	dest->mgid = mc_rec->mgid;
	acm_record_mc_av(ep->port, mc_rec, dest);

	if (index == 0) {
		dest->ah =
		    ibv_create_ah(((struct acm_port *)ep->port)->dev->pd, &dest->av);
		if (!dest->ah) {
			ssa_log_err(0, "unable to create ah\n");
			goto out;
		}
		ret = ibv_attach_mcast(ep->qp, &mc_rec->mgid, mc_rec->mlid);
		if (ret) {
			ssa_log_err(0, "unable to attach QP to multicast group\n");
			goto out;
		}
	}

	atomic_set(&dest->refcnt, 1);
	dest->state = ACM_READY;
	ssa_log(SSA_LOG_VERBOSE, "join successful\n");
out:
	pthread_mutex_unlock(&ep->lock);
}

static int acm_addr_index(struct acm_ep *ep, uint8_t *addr, uint8_t addr_type)
{
	int i;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (ep->addr_type[i] != addr_type)
			continue;

		if ((addr_type == ACM_ADDRESS_NAME &&
			!strncasecmp((char *) ep->addr[i].name,
				(char *) addr, ACM_MAX_ADDRESS)) ||
			!memcmp(ep->addr[i].addr, addr, ACM_MAX_ADDRESS))
			return i;
	}
	return -1;
}

static uint8_t
acm_record_acm_route(struct acm_ep *ep, struct acm_dest *dest)
{
	int i;

	ssa_log_func(SSA_LOG_VERBOSE);
	for (i = 0; i < MAX_EP_MC; i++) {
		if (!memcmp(&dest->mgid, &ep->mc_dest[i].mgid, sizeof dest->mgid))
			break;
	}
	if (i == MAX_EP_MC) {
		ssa_log_err(0, "cannot match mgid\n");
		return ACM_STATUS_EINVAL;
	}

	dest->path = ep->mc_dest[i].path;
	dest->path.dgid = dest->av.grh.dgid;
	dest->path.dlid = htons(dest->av.dlid);
	dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
	dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
	ssa_log(SSA_LOG_VERBOSE, "timeout addr %llu route %llu\n",
		dest->addr_timeout, dest->route_timeout);
	dest->state = ACM_READY;
	return ACM_STATUS_SUCCESS;
}

static void acm_init_path_query(struct ib_sa_mad *mad)
{
	ssa_log_func(SSA_LOG_VERBOSE);
	mad->base_version = UMAD_BASE_VERSION;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = UMAD_SA_CLASS_VERSION;
	mad->method = IB_METHOD_GET;
	mad->tid = (uint64_t) atomic_inc(&tid);
	mad->attr_id = IB_SA_ATTR_PATH_REC;
}

static uint64_t acm_path_comp_mask(struct ibv_path_record *path)
{
	uint32_t fl_hop;
	uint16_t qos_sl;
	uint64_t comp_mask = 0;

	ssa_log_func(SSA_LOG_VERBOSE);
	if (path->service_id)
		comp_mask |= IB_COMP_MASK_PR_SERVICE_ID;
	if (!ib_any_gid(&path->dgid))
		comp_mask |= IB_COMP_MASK_PR_DGID;
	if (!ib_any_gid(&path->sgid))
		comp_mask |= IB_COMP_MASK_PR_SGID;
	if (path->dlid)
		comp_mask |= IB_COMP_MASK_PR_DLID;
	if (path->slid)
		comp_mask |= IB_COMP_MASK_PR_SLID;

	fl_hop = ntohl(path->flowlabel_hoplimit);
	if (fl_hop >> 8)
		comp_mask |= IB_COMP_MASK_PR_FLOW_LABEL;
	if (fl_hop & 0xFF)
		comp_mask |= IB_COMP_MASK_PR_HOP_LIMIT;

	if (path->tclass)
		comp_mask |= IB_COMP_MASK_PR_TCLASS;
	if (path->reversible_numpath & 0x80)
		comp_mask |= IB_COMP_MASK_PR_REVERSIBLE;
	if (path->pkey)
		comp_mask |= IB_COMP_MASK_PR_PKEY;

	qos_sl = ntohs(path->qosclass_sl);
	if (qos_sl >> 4)
		comp_mask |= IB_COMP_MASK_PR_QOS_CLASS;
	if (qos_sl & 0xF)
		comp_mask |= IB_COMP_MASK_PR_SL;

	if (path->mtu & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_MTU_SELECTOR;
	if (path->mtu & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_MTU;
	if (path->rate & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_RATE_SELECTOR;
	if (path->rate & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_RATE;
	if (path->packetlifetime & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME_SELECTOR;
	if (path->packetlifetime & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME;

	return comp_mask;
}

/* Caller must hold dest lock */
static uint8_t acm_resolve_path(struct acm_ep *ep, struct acm_dest *dest,
	void (*resp_handler)(struct acm_send_msg *req,
		struct ibv_wc *wc, struct acm_mad *resp))
{
	struct acm_send_msg *msg;
	struct acm_dest *sa_dest;
	struct ib_sa_mad *mad;
	uint8_t ret;

	ssa_log(SSA_LOG_VERBOSE, "%s\n", dest->name);
	if (!acm_acquire_sa_dest(ep->port)) {
		ssa_log(SSA_LOG_VERBOSE, "cannot acquire SA destination\n");
		ret = ACM_STATUS_EINVAL;
		goto err;
	}

	sa_dest = GET_PORT_FIELD_PTR(ep->port, struct acm_dest, sa_dest);
	msg = acm_alloc_send(ep, sa_dest, sizeof(*mad));
	acm_release_sa_dest(sa_dest);
	if (!msg) {
		ssa_log_err(0, "cannot allocate send msg\n");
		ret = ACM_STATUS_ENOMEM;
		goto err;
	}

	(void) atomic_inc(&dest->refcnt);
	acm_init_send_req(msg, (void *) dest, resp_handler);
	mad = (struct ib_sa_mad *) msg->data;
	acm_init_path_query(mad);

	memcpy(mad->data, &dest->path, sizeof(dest->path));
	mad->comp_mask = acm_path_comp_mask(&dest->path);

	atomic_inc(&counter[ACM_CNTR_ROUTE_QUERY]);
	dest->state = ACM_QUERY_ROUTE;
	acm_post_send(&ep->sa_queue, msg);
	return ACM_STATUS_SUCCESS;
err:
	dest->state = ACM_INIT;
	return ret;
}

static uint8_t
acm_record_acm_addr(struct acm_ep *ep, struct acm_dest *dest, struct ibv_wc *wc,
	struct acm_resolve_rec *rec)
{
	int index;

	ssa_log(SSA_LOG_VERBOSE, "%s\n", dest->name);
	index = acm_best_mc_index(ep, rec);
	if (index < 0) {
		ssa_log_err(0, "no shared multicast groups\n");
		dest->state = ACM_INIT;
		return ACM_STATUS_ENODATA;
	}

	ssa_log(SSA_LOG_VERBOSE, "selecting MC group at index %d\n", index);
	dest->av = ep->mc_dest[index].av;
	dest->av.dlid = wc->slid;
	dest->av.src_path_bits = wc->dlid_path_bits;
	dest->av.grh.dgid = ((struct ibv_grh *) (uintptr_t) wc->wr_id)->sgid;
	
	dest->mgid = ep->mc_dest[index].mgid;
	dest->path.sgid = ep->mc_dest[index].path.sgid;
	dest->path.dgid = dest->av.grh.dgid;
	dest->path.tclass = ep->mc_dest[index].path.tclass;
	dest->path.pkey = ep->mc_dest[index].path.pkey;
	dest->remote_qpn = wc->src_qp;

	dest->state = ACM_ADDR_RESOLVED;
	return ACM_STATUS_SUCCESS;
}

static void
acm_record_path_addr(struct acm_ep *ep, struct acm_dest *dest,
	struct ibv_path_record *path)
{
	uint16_t *lid;

	ssa_log(SSA_LOG_VERBOSE, "%s\n", dest->name);
	dest->path.pkey = htons(ep->pkey);
	dest->path.dgid = path->dgid;
	if (path->slid || !ib_any_gid(&path->sgid)) {
		dest->path.sgid = path->sgid;
		dest->path.slid = path->slid;
	} else {
		lid = GET_PORT_FIELD_PTR(ep->port, uint16_t, lid);
		dest->path.slid = htons(*lid);
	}
	dest->path.dlid = path->dlid;
	dest->state = ACM_ADDR_RESOLVED;
}

static uint8_t acm_validate_addr_req(struct acm_mad *mad)
{
	struct acm_resolve_rec *rec;

	if (mad->method != IB_METHOD_GET) {
		ssa_log_err(0, "invalid method 0x%x\n", mad->method);
		return ACM_STATUS_EINVAL;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	if (!rec->src_type || rec->src_type >= ACM_ADDRESS_RESERVED) {
		ssa_log_err(0, "unknown src type 0x%x\n", rec->src_type);
		return ACM_STATUS_EINVAL;
	}

	return ACM_STATUS_SUCCESS;
}

static void
acm_send_addr_resp(struct acm_ep *ep, struct acm_dest *dest)
{
	struct acm_resolve_rec *rec;
	struct acm_send_msg *msg;
	struct acm_mad *mad;

	ssa_log(SSA_LOG_VERBOSE, "%s\n", dest->name);
	msg = acm_alloc_send(ep, dest, sizeof (*mad));
	if (!msg) {
		ssa_log_err(0, "failed to allocate message\n");
		return;
	}

	mad = (struct acm_mad *) msg->data;
	rec = (struct acm_resolve_rec *) mad->data;

	mad->base_version = UMAD_BASE_VERSION;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = ACM_CLASS_VERSION;
	mad->method = IB_METHOD_GET | IB_METHOD_RESP;
	mad->status = ACM_STATUS_SUCCESS;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = dest->req_id;
	rec->gid_cnt = 1;
	memcpy(rec->gid, dest->mgid.raw, sizeof(union ibv_gid));

	acm_post_send(&ep->resp_queue, msg);
}

static int
acm_client_resolve_resp(struct acm_client *client, struct acm_msg *req_msg,
	struct acm_dest *dest, uint8_t status)
{
	struct acm_msg msg;
	int ret;

	ssa_log(SSA_LOG_VERBOSE, "client %d, status 0x%x\n", client->index, status);
	memset(&msg, 0, sizeof msg);

	if (status == ACM_STATUS_ENODATA)
		atomic_inc(&counter[ACM_CNTR_NODATA]);
	else if (status)
		atomic_inc(&counter[ACM_CNTR_ERROR]);

	pthread_mutex_lock(&client->lock);
	if (client->sock == -1) {
		ssa_log_err(0, "connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	msg.hdr = req_msg->hdr;
	msg.hdr.opcode |= ACM_OP_ACK;
	msg.hdr.status = status;
	msg.hdr.length = ACM_MSG_HDR_LENGTH;
	memset(msg.hdr.data, 0, sizeof(msg.hdr.data));

	if (status == ACM_STATUS_SUCCESS) {
		msg.hdr.length += ACM_MSG_EP_LENGTH;
		msg.resolve_data[0].flags = IBV_PATH_FLAG_GMP |
			IBV_PATH_FLAG_PRIMARY | IBV_PATH_FLAG_BIDIRECTIONAL;
		msg.resolve_data[0].type = ACM_EP_INFO_PATH;
		msg.resolve_data[0].info.path = dest->path;

		if (req_msg->hdr.src_out) {
			msg.hdr.length += ACM_MSG_EP_LENGTH;
			memcpy(&msg.resolve_data[1],
				&req_msg->resolve_data[req_msg->hdr.src_out],
				ACM_MSG_EP_LENGTH);
		}
	}

	ret = send(client->sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		ssa_log_err(0, "failed to send response\n");
	else
		ret = 0;

release:
	pthread_mutex_unlock(&client->lock);
	return ret;
}

static void
acm_complete_queued_req(struct acm_dest *dest, uint8_t status)
{
	struct acm_request *req;
	DLIST_ENTRY *entry;

	ssa_log(SSA_LOG_VERBOSE, "status %d\n", status);
	pthread_mutex_lock(&dest->lock);
	while (!DListEmpty(&dest->req_queue)) {
		entry = dest->req_queue.Next;
		DListRemove(entry);
		req = container_of(entry, struct acm_request, entry);
		pthread_mutex_unlock(&dest->lock);

		ssa_log(SSA_LOG_VERBOSE, "completing request, client %d\n", req->client->index);
		acm_client_resolve_resp(req->client, &req->msg, dest, status);
		acm_free_req(req);

		pthread_mutex_lock(&dest->lock);
	}
	pthread_mutex_unlock(&dest->lock);
}

static void
acm_dest_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	uint8_t status;

	if (mad) {
		status = (uint8_t) (ntohs(mad->status) >> 8);
	} else {
		status = ACM_STATUS_ETIMEDOUT;
	}
	ssa_log(SSA_LOG_VERBOSE, "%s status=0x%x\n", dest->name, status);

	pthread_mutex_lock(&dest->lock);
	if (dest->state != ACM_QUERY_ROUTE) {
		ssa_log(SSA_LOG_VERBOSE, "notice - discarding SA response\n");
		pthread_mutex_unlock(&dest->lock);
		return;
	}

	if (!status) {
		memcpy(&dest->path, sa_mad->data, sizeof(dest->path));
		acm_init_path_av(msg->ep->port, dest);
		dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
		dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
		ssa_log(SSA_LOG_VERBOSE, "timeout addr %llu route %llu\n",
			dest->addr_timeout, dest->route_timeout);
		dest->state = ACM_READY;
	} else {
		dest->state = ACM_INIT;
	}
	pthread_mutex_unlock(&dest->lock);

	acm_complete_queued_req(dest, status);
}

static void
acm_resolve_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	int send_resp;

	ssa_log_func(SSA_LOG_VERBOSE);
	acm_dest_sa_resp(msg, wc, mad);

	pthread_mutex_lock(&dest->lock);
	send_resp = (dest->state == ACM_READY);
	pthread_mutex_unlock(&dest->lock);

	if (send_resp)
		acm_send_addr_resp(msg->ep, dest);
}

static void
acm_process_addr_req(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *rec;
	struct acm_dest *dest;
	uint8_t status;
	int addr_index;

	ssa_log_func(SSA_LOG_VERBOSE);
	if ((status = acm_validate_addr_req(mad))) {
		ssa_log_err(0, "invalid request\n");
		return;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	dest = acm_acquire_dest(ep, rec->src_type, rec->src);
	if (!dest) {
		ssa_log_err(0, "unable to add source\n");
		return;
	}
	
	addr_index = acm_addr_index(ep, rec->dest, rec->dest_type);
	if (addr_index >= 0)
		dest->req_id = mad->tid;

	pthread_mutex_lock(&dest->lock);
	ssa_log(SSA_LOG_VERBOSE, "dest state %d\n", dest->state);
	switch (dest->state) {
	case ACM_READY:
		if (dest->remote_qpn == wc->src_qp)
			break;

		ssa_log(SSA_LOG_VERBOSE, "src service has new qp, resetting\n");
		/* fall through */
	case ACM_INIT:
	case ACM_QUERY_ADDR:
		status = acm_record_acm_addr(ep, dest, wc, rec);
		if (status)
			break;
		/* fall through */
	case ACM_ADDR_RESOLVED:
		if (route_prot == ACM_ROUTE_PROT_ACM) {
			status = acm_record_acm_route(ep, dest);
			break;
		}
		if (addr_index >= 0 || !DListEmpty(&dest->req_queue)) {
			status = acm_resolve_path(ep, dest, acm_resolve_sa_resp);
			if (status)
				break;
		}
		/* fall through */
	default:
		pthread_mutex_unlock(&dest->lock);
		acm_put_dest(dest);
		return;
	}
	pthread_mutex_unlock(&dest->lock);
	acm_complete_queued_req(dest, status);

	if (addr_index >= 0 && !status) {
		acm_send_addr_resp(ep, dest);
	}
	acm_put_dest(dest);
}

static void
acm_process_addr_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *resp_rec;
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	uint8_t status;

	if (mad) {
		status = acm_class_status(mad->status);
		resp_rec = (struct acm_resolve_rec *) mad->data;
	} else {
		status = ACM_STATUS_ETIMEDOUT;
		resp_rec = NULL;
	}
	ssa_log(SSA_LOG_VERBOSE, "resp status 0x%x\n", status);

	pthread_mutex_lock(&dest->lock);
	if (dest->state != ACM_QUERY_ADDR) {
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}

	if (!status) {
		status = acm_record_acm_addr(msg->ep, dest, wc, resp_rec);
		if (!status) {
			if (route_prot == ACM_ROUTE_PROT_ACM) {
				status = acm_record_acm_route(msg->ep, dest);
			} else {
				status = acm_resolve_path(msg->ep, dest, acm_dest_sa_resp);
				if (!status) {
					pthread_mutex_unlock(&dest->lock);
					goto put;
				}
			}
		}
	} else {
		dest->state = ACM_INIT;
	}
	pthread_mutex_unlock(&dest->lock);

	acm_complete_queued_req(dest, status);
put:
	acm_put_dest(dest);
}

static void acm_process_acm_recv(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_send_msg *req;
	struct acm_resolve_rec *rec;
	int free;

	ssa_log_func(SSA_LOG_VERBOSE);
	if (mad->base_version != UMAD_BASE_VERSION ||
	    mad->class_version != ACM_CLASS_VERSION) {
		ssa_log_err(0, "invalid version %d %d\n",
			    mad->base_version, mad->class_version);
		return;
	}
	
	if (mad->control != ACM_CTRL_RESOLVE) {
		ssa_log_err(0, "invalid control 0x%x\n", mad->control);
		return;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
			rec->src_type, rec->src, sizeof rec->src);
	ssa_log(SSA_LOG_VERBOSE, "src  %s\n", log_data);
	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
			rec->dest_type, rec->dest, sizeof rec->dest);
	ssa_log(SSA_LOG_VERBOSE, "dest %s\n", log_data);
	if (mad->method & IB_METHOD_RESP) {
		ssa_log(SSA_LOG_VERBOSE, "received response\n");
		req = acm_get_request(ep, mad->tid, &free);
		if (!req) {
			ssa_log(SSA_LOG_VERBOSE,
				"notice - response did not match active request\n");
			return;
		}
		ssa_log(SSA_LOG_VERBOSE, "found matching request\n");
		req->resp_handler(req, wc, mad);
		if (free)
			acm_free_send(req);
	} else {
		ssa_log(SSA_LOG_VERBOSE, "unsolicited request\n");
		acm_process_addr_req(ep, wc, mad);
	}
}

static int
acm_client_query_resp(struct acm_client *client,
	struct acm_msg *msg, uint8_t status)
{
	int ret;

	ssa_log(SSA_LOG_VERBOSE, "status 0x%x\n", status);
	pthread_mutex_lock(&client->lock);
	if (client->sock == -1) {
		ssa_log_err(0, "connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = status;

	ret = send(client->sock, (char *) msg, msg->hdr.length, 0);
	if (ret != msg->hdr.length)
		ssa_log_err(0, "failed to send response\n");
	else
		ret = 0;

release:
	pthread_mutex_unlock(&client->lock);
	return ret;
}

static void
acm_client_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_request *req = (struct acm_request *) msg->context;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	uint8_t status;

	if (mad) {
		status = (uint8_t) (ntohs(sa_mad->status) >> 8);
		memcpy(&req->msg.resolve_data[0].info.path, sa_mad->data,
			sizeof(struct ibv_path_record));
	} else {
		status = ACM_STATUS_ETIMEDOUT;
	}
	ssa_log(SSA_LOG_VERBOSE, "status 0x%x\n", status);

	acm_client_query_resp(req->client, &req->msg, status);
	acm_free_req(req);
}

static void acm_process_sa_recv(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	struct acm_send_msg *req;
	int free;

	ssa_log_func(SSA_LOG_VERBOSE);
	if (mad->base_version != UMAD_BASE_VERSION ||
	    mad->class_version != UMAD_SA_CLASS_VERSION ||
	    !(mad->method & IB_METHOD_RESP) || sa_mad->attr_id != IB_SA_ATTR_PATH_REC) {
		ssa_log_err(0, "unexpected SA MAD %d %d\n",
			    mad->base_version, mad->class_version);
		return;
	}
	
	req = acm_get_request(ep, mad->tid, &free);
	if (!req) {
		ssa_log(SSA_LOG_VERBOSE,
			"notice - response did not match active request\n");
		return;
	}
	ssa_log(SSA_LOG_VERBOSE, "found matching request\n");
	req->resp_handler(req, wc, mad);
	if (free)
		acm_free_send(req);
}

static void acm_process_recv(struct acm_ep *ep, struct ibv_wc *wc)
{
	struct acm_mad *mad;

	ssa_log(SSA_LOG_VERBOSE, "base endpoint name %s\n", ep->name[0]);
	mad = (struct acm_mad *) (uintptr_t) (wc->wr_id + sizeof(struct ibv_grh));
	switch (mad->mgmt_class) {
	case IB_MGMT_CLASS_SA:
		acm_process_sa_recv(ep, wc, mad);
		break;
	case ACM_MGMT_CLASS:
		acm_process_acm_recv(ep, wc, mad);
		break;
	default:
		ssa_log_err(0, "invalid mgmt class 0x%x\n", mad->mgmt_class);
		break;
	}

	acm_post_recv(ep, wc->wr_id);
}

static void acm_process_comp(struct acm_ep *ep, struct ibv_wc *wc)
{
	if (wc->status) {
		ssa_log_err(0, "work completion error\n"
			    "\topcode %d, completion status %d\n",
			    wc->opcode, wc->status);
		return;
	}

	if (wc->opcode & IBV_WC_RECV)
		acm_process_recv(ep, wc);
	else
		acm_complete_send((struct acm_send_msg *) (uintptr_t) wc->wr_id);
}

static void *acm_comp_handler(void *context)
{
	struct ibv_comp_channel *channel;
	struct acm_ep *ep;
	struct ibv_cq *cq;
	struct ibv_wc wc;
	int cnt;

	if (acm_mode == ACM_MODE_ACM) {
		SET_THREAD_NAME(comp_thread, "COMP_0x%" PRIx64,
				((struct acm_device *)context)->guid);
	} else {	/* ACM_MODE_SSA */
		SET_THREAD_NAME(comp_thread, "COMP_%s",
				((struct ssa_device *)context)->name);
	}

	ssa_log(SSA_LOG_VERBOSE, "started\n");
	if (acm_mode == ACM_MODE_ACM)
		channel = ((struct acm_device *)context)->channel;
	else /* ACM_MODE_SSA */
		channel = ((struct ssa_device *)context)->channel;

	while (1) {
		ibv_get_cq_event(channel, &cq, (void *) &ep);

		cnt = 0;
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acm_process_comp(ep, &wc);
		}

		ibv_req_notify_cq(cq, 0);
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acm_process_comp(ep, &wc);
		}

		ibv_ack_cq_events(cq, cnt);
	}
	return context;
}

static void acm_format_mgid(union ibv_gid *mgid, uint16_t pkey, uint8_t tos,
	uint8_t rate, uint8_t mtu)
{
	mgid->raw[0] = 0xFF;
	mgid->raw[1] = 0x10 | 0x05;
	mgid->raw[2] = 0x40;
	mgid->raw[3] = 0x01;
	mgid->raw[4] = (uint8_t) (pkey >> 8);
	mgid->raw[5] = (uint8_t) pkey;
	mgid->raw[6] = tos;
	mgid->raw[7] = rate;
	mgid->raw[8] = mtu;
	mgid->raw[9] = 0;
	mgid->raw[10] = 0;
	mgid->raw[11] = 0;
	mgid->raw[12] = 0;
	mgid->raw[13] = 0;
	mgid->raw[14] = 0;
	mgid->raw[15] = 0;
}

static void acm_init_join(struct ib_sa_mad *mad, union ibv_gid *port_gid,
	uint16_t pkey, uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ib_mc_member_rec *mc_rec;

	ssa_log_func(SSA_LOG_VERBOSE);
	mad->base_version = UMAD_BASE_VERSION;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = UMAD_SA_CLASS_VERSION;
	mad->method = IB_METHOD_SET;
	mad->tid = (uint64_t) atomic_inc(&tid);
	mad->attr_id = IB_SA_ATTR_MC_MEMBER_REC;
	mad->comp_mask =
		IB_COMP_MASK_MC_MGID | IB_COMP_MASK_MC_PORT_GID |
		IB_COMP_MASK_MC_QKEY | IB_COMP_MASK_MC_MTU_SEL| IB_COMP_MASK_MC_MTU |
		IB_COMP_MASK_MC_TCLASS | IB_COMP_MASK_MC_PKEY | IB_COMP_MASK_MC_RATE_SEL |
		IB_COMP_MASK_MC_RATE | IB_COMP_MASK_MC_SL | IB_COMP_MASK_MC_FLOW |
		IB_COMP_MASK_MC_SCOPE | IB_COMP_MASK_MC_JOIN_STATE;

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	acm_format_mgid(&mc_rec->mgid, pkey, tos, rate, mtu);
	mc_rec->port_gid = *port_gid;
	mc_rec->qkey = ACM_QKEY;
	mc_rec->mtu = 0x80 | mtu;
	mc_rec->tclass = tclass;
	mc_rec->pkey = htons(pkey);
	mc_rec->rate = 0x80 | rate;
	mc_rec->sl_flow_hop = htonl(((uint32_t) sl) << 28);
	mc_rec->scope_state = 0x51;
}

static void acm_join_group(struct acm_ep *ep, union ibv_gid *port_gid,
	uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct acm_port *port;
	struct ib_sa_mad *mad;
	struct ib_user_mad *umad;
	struct ib_mc_member_rec *mc_rec;
	int ret, len;

	ssa_log_func(SSA_LOG_VERBOSE);
	len = sizeof(*umad) + sizeof(*mad);
	umad = (struct ib_user_mad *) calloc(1, len);
	if (!umad) {
		ssa_log_err(0, "unable to allocate MAD for join\n");
		return;
	}

	port = ((struct acm_port *)ep->port);
	umad->addr.qpn = htonl(port->sa_dest.remote_qpn);
	umad->addr.qkey = htonl(ACM_QKEY);
	umad->addr.pkey_index = ep->pkey_index;
	umad->addr.lid = htons(port->sa_dest.av.dlid);
	umad->addr.sl = port->sa_dest.av.sl;
	umad->addr.path_bits = port->sa_dest.av.src_path_bits;

	ssa_log(SSA_LOG_DEFAULT, "%s %d pkey 0x%x, sl 0x%x, rate 0x%x, mtu 0x%x\n",
		((struct acm_port *)ep->port)->dev->verbs->device->name,
		((struct acm_port *)ep->port)->port_num,
		ep->pkey, sl, rate, mtu);
	mad = (struct ib_sa_mad *) umad->data;
	acm_init_join(mad, port_gid, ep->pkey, tos, tclass, sl, rate, mtu);
	mc_rec = (struct ib_mc_member_rec *) mad->data;
	acm_set_dest_addr(&ep->mc_dest[ep->mc_cnt++], ACM_ADDRESS_GID,
		mc_rec->mgid.raw, sizeof(mc_rec->mgid));

	ret = umad_send(port->mad_portid, port->mad_agentid, (void *) umad,
		sizeof(*mad), timeout, retries);
	if (ret) {
		ssa_log_err(0, "failed to send multicast join request %d\n", ret);
		goto out;
	}

	ssa_log(SSA_LOG_VERBOSE, "waiting for response from SA to join request\n");
	ret = umad_recv(port->mad_portid, (void *) umad, &len, -1);
	if (ret < 0) {
		ssa_log_err(0, "recv error for multicast join response %d\n", ret);
		goto out;
	}

	acm_process_join_resp(ep, umad);
out:
	free(umad);
}

static void acm_port_join(struct acm_port *port)
{
	struct acm_device *dev;
	struct acm_ep *ep;
	union ibv_gid port_gid;
	DLIST_ENTRY *ep_entry;
	int ret;

	dev = port->dev;
	ssa_log(SSA_LOG_VERBOSE, "device %s port %d\n", dev->verbs->device->name,
		port->port_num);

	ret = ibv_query_gid(dev->verbs, port->port_num, 0, &port_gid);
	if (ret) {
		ssa_log_err(0, "ibv_query_gid %d device %s port %d\n",
			    ret, dev->verbs->device->name, port->port_num);
		return;
	}

	for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
		 ep_entry = ep_entry->Next) {

		ep = container_of(ep_entry, struct acm_ep, entry);
		ep->mc_cnt = 0;
		acm_join_group(ep, &port_gid, 0, 0, 0, min_rate, min_mtu);

		if ((ep->state = ep->mc_dest[0].state) != ACM_READY)
			continue;

		if ((route_prot == ACM_ROUTE_PROT_ACM) &&
		    (port->rate != min_rate || port->mtu != min_mtu))
			acm_join_group(ep, &port_gid, 0, 0, 0, port->rate, port->mtu);
	}
	ssa_log(SSA_LOG_VERBOSE, "joins for device %s port %d complete\n",
		dev->verbs->device->name, port->port_num);
}

static void acm_process_timeouts(void)
{
	DLIST_ENTRY *entry;
	struct acm_send_msg *msg;
	struct acm_resolve_rec *rec;
	struct acm_mad *mad;
	
	while (!DListEmpty(&timeout_list)) {
		entry = timeout_list.Next;
		DListRemove(entry);

		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) &msg->data[0];
		rec = (struct acm_resolve_rec *) mad->data;

		acm_format_name(SSA_LOG_DEFAULT, log_data, sizeof log_data,
				rec->dest_type, rec->dest, sizeof rec->dest);
		ssa_log(SSA_LOG_DEFAULT, "notice - dest %s\n", log_data);
		msg->resp_handler(msg, NULL, NULL);
		acm_free_send(msg);
	}
}

static void acm_process_wait_queue(struct acm_ep *ep, uint64_t *next_expire)
{
	struct acm_send_msg *msg;
	DLIST_ENTRY *entry, *next;
	struct ibv_send_wr *bad_wr;

	for (entry = ep->wait_queue.Next; entry != &ep->wait_queue; entry = next) {
		next = entry->Next;
		msg = container_of(entry, struct acm_send_msg, entry);
		if (msg->expires < time_stamp_ms()) {
			DListRemove(entry);
			(void) atomic_dec(&wait_cnt);
			if (--msg->tries) {
				ssa_log(SSA_LOG_VERBOSE, "notice - retrying request\n");
				DListInsertTail(&msg->entry, &ep->active_queue);
				ibv_post_send(ep->qp, &msg->wr, &bad_wr);
			} else {
				ssa_log(SSA_LOG_DEFAULT, "notice - failing request\n");
				acm_send_available(ep, msg->req_queue);
				DListInsertTail(&msg->entry, &timeout_list);
			}
		} else {
			*next_expire = min(*next_expire, msg->expires);
			break;
		}
	}
}

static void
acm_retry_process_wait_queue(DLIST_ENTRY *ep_list, uint64_t *p_next_expire)
{
	struct acm_ep *ep;
	DLIST_ENTRY *ep_entry;

	for (ep_entry = ep_list->Next; ep_entry != ep_list;
	     ep_entry = ep_entry->Next) {
		ep = container_of(ep_entry, struct acm_ep, entry);

		pthread_mutex_lock(&ep->lock);
		if (!DListEmpty(&ep->wait_queue))
			acm_process_wait_queue(ep, p_next_expire);
		pthread_mutex_unlock(&ep->lock);
	}
}

static void *acm_retry_handler(void *context)
{
	struct acm_device *dev;
	struct ssa_device *ssa_dev1;
	struct acm_port *acm_port;
	struct ssa_port *ssa_port;
	DLIST_ENTRY *dev_entry;
	uint64_t next_expire;
	int i, d, p, wait;

	SET_THREAD_NAME(retry_thread, "RETRY");

	ssa_log(SSA_LOG_DEFAULT, "started\n");
	while (1) {
		while (!atomic_get(&wait_cnt))
			event_wait(&timeout_event, -1);

		next_expire = -1;
		if (acm_mode == ACM_MODE_ACM) {
			for (dev_entry = device_list.Next;
			     dev_entry != &device_list;
			     dev_entry = dev_entry->Next) {
				dev = container_of(dev_entry, struct acm_device,
						   entry);
				for (i = 0; i < dev->port_cnt; i++) {
					acm_port = &dev->port[i];
					acm_retry_process_wait_queue(
					    &acm_port->ep_list, &next_expire);
				}
			}
		} else { /* ACM_MODE_SSA */
			for (d = 0; d < ssa.dev_cnt; d++) {
				ssa_dev1 = ssa_dev(&ssa, d);
				for (p = 1; p <= ssa_dev1->port_cnt; p++) {
					ssa_port = ssa_dev_port(ssa_dev1, p);
					acm_retry_process_wait_queue(
					    &ssa_port->ep_list, &next_expire);
				}
			}
		}

		acm_process_timeouts();
		wait = (int) (next_expire - time_stamp_ms());
		if (wait > 0 && atomic_get(&wait_cnt))
			event_wait(&timeout_event, wait);
	}
	return context;
}

static void acm_init_server(void)
{
	FILE *f;
	int i;

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		pthread_mutex_init(&client_array[i].lock, NULL);
		client_array[i].index = i;
		client_array[i].sock = -1;
		atomic_init(&client_array[i].refcnt);
	}

	if (!(f = fopen("/var/run/ibacm.port", "w"))) {
		ssa_log(SSA_LOG_DEFAULT, "notice - cannot publish ibacm port number\n");
		return;
	}
	fprintf(f, "%hu\n", server_port);
	fclose(f);
}

static int acm_listen(void)
{
	struct sockaddr_in addr;
	int ret;

	ssa_log_func(SSA_LOG_VERBOSE);
	listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_socket == -1) {
		ssa_log_err(0, "unable to allocate listen socket\n");
		return errno;
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ret = bind(listen_socket, (struct sockaddr *) &addr, sizeof addr);
	if (ret == -1) {
		ssa_log_err(0, "unable to bind listen socket\n");
		return errno;
	}
	
	ret = listen(listen_socket, 0);
	if (ret == -1) {
		ssa_log_err(0, "unable to start listen\n");
		return errno;
	}

	ssa_log(SSA_LOG_VERBOSE, "listen active\n");
	return 0;
}

static void acm_disconnect_client(struct acm_client *client)
{
	pthread_mutex_lock(&client->lock);
	shutdown(client->sock, SHUT_RDWR);
	close(client->sock);
	client->sock = -1;
	pthread_mutex_unlock(&client->lock);
	(void) atomic_dec(&client->refcnt);
}

static void acm_svr_accept(void)
{
	int s, i;

	ssa_log_func(SSA_LOG_VERBOSE);
	s = accept(listen_socket, NULL, NULL);
	if (s == -1) {
		ssa_log_err(0, "failed to accept connection\n");
		return;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		if (!atomic_get(&client_array[i].refcnt))
			break;
	}

	if (i == FD_SETSIZE - 1) {
		ssa_log_err(0, "all connections busy - rejecting\n");
		close(s);
		return;
	}

	client_array[i].sock = s;
	atomic_set(&client_array[i].refcnt, 1);
	ssa_log(SSA_LOG_VERBOSE, "assigned client %d\n", i);
}

static int
acm_is_path_from_port(void *port, struct ibv_path_record *path)
{
	union ibv_gid gid;
	struct ibv_context *verbs;
	int *gid_cnt;
	uint16_t *lid, *lid_mask;
	uint8_t *port_num;
	uint8_t i;

	if (acm_mode == ACM_MODE_ACM)
		verbs = ((struct acm_port *)(port))->dev->verbs;
	else /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)(port))->dev->verbs;

	gid_cnt = GET_PORT_FIELD_PTR(port, int, gid_cnt);
	lid = GET_PORT_FIELD_PTR(port, uint16_t, lid);
	lid_mask = GET_PORT_FIELD_PTR(port, uint16_t, lid_mask);
	port_num = GET_PORT_FIELD_PTR(port, uint8_t, port_num);

	if (!ib_any_gid(&path->sgid)) {
		return (acm_gid_index(port, &path->sgid) < *gid_cnt);
	}

	if (path->slid) {
		return (*lid == (ntohs(path->slid) & *lid_mask));
	}

	if (ib_any_gid(&path->dgid)) {
		return 1;
	}

	if (acm_gid_index(port, &path->dgid) < *gid_cnt) {
		return 1;
	}

	for (i = 0; i < *gid_cnt; i++) {
		ibv_query_gid(verbs, *port_num, i, &gid);
		if (gid.global.subnet_prefix == path->dgid.global.subnet_prefix) {
			return 1;
		}
	}

	return 0;
}

static struct acm_ep *
acm_get_port_ep(void *port, struct acm_ep_addr_data *data)
{
	struct acm_ep *ep;
	DLIST_ENTRY *ep_entry, *ep_list;
	enum ibv_port_state *state;

	ep_list = GET_PORT_FIELD_PTR(port, DLIST_ENTRY, ep_list);
	state = GET_PORT_FIELD_PTR(port, enum ibv_port_state, state);

	if (*state != IBV_PORT_ACTIVE)
		return NULL;

	if (data->type == ACM_EP_INFO_PATH &&
	    !acm_is_path_from_port(port, &data->info.path))
		return NULL;

	for (ep_entry = ep_list->Next; ep_entry != ep_list;
		 ep_entry = ep_entry->Next) {

		ep = container_of(ep_entry, struct acm_ep, entry);
		if (ep->state != ACM_READY)
			continue;

		if ((data->type == ACM_EP_INFO_PATH) &&
		    (!data->info.path.pkey || (ntohs(data->info.path.pkey) == ep->pkey)))
			return ep;

		if (acm_addr_index(ep, data->info.addr, (uint8_t) data->type) >= 0)
			return ep;
	}

	return NULL;
}

static struct acm_ep *
acm_get_ep(struct acm_ep_addr_data *data)
{
	struct acm_device *acm_dev;
	struct ssa_device *ssa_dev1;
	void *port;
	struct acm_ep *ep;
	DLIST_ENTRY *dev_entry;
	int i, d, p;

	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
			data->type, data->info.addr, sizeof data->info.addr);
	ssa_log(SSA_LOG_VERBOSE, "%s\n", log_data);
	if (acm_mode == ACM_MODE_ACM) {
		for (dev_entry = device_list.Next; dev_entry != &device_list;
			 dev_entry = dev_entry->Next) {

			acm_dev =
			    container_of(dev_entry, struct acm_device, entry);
			for (i = 0; i < acm_dev->port_cnt; i++) {
				port = &acm_dev->port[i];
				pthread_mutex_lock(&acm_dev->port[i].lock);
				ep = acm_get_port_ep(port, data);
				pthread_mutex_unlock(&acm_dev->port[i].lock);
				if (ep)
					return ep;
			}
		}
	} else { /* ACM_MODE_SSA */
		for (d = 0; d < ssa.dev_cnt; d++) {
			ssa_dev1 = ssa_dev(&ssa, d);
			for (p = 1; p <= ssa_dev1->port_cnt; p++) {
				port = ssa_dev_port(ssa_dev1, p);
				pthread_mutex_lock(&((struct ssa_port *)(port))->lock);
				ep = acm_get_port_ep(port, data);
				pthread_mutex_unlock(&((struct ssa_port *)(port))->lock);
				if (ep)
					return ep;
			}
		}
	}

	acm_format_name(SSA_LOG_DEFAULT, log_data, sizeof log_data,
			data->type, data->info.addr, sizeof data->info.addr);
	ssa_log(SSA_LOG_VERBOSE, "notice - could not find %s\n", log_data);
	return NULL;
}

static int
acm_svr_query_path(struct acm_client *client, struct acm_msg *msg)
{
	struct acm_request *req;
	struct acm_send_msg *sa_msg;
	struct ib_sa_mad *mad;
	struct acm_dest *sa_dest;
	struct acm_ep *ep;
	uint8_t status;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	if (msg->hdr.length != ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH) {
		ssa_log_err(0, "invalid length: 0x%x\n", msg->hdr.length);
		status = ACM_STATUS_EINVAL;
		goto resp;
	}

	ep = acm_get_ep(&msg->resolve_data[0]);
	if (!ep) {
		ssa_log(SSA_LOG_VERBOSE, "notice - could not find local end point\n");
		status = ACM_STATUS_ESRCADDR;
		goto resp;
	}

	req = acm_alloc_req(client, msg);
	if (!req) {
		status = ACM_STATUS_ENOMEM;
		goto resp;
	}

	if (!acm_acquire_sa_dest(ep->port)) {
		ssa_log(SSA_LOG_VERBOSE, "cannot acquire SA destination\n");
		status = ACM_STATUS_EINVAL;
		goto free;
	}

	sa_dest = GET_PORT_FIELD_PTR(ep->port, struct acm_dest, sa_dest);
	sa_msg = acm_alloc_send(ep, sa_dest, sizeof(*mad));
	acm_release_sa_dest(sa_dest);
	if (!sa_msg) {
		ssa_log_err(0, "cannot allocate send msg\n");
		status = ACM_STATUS_ENOMEM;
		goto free;
	}

	acm_init_send_req(sa_msg, (void *) req, acm_client_sa_resp);
	mad = (struct ib_sa_mad *) sa_msg->data;
	acm_init_path_query(mad);

	memcpy(mad->data, &msg->resolve_data[0].info.path,
		sizeof(struct ibv_path_record));
	mad->comp_mask = acm_path_comp_mask(&msg->resolve_data[0].info.path);

	atomic_inc(&counter[ACM_CNTR_ROUTE_QUERY]);
	acm_post_send(&ep->sa_queue, sa_msg);
	return ACM_STATUS_SUCCESS;

free:
	acm_free_req(req);
resp:
	return acm_client_query_resp(client, msg, status);
}

static uint8_t
acm_send_resolve(struct acm_ep *ep, struct acm_dest *dest,
	struct acm_ep_addr_data *saddr)
{
	struct acm_send_msg *msg;
	struct acm_mad *mad;
	struct acm_resolve_rec *rec;
	int i;

	ssa_log_func(SSA_LOG_VERBOSE);
	msg = acm_alloc_send(ep, &ep->mc_dest[0], sizeof(*mad));
	if (!msg) {
		ssa_log_err(0, "cannot allocate send msg\n");
		return ACM_STATUS_ENOMEM;
	}

	acm_init_send_req(msg, (void *) dest, acm_process_addr_resp);
	(void) atomic_inc(&dest->refcnt);

	mad = (struct acm_mad *) msg->data;
	mad->base_version = UMAD_BASE_VERSION;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = ACM_CLASS_VERSION;
	mad->method = IB_METHOD_GET;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = (uint64_t) atomic_inc(&tid);

	rec = (struct acm_resolve_rec *) mad->data;
	rec->src_type = (uint8_t) saddr->type;
	rec->src_length = ACM_MAX_ADDRESS;
	memcpy(rec->src, saddr->info.addr, ACM_MAX_ADDRESS);
	rec->dest_type = dest->addr_type;
	rec->dest_length = ACM_MAX_ADDRESS;
	memcpy(rec->dest, dest->address, ACM_MAX_ADDRESS);

	rec->gid_cnt = (uint8_t) ep->mc_cnt;
	for (i = 0; i < ep->mc_cnt; i++)
		memcpy(&rec->gid[i], ep->mc_dest[i].address, 16);
	
	atomic_inc(&counter[ACM_CNTR_ADDR_QUERY]);
	acm_post_send(&ep->resolve_queue, msg);
	return 0;
}

static int acm_svr_select_src(struct acm_ep_addr_data *src, struct acm_ep_addr_data *dst)
{
	union socket_addr addr;
	socklen_t len;
	int ret, s;

	if (src->type)
		return 0;

	ssa_log(SSA_LOG_VERBOSE, "selecting source address\n");
	memset(&addr, 0, sizeof addr);
	switch (dst->type) {
	case ACM_EP_INFO_ADDRESS_IP:
		addr.sin.sin_family = AF_INET;
		memcpy(&addr.sin.sin_addr, dst->info.addr, 4);
		len = sizeof(struct sockaddr_in);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		addr.sin6.sin6_family = AF_INET6;
		memcpy(&addr.sin6.sin6_addr, dst->info.addr, 16);
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		ssa_log(SSA_LOG_VERBOSE,
			"notice - bad destination type, cannot lookup source\n");
		return ACM_STATUS_EDESTTYPE;
	}

	s = socket(addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1) {
		ssa_log_err(0, "unable to allocate socket\n");
		return errno;
	}

	ret = connect(s, &addr.sa, len);
	if (ret) {
		ssa_log_err(0, "unable to connect socket\n");
		ret = errno;
		goto out;
	}

	ret = getsockname(s, &addr.sa, &len);
	if (ret) {
		ssa_log_err(0, "failed to get socket address\n");
		ret = errno;
		goto out;
	}

	src->type = dst->type;
	src->flags = ACM_EP_FLAG_SOURCE;
	if (dst->type == ACM_EP_INFO_ADDRESS_IP) {
		memcpy(&src->info.addr, &addr.sin.sin_addr, 4);
	} else {
		memcpy(&src->info.addr, &addr.sin6.sin6_addr, 16);
	}
out:
	close(s);
	return ret;
}

/*
 * Verify the resolve message from the client and return
 * references to the source and destination addresses.
 * The message buffer contains extra address data buffers.  If a
 * source address is not given, reference an empty address buffer,
 * and we'll resolve a source address later.
 */
static uint8_t
acm_svr_verify_resolve(struct acm_msg *msg,
	struct acm_ep_addr_data **saddr, struct acm_ep_addr_data **daddr)
{
	struct acm_ep_addr_data *src = NULL, *dst = NULL;
	int i, cnt;

	if (msg->hdr.length < ACM_MSG_HDR_LENGTH) {
		ssa_log_err(0, "invalid msg hdr length %d\n", msg->hdr.length);
		return ACM_STATUS_EINVAL;
	}

	cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) / ACM_MSG_EP_LENGTH;
	for (i = 0; i < cnt; i++) {
		if (msg->resolve_data[i].flags & ACM_EP_FLAG_SOURCE) {
			if (src) {
				ssa_log_err(0, "multiple sources specified\n");
				return ACM_STATUS_ESRCADDR;
			}
			if (!msg->resolve_data[i].type ||
			    (msg->resolve_data[i].type >= ACM_ADDRESS_RESERVED)) {
				ssa_log_err(0, "unsupported source address type\n");
				return ACM_STATUS_ESRCTYPE;
			}
			src = &msg->resolve_data[i];
		}
		if (msg->resolve_data[i].flags & ACM_EP_FLAG_DEST) {
			if (dst) {
				ssa_log_err(0, "multiple destinations specified\n");
				return ACM_STATUS_EDESTADDR;
			}
			if (!msg->resolve_data[i].type ||
			    (msg->resolve_data[i].type >= ACM_ADDRESS_RESERVED)) {
				ssa_log_err(0, "unsupported destination address type\n");
				return ACM_STATUS_EDESTTYPE;
			}
			dst = &msg->resolve_data[i];
		}
	}

	if (!dst) {
		ssa_log_err(0, "destination address required\n");
		return ACM_STATUS_EDESTTYPE;
	}

	if (!src) {
		msg->hdr.src_out = i;
		src = &msg->resolve_data[i];
		memset(src, 0, sizeof *src);
	}
	*saddr = src;
	*daddr = dst;
	return ACM_STATUS_SUCCESS;
}

/* Caller must hold dest lock */
static uint8_t
acm_svr_queue_req(struct acm_dest *dest, struct acm_client *client,
	struct acm_msg *msg)
{
	struct acm_request *req;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	req = acm_alloc_req(client, msg);
	if (!req) {
		return ACM_STATUS_ENOMEM;
	}

	DListInsertTail(&req->entry, &dest->req_queue);
	return ACM_STATUS_SUCCESS;
}

static int acm_dest_timeout(struct acm_dest *dest)
{
	uint64_t timestamp = time_stamp_min();

	if (timestamp > dest->addr_timeout) {
		ssa_log(SSA_LOG_VERBOSE, "%s address timed out\n", dest->name);
		dest->state = ACM_INIT;
		return 1;
	} else if (timestamp > dest->route_timeout) {
		ssa_log(SSA_LOG_VERBOSE, "%s route timed out\n", dest->name);
		dest->state = ACM_ADDR_RESOLVED;
		return 1;
	}
	return 0;
}

static int
acm_svr_resolve_dest(struct acm_client *client, struct acm_msg *msg)
{
	struct acm_ep *ep;
	struct acm_dest *dest;
	struct acm_ep_addr_data *saddr, *daddr;
	uint8_t status;
	int ret;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	status = acm_svr_verify_resolve(msg, &saddr, &daddr);
	if (status) {
		ssa_log(SSA_LOG_DEFAULT,
			"notice - misformatted or unsupported request\n");
		return acm_client_resolve_resp(client, msg, NULL, status);
	}

	status = acm_svr_select_src(saddr, daddr);
	if (status) {
		ssa_log(SSA_LOG_DEFAULT,
			"notice - unable to select suitable source address\n");
		return acm_client_resolve_resp(client, msg, NULL, status);
	}

	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
			saddr->type, saddr->info.addr, sizeof saddr->info.addr);
	ssa_log(SSA_LOG_VERBOSE, "src  %s\n", log_data);
	ep = acm_get_ep(saddr);
	if (!ep) {
		ssa_log(SSA_LOG_DEFAULT, "notice - unknown local end point\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ESRCADDR);
	}

	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
			daddr->type, daddr->info.addr, sizeof daddr->info.addr);
	ssa_log(SSA_LOG_VERBOSE, "dest %s\n", log_data);

	dest = acm_acquire_dest(ep, daddr->type, daddr->info.addr);
	if (!dest) {
		ssa_log_err(0, "unable to allocate destination in client request\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ENOMEM);
	}

	pthread_mutex_lock(&dest->lock);
test:
	switch (dest->state) {
	case ACM_READY:
		if (acm_dest_timeout(dest))
			goto test;
		ssa_log(SSA_LOG_VERBOSE, "request satisfied from local cache\n");
		atomic_inc(&counter[ACM_CNTR_ROUTE_CACHE]);
		status = ACM_STATUS_SUCCESS;
		break;
	case ACM_ADDR_RESOLVED:
		ssa_log(SSA_LOG_VERBOSE, "have address, resolving route\n");
		atomic_inc(&counter[ACM_CNTR_ADDR_CACHE]);
		status = acm_resolve_path(ep, dest, acm_dest_sa_resp);
		if (status) {
			break;
		}
		goto queue;
	case ACM_INIT:
		if (acm_mode == ACM_MODE_ACM) {
			ssa_log(SSA_LOG_VERBOSE, "sending resolve msg to dest\n");
			status = acm_send_resolve(ep, dest, saddr);
			if (status) {
				break;
			}
			dest->state = ACM_QUERY_ADDR;
			/* fall through */
		} else {	/* ACM_MODE_SSA */
			ssa_log(SSA_LOG_VERBOSE, "SSA mode but dest not cached\n");
			status = ACM_STATUS_ENODATA;
			break;
		}
	default:
queue:
		if (daddr->flags & ACM_FLAGS_NODELAY) {
			ssa_log(SSA_LOG_VERBOSE,
				"lookup initiated, but client wants no delay\n");
			status = ACM_STATUS_ENODATA;
			break;
		}
		status = acm_svr_queue_req(dest, client, msg);
		if (status) {
			break;
		}
		ret = 0;
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}
	pthread_mutex_unlock(&dest->lock);
	ret = acm_client_resolve_resp(client, msg, dest, status);
put:
	acm_put_dest(dest);
	return ret;
}

/*
 * The message buffer contains extra address data buffers.  We extract the
 * destination address from the path record into an extra buffer, so we can
 * lookup the destination by either LID or GID.
 */
static int
acm_svr_resolve_path(struct acm_client *client, struct acm_msg *msg)
{
	struct acm_ep *ep;
	struct acm_dest *dest;
	struct ibv_path_record *path;
	struct ssa_svc *svc;
	uint8_t *addr;
	uint8_t status;
	int ret, i;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	if (msg->hdr.length < (ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH)) {
		ssa_log(SSA_LOG_DEFAULT, "notice - invalid msg hdr length %d\n",
			msg->hdr.length);
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_EINVAL);
	}

	path = &msg->resolve_data[0].info.path;
	if (!path->dlid && ib_any_gid(&path->dgid)) {
		ssa_log(SSA_LOG_DEFAULT, "notice - no destination specified\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_EDESTADDR);
	}

	acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data, ACM_EP_INFO_PATH,
		msg->resolve_data[0].info.addr, sizeof *path);
	ssa_log(SSA_LOG_VERBOSE, "path %s\n", log_data);
	ep = acm_get_ep(&msg->resolve_data[0]);
	if (!ep) {
		ssa_log(SSA_LOG_DEFAULT, "notice - unknown local end point\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ESRCADDR);
	}

	addr = msg->resolve_data[1].info.addr;
	memset(addr, 0, ACM_MAX_ADDRESS);
	if (path->dlid) {
		* ((uint16_t *) addr) = path->dlid;
		dest = acm_acquire_dest(ep, ACM_ADDRESS_LID, addr);
	} else {
		memcpy(addr, &path->dgid, sizeof path->dgid);
		dest = acm_acquire_dest(ep, ACM_ADDRESS_GID, addr);
	}
	if (!dest) {
		ssa_log_err(0, "unable to allocate destination in client request\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ENOMEM);
	}

	if (acm_mode == ACM_MODE_SSA && acm_issue_query_done) {
		for (i = 0; i < ssa_get_svc_cnt(ep->port); i++) {
			svc = ssa_get_svc(ep->port, i);
			ret = ssa_upstream_query_db(svc);
			if (ret)
				ssa_log(SSA_LOG_CTRL,
					"unsuccessful last DB query (status: %d)\n",
					ret);
		}
	}

	pthread_mutex_lock(&dest->lock);
test:
	switch (dest->state) {
	case ACM_READY:
		if (acm_dest_timeout(dest))
			goto test;
		ssa_log(SSA_LOG_VERBOSE, "request satisfied from local cache\n");
		atomic_inc(&counter[ACM_CNTR_ROUTE_CACHE]);
		status = ACM_STATUS_SUCCESS;
		break;
	case ACM_INIT:
		ssa_log(SSA_LOG_VERBOSE, "have path, bypassing address resolution\n");
		acm_record_path_addr(ep, dest, path);
		/* fall through */
	case ACM_ADDR_RESOLVED:
		ssa_log(SSA_LOG_VERBOSE, "have address, resolving route\n");
		status = acm_resolve_path(ep, dest, acm_dest_sa_resp);
		if (status) {
			break;
		}
		/* fall through */
	default:
		if (msg->resolve_data[0].flags & ACM_FLAGS_NODELAY) {
			ssa_log(SSA_LOG_VERBOSE,
				"lookup initiated, but client wants no delay\n");
			status = ACM_STATUS_ENODATA;
			break;
		}
		status = acm_svr_queue_req(dest, client, msg);
		if (status) {
			break;
		}
		ret = 0;
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}
	pthread_mutex_unlock(&dest->lock);
	ret = acm_client_resolve_resp(client, msg, dest, status);
put:
	acm_put_dest(dest);
	return ret;
}

static int acm_svr_resolve(struct acm_client *client, struct acm_msg *msg)
{
	if (msg->resolve_data[0].type == ACM_EP_INFO_PATH) {
		if (msg->resolve_data[0].flags & ACM_FLAGS_QUERY_SA) {
			return acm_svr_query_path(client, msg);
		} else {
			return acm_svr_resolve_path(client, msg);
		}
	} else {
		return acm_svr_resolve_dest(client, msg);
	}
}

static int acm_svr_perf_query(struct acm_client *client, struct acm_msg *msg)
{
	int ret, i;
	uint16_t len;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = ACM_STATUS_SUCCESS;
	msg->hdr.data[0] = ACM_MAX_COUNTER;
	msg->hdr.data[1] = 0;
	msg->hdr.data[2] = 0;
	len = ACM_MSG_HDR_LENGTH + (ACM_MAX_COUNTER * sizeof(uint64_t));
	msg->hdr.length = htons(len);

	for (i = 0; i < ACM_MAX_COUNTER; i++)
		msg->perf_data[i] = htonll((uint64_t) atomic_get(&counter[i]));

	ret = send(client->sock, (char *) msg, len, 0);
	if (ret != len)
		ssa_log_err(0, "failed to send response\n");
	else
		ret = 0;

	return ret;
}

static int acm_msg_length(struct acm_msg *msg)
{
	return (msg->hdr.opcode == ACM_OP_RESOLVE) ?
		msg->hdr.length : ntohs(msg->hdr.length);
}

static void acm_svr_receive(struct acm_client *client)
{
	struct acm_msg msg;
	int ret;

	ssa_log(SSA_LOG_VERBOSE, "client %d\n", client->index);
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
	if (ret <= 0 || ret != acm_msg_length(&msg)) {
		ssa_log(SSA_LOG_VERBOSE, "client disconnected\n");
		ret = ACM_STATUS_ENOTCONN;
		goto out;
	}

	if (msg.hdr.version != ACM_VERSION) {
		ssa_log_err(0, "unsupported version %d\n", msg.hdr.version);
		goto out;
	}

	switch (msg.hdr.opcode & ACM_OP_MASK) {
	case ACM_OP_RESOLVE:
		atomic_inc(&counter[ACM_CNTR_RESOLVE]);
		ret = acm_svr_resolve(client, &msg);
		break;
	case ACM_OP_PERF_QUERY:
		ret = acm_svr_perf_query(client, &msg);
		break;
	default:
		ssa_log_err(0, "unknown opcode 0x%x\n", msg.hdr.opcode);
		break;
	}

out:
	if (ret)
		acm_disconnect_client(client);
}

static void acm_server(void)
{
	fd_set readfds;
	int i, n, ret;

	ssa_log(SSA_LOG_DEFAULT, "started\n");
	acm_init_server();
	ret = acm_listen();
	if (ret) {
		ssa_log_err(0, "server listen failed\n");
		return;
	}

	while (1) {
		n = (int) listen_socket;
		FD_ZERO(&readfds);
		FD_SET(listen_socket, &readfds);

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1) {
				FD_SET(client_array[i].sock, &readfds);
				n = max(n, (int) client_array[i].sock);
			}
		}

		ret = rselect(n + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			ssa_log_err(0, "server select error\n");
			continue;
		}

		if (FD_ISSET(listen_socket, &readfds))
			acm_svr_accept();

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1 &&
				FD_ISSET(client_array[i].sock, &readfds)) {
				ssa_log(SSA_LOG_VERBOSE,
					"receiving from client %d\n", i);
				acm_svr_receive(&client_array[i]);
			}
		}
	}
}

static enum acm_addr_prot acm_convert_addr_prot(char *param)
{
	if (!strcasecmp("acm", param))
		return ACM_ADDR_PROT_ACM;

	return addr_prot;
}

static enum acm_route_prot acm_convert_route_prot(char *param)
{
	if (!strcasecmp("acm", param))
		return ACM_ROUTE_PROT_ACM;
	else if (!strcasecmp("sa", param))
		return ACM_ROUTE_PROT_SA;

	return route_prot;
}

static enum acm_loopback_prot acm_convert_loopback_prot(char *param)
{
	if (!strcasecmp("none", param))
		return ACM_LOOPBACK_PROT_NONE;
	else if (!strcasecmp("local", param))
		return ACM_LOOPBACK_PROT_LOCAL;

	return loopback_prot;
}

static enum acm_route_preload acm_convert_route_preload(char *param)
{
	if (!strcasecmp("none", param) || !strcasecmp("no", param))
		return ACM_ROUTE_PRELOAD_NONE;
	else if (!strcasecmp("opensm_full_v1", param))
		return ACM_ROUTE_PRELOAD_OSM_FULL_V1;
	else if (!strcasecmp("access_v1", param))
		return ACM_ROUTE_PRELOAD_ACCESS_V1;

	return route_preload;
}

static enum acm_route_preload acm_convert_addr_preload(char *param)
{
	if (!strcasecmp("none", param) || !strcasecmp("no", param))
		return ACM_ADDR_PRELOAD_NONE;
	else if (!strcasecmp("acm_hosts", param))
		return ACM_ADDR_PRELOAD_HOSTS;

	return addr_preload;
}

static enum acm_mode acm_convert_mode(char *param)
{
	if (!strcasecmp("acm", param))
		return ACM_MODE_ACM;
	else if (!strcasecmp("ssa", param))
		return ACM_MODE_SSA;

	return acm_mode;
}

enum ibv_rate acm_get_rate(uint8_t width, uint8_t speed)
{
	switch (width) {
	case 1:
		switch (speed) {
		case 1: return IBV_RATE_2_5_GBPS;
		case 2: return IBV_RATE_5_GBPS;
		case 4: return IBV_RATE_10_GBPS;
#if HAVE_IBA_EXTENDED_RATES
		case 8: return IBV_RATE_10_GBPS;
		case 16: return IBV_RATE_14_GBPS;
		case 32: return IBV_RATE_25_GBPS;
#endif
		default: return IBV_RATE_MAX;
		}
	case 2:
		switch (speed) {
		case 1: return IBV_RATE_10_GBPS;
		case 2: return IBV_RATE_20_GBPS;
		case 4: return IBV_RATE_40_GBPS;
#if HAVE_IBA_EXTENDED_RATES
		case 8: return IBV_RATE_40_GBPS;
		case 16: return IBV_RATE_56_GBPS;
		case 32: return IBV_RATE_100_GBPS;
#endif
		default: return IBV_RATE_MAX;
		}
	case 4:
		switch (speed) {
		case 1: return IBV_RATE_20_GBPS;
		case 2: return IBV_RATE_40_GBPS;
		case 4: return IBV_RATE_80_GBPS;
#if HAVE_IBA_EXTENDED_RATES
		case 8: return IBV_RATE_80_GBPS;
		case 16: return IBV_RATE_112_GBPS;
		case 32: return IBV_RATE_200_GBPS;
#endif
		default: return IBV_RATE_MAX;
		}
	case 8:
		switch (speed) {
		case 1: return IBV_RATE_30_GBPS;
		case 2: return IBV_RATE_60_GBPS;
		case 4: return IBV_RATE_120_GBPS;
#if HAVE_IBA_EXTENDED_RATES
		case 8: return IBV_RATE_120_GBPS;
		case 16: return IBV_RATE_168_GBPS;
		case 32: return IBV_RATE_300_GBPS;
#endif
		default: return IBV_RATE_MAX;
		}
	default:
		ssa_log_err(0, "unknown link width 0x%x\n", width);
		return IBV_RATE_MAX;
	}
}

static enum ibv_mtu acm_convert_mtu(int mtu)
{
	switch (mtu) {
	case 256:  return IBV_MTU_256;
	case 512:  return IBV_MTU_512;
	case 1024: return IBV_MTU_1024;
	case 2048: return IBV_MTU_2048;
	case 4096: return IBV_MTU_4096;
	default:   return IBV_MTU_2048;
	}
}

static enum ibv_rate acm_convert_rate(int rate)
{
	switch (rate) {
	case 2:   return IBV_RATE_2_5_GBPS;
	case 5:   return IBV_RATE_5_GBPS;
	case 10:  return IBV_RATE_10_GBPS;
#if HAVE_IBA_EXTENDED_RATES
	case 14:  return IBV_RATE_14_GBPS;
#endif
	case 20:  return IBV_RATE_20_GBPS;
#if HAVE_IBA_EXTENDED_RATES
	case 25:  return IBV_RATE_25_GBPS;
#endif
	case 30:  return IBV_RATE_30_GBPS;
	case 40:  return IBV_RATE_40_GBPS;
#if HAVE_IBA_EXTENDED_RATES
	case 56:  return IBV_RATE_56_GBPS;
#endif
	case 60:  return IBV_RATE_60_GBPS;
	case 80:  return IBV_RATE_80_GBPS;
#if HAVE_IBA_EXTENDED_RATES
	case 100: return IBV_RATE_100_GBPS;
	case 112: return IBV_RATE_112_GBPS;
#endif
	case 120: return IBV_RATE_120_GBPS;
#if HAVE_IBA_EXTENDED_RATES
	case 168: return IBV_RATE_168_GBPS;
	case 200: return IBV_RATE_200_GBPS;
	case 300: return IBV_RATE_300_GBPS;
#endif
	default:  return IBV_RATE_10_GBPS;
	}
}

static int acm_post_recvs(struct acm_ep *ep)
{
	struct ibv_pd *pd;
	int i, size;

	if (acm_mode == ACM_MODE_ACM)
		pd = ((struct acm_port *)ep->port)->dev->pd;
	else /* ACM_MODE_SSA */
		pd = ((struct ssa_port *)ep->port)->dev->pd;

	size = recv_depth * ACM_RECV_SIZE;
	ep->recv_bufs = malloc(size);
	if (!ep->recv_bufs) {
		ssa_log_err(0, "unable to allocate receive buffer\n");
		return ACM_STATUS_ENOMEM;
	}

	ep->mr = ibv_reg_mr(pd, ep->recv_bufs, size, IBV_ACCESS_LOCAL_WRITE);
	if (!ep->mr) {
		ssa_log_err(0, "unable to register receive buffer\n");
		goto err;
	}

	for (i = 0; i < recv_depth; i++) {
		acm_post_recv(ep, (uintptr_t) (ep->recv_bufs + ACM_RECV_SIZE * i));
	}
	return 0;

err:
	free(ep->recv_bufs);
	return -1;
}

static FILE *acm_open_addr_file(void)
{
	FILE *f;

	if ((f = fopen(addr_file, "r")))
		return f;

	ssa_log(SSA_LOG_DEFAULT, "notice - generating %s file\n", addr_file);
	if (!(f = popen(acme, "r"))) {
		ssa_log_err(0, "cannot generate %s\n", addr_file);
		return NULL;
	}
	pclose(f);
	return fopen(addr_file, "r");
}

/* Parse "opensm full v1" file to build LID to GUID table */
static void acm_parse_osm_fullv1_lid2guid(FILE *f, uint64_t *lid2guid)
{
	char s[128];
	char *p, *ptr, *p_guid, *p_lid;
	uint64_t guid;
	uint16_t lid;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;       /* ignore blank lines */

		if (strncmp(p, "Switch", sizeof("Switch") - 1) &&
		    strncmp(p, "Channel", sizeof("Channel") - 1) &&
		    strncmp(p, "Router", sizeof("Router") - 1))
			continue;

		if (!strncmp(p, "Channel", sizeof("Channel") - 1)) {
			p = strtok_r(NULL, " ", &ptr); /* skip 'Adapter' */
			if (!p)
				continue;
		}

		p_guid = strtok_r(NULL, ",", &ptr);
		if (!p_guid)
			continue;

		guid = (uint64_t) strtoull(p_guid, NULL, 16);

		ptr = strstr(ptr, "base LID");
		if (!ptr)
			continue;
		ptr += sizeof("base LID");
		p_lid = strtok_r(NULL, ",", &ptr);
		if (!p_lid)
			continue;

		lid = (uint16_t) strtoul(p_lid, NULL, 0);
		if (lid >= IB_LID_MCAST_START)
			continue;
		if (lid2guid[lid])
			ssa_log(SSA_LOG_DEFAULT, "ERROR - duplicate lid %u\n", lid);
		else
			lid2guid[lid] = htonll(guid);
	}
}

/* Parse 'opensm full v1' file to populate PR cache */
static int acm_parse_osm_fullv1_paths(FILE *f, uint64_t *lid2guid, struct acm_ep *ep)
{
	union ibv_gid sgid, dgid;
	struct ibv_port_attr attr = { 0 };
	struct ibv_context *verbs;
	struct acm_dest *dest;
	char s[128];
	char *p, *ptr, *p_guid, *p_lid;
	uint16_t *port_lid;
	uint8_t *port_num;
	uint64_t guid;
	uint16_t lid, dlid, net_dlid;
	int sl, mtu, rate;
	int ret, i;
	uint8_t addr[ACM_MAX_ADDRESS];
	uint8_t addr_type;

	if (acm_mode == ACM_MODE_ACM)
		verbs = ((struct acm_port *)(ep->port))->dev->verbs;
	else /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)(ep->port))->dev->verbs;

	port_num = GET_PORT_FIELD_PTR(ep->port, uint8_t, port_num);
	port_lid = GET_PORT_FIELD_PTR(ep->port, uint16_t, lid);
	ret = ibv_query_gid(verbs, *port_num, 0, &sgid);
	if (ret < 0) {
		ssa_log_err(0, "unable to query gid for port num %d\n",
			    *port_num);
		return ret;
	}

	/* Search for endpoint's SLID */
	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;       /* ignore blank lines */

		if (strncmp(p, "Switch", sizeof("Switch") - 1) &&
		    strncmp(p, "Channel", sizeof("Channel") - 1) &&
		    strncmp(p, "Router", sizeof("Router") - 1))
			continue;

		if (!strncmp(p, "Channel", sizeof("Channel") - 1)) {
			p = strtok_r(NULL, " ", &ptr); /* skip 'Adapter' */
			if (!p)
				continue;
		}

		p_guid = strtok_r(NULL, ",", &ptr);
		if (!p_guid)
			continue;

		guid = (uint64_t) strtoull(p_guid, NULL, 16);
		if (guid != ntohll(sgid.global.interface_id))
			continue;

		ptr = strstr(ptr, "base LID");
		if (!ptr)
			continue;
		ptr += sizeof("base LID");
		p_lid = strtok_r(NULL, ",", &ptr);
		if (!p_lid)
			continue;

		lid = (uint16_t) strtoul(p_lid, NULL, 0);
		if (lid != *port_lid)
		        continue;

		ret = ibv_query_port(verbs, *port_num, &attr);
		if (ret) {
			ssa_log_err(0, "unable to get port state ERROR %d (%s)\n",
				    errno, strerror(errno));
			return ret;
		}
		ret = 0;
		break;
	}

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;       /* ignore blank lines */
		if (!strncmp(p, "Switch", sizeof("Switch") - 1) ||
		    !strncmp(p, "Channel", sizeof("Channel") - 1) ||
		    !strncmp(p, "Router", sizeof("Router") - 1))
			break;

		dlid = strtoul(p, NULL, 0);
		net_dlid = htons(dlid);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		if (strcmp(p, "UNREACHABLE") == 0)
			continue;
		sl = atoi(p);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		mtu = atoi(p);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		rate = atoi(p);

		if (!lid2guid[dlid]) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - dlid %u not found in lid2guid table\n", dlid);
			continue;
	        }

	        dgid.global.subnet_prefix = sgid.global.subnet_prefix;
	        dgid.global.interface_id = lid2guid[dlid];

	        for (i = 0; i < 2; i++) {
			memset(addr, 0, ACM_MAX_ADDRESS);
			if (i == 0) {
				addr_type = ACM_ADDRESS_LID;
				memcpy(addr, &net_dlid, sizeof net_dlid);
			} else {
				addr_type = ACM_ADDRESS_GID;
				memcpy(addr, &dgid, sizeof(dgid));
			}
			dest = acm_acquire_dest(ep, addr_type, addr);
			if (!dest) {
				ssa_log(SSA_LOG_DEFAULT,
					"ERROR - unable to create dest\n");
				break;
			}

			dest->path.sgid = sgid;
			dest->path.slid = htons(*port_lid);
			dest->path.dgid = dgid;
			dest->path.dlid = net_dlid;
			dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
			dest->path.pkey = htons(ep->pkey);
			dest->path.mtu = (uint8_t) mtu;
			dest->path.rate = (uint8_t) rate;
			dest->path.qosclass_sl = htons((uint16_t) sl & 0xF);
			if (dlid == *port_lid) {
				dest->path.packetlifetime = 0;
				dest->addr_timeout = (uint64_t)~0ULL;
				dest->route_timeout = (uint64_t)~0ULL;
			} else {
				dest->path.packetlifetime = attr.subnet_timeout;
				dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
				dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
			}
			dest->remote_qpn = 1;
			dest->state = ACM_READY;
			acm_put_dest(dest);
			ssa_log(SSA_LOG_VERBOSE, "added cached dest %s\n",
				dest->name);
	        }
	}
	return ret;
}

static int acm_parse_osm_fullv1(struct acm_ep *ep)
{
	FILE *f;
	uint64_t *lid2guid;
	int ret = 1;

	if (!(f = fopen(route_data_file, "r"))) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR - couldn't open %s\n",
			route_data_file);
		return ret;
	}

	lid2guid = calloc(IB_LID_MCAST_START, sizeof(*lid2guid));
	if (!lid2guid) {
		ssa_log(SSA_LOG_DEFAULT,
			"ERROR - no memory for path record parsing\n");
		goto err;
	}

	acm_parse_osm_fullv1_lid2guid(f, lid2guid);
	rewind(f);
	ret = acm_parse_osm_fullv1_paths(f, lid2guid, ep);
	free(lid2guid);
err:
	fclose(f);
	return ret;
}

/* Parse "access layer v1" file to build LID to GUID table */
static void acm_parse_access_v1_lid2guid(struct ssa_db *p_ssa_db, uint64_t *lid2guid)
{
	struct ep_pr_tbl_rec *p_pr_tbl;
	struct ep_pr_tbl_rec *p_pr_rec;
	uint64_t guid;
	uint64_t pr_cnt;
	uint64_t i;
	uint16_t lid;

	p_pr_tbl = (struct ep_pr_tbl_rec *) p_ssa_db->pp_tables[SSA_PR_TABLE_ID];
	pr_cnt = ntohll(p_ssa_db->p_db_tables[SSA_PR_TABLE_ID].set_count);

	for (i = 0; i < pr_cnt; i++) {
		p_pr_rec = p_pr_tbl + i;
		guid = p_pr_rec->guid;
		lid = ntohs(p_pr_rec->lid);

		if (lid >= IB_LID_MCAST_START)
			continue;
		if (lid2guid[lid])
			ssa_log(SSA_LOG_DEFAULT, "ERROR - duplicate lid %u\n", lid);
		else
			lid2guid[lid] = guid;
	}
}

/* Parse 'access layer v1' file to populate PR cache */
static int acm_parse_access_v1_paths(struct ssa_db *p_ssa_db,
				     uint64_t *lid2guid, struct acm_ep *ep)
{
	union ibv_gid sgid, dgid;
	struct ibv_port_attr attr = { 0 };
	struct ibv_context *verbs;
	struct acm_dest *dest;
	struct ep_pr_tbl_rec *p_pr_tbl, *p_pr_rec;
	uint16_t *port_lid;
	uint8_t *port_num;
	uint64_t guid, i, k, pr_cnt;
	uint16_t lid, dlid;
	int sl, mtu, rate;
	int ret = 1;
	uint8_t addr[ACM_MAX_ADDRESS];
	union ibv_gid *gid_addr = (union ibv_gid *) &addr;
	uint16_t *lid_addr = (uint16_t *) &addr;
	uint8_t addr_type;

	if (acm_mode == ACM_MODE_ACM)
		verbs = ((struct acm_port *)(ep->port))->dev->verbs;
	else /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)(ep->port))->dev->verbs;

	port_num = GET_PORT_FIELD_PTR(ep->port, uint8_t, port_num);
	port_lid = GET_PORT_FIELD_PTR(ep->port, uint16_t, lid);
	ret = ibv_query_gid(verbs, *port_num, 0, &sgid);
	if (ret < 0) {
		ssa_log_err(0, "unable to query gid for port num %d\n",
			    *port_num);
		return ret;
	}

	p_pr_tbl = (struct ep_pr_tbl_rec *) p_ssa_db->pp_tables[SSA_PR_TABLE_ID];
	pr_cnt = ntohll(p_ssa_db->p_db_tables[SSA_PR_TABLE_ID].set_count);

	/* Search for endpoint's SLID */
	for (i = 0; i < pr_cnt; i++) {
		p_pr_rec = p_pr_tbl + i;
		guid = p_pr_rec->guid;
		if (guid !=  sgid.global.interface_id)
			continue;

		lid = ntohs(p_pr_rec->lid);
		if (lid != *port_lid)
		        continue;

		ret = ibv_query_port(verbs, *port_num, &attr);
		if (ret) {
			ssa_log_err(0, "unable to get port state ERROR %d (%s)\n",
				    errno, strerror(errno));
			return ret;
		}
		ret = 0;
		break;
	}

	for (k = 0; k < pr_cnt; k++) {
		p_pr_rec = p_pr_tbl + k;
		dlid = ntohs(p_pr_rec->lid);
		sl = p_pr_rec->sl;
		mtu = p_pr_rec->mtu;
		rate = p_pr_rec->rate;

		if (!lid2guid[dlid]) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - dlid %u not found in lid2guid table\n", dlid);
			continue;
	        }

	        dgid.global.subnet_prefix = sgid.global.subnet_prefix;
	        dgid.global.interface_id = lid2guid[dlid];

	        for (i = 0; i < 2; i++) {
			memset(addr, 0, ACM_MAX_ADDRESS);
			if (i == 0) {
				addr_type = ACM_ADDRESS_LID;
				*lid_addr = htons(dlid);
			} else {
				addr_type = ACM_ADDRESS_GID;
				memcpy(gid_addr, &dgid, sizeof(dgid));
			}
			dest = acm_acquire_dest(ep, addr_type, addr);
			if (!dest) {
				ssa_log(SSA_LOG_DEFAULT,
					"ERROR - unable to create dest\n");
				break;
			}

			dest->path.sgid = sgid;
			dest->path.slid = htons(*port_lid);
			dest->path.dgid = dgid;
			dest->path.dlid = htons(dlid);
			dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
			dest->path.pkey = htons(ep->pkey);
			dest->path.mtu = (uint8_t) mtu;
			dest->path.rate = (uint8_t) rate;
			dest->path.qosclass_sl = htons((uint16_t) sl & 0xF);
			if (dlid == *port_lid) {
				dest->path.packetlifetime = 0;
				dest->addr_timeout = (uint64_t)~0ULL;
				dest->route_timeout = (uint64_t)~0ULL;
			} else {
				dest->path.packetlifetime = attr.subnet_timeout;
				dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
				dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
			}
			dest->remote_qpn = 1;
			dest->state = ACM_READY;
			acm_put_dest(dest);
			ssa_log(SSA_LOG_VERBOSE, "added cached dest %s\n",
				dest->name);
	        }
	}
	return ret;
}

static void
acm_parse_access_v1_paths_update(uint64_t *lid2guid, uint64_t *lid2guid_cached,
				 struct acm_ep *ep)
{
	union ibv_gid sgid, dgid;
	struct ssa_port *port;
	struct acm_dest *dest, **tdest;
	uint16_t dlid;
	uint8_t addr[ACM_MAX_ADDRESS];
	union ibv_gid *gid_addr = (union ibv_gid *) &addr;
	uint16_t *lid_addr = (uint16_t *) &addr;
	int ret;
	uint8_t addr_type, k;

	if (!lid2guid_cached || !lid2guid)
		return;

	port = (struct ssa_port *)ep->port;

	ret = ibv_query_gid(port->dev->verbs, port->port_num, 0, &sgid);
	if (ret < 0)
		ssa_log_err(0, "unable to query gid for port num %d\n",
			    port->port_num);
	dgid.global.subnet_prefix = sgid.global.subnet_prefix;

	for (dlid = 1; dlid < IB_LID_MCAST_START; dlid++) {
		if (!lid2guid_cached[dlid])
			continue;

		if (lid2guid[dlid])
			continue;

		/* removing old dest records from ep cache */
		for (k = 0; k < 2; k++) {
			memset(addr, 0, ACM_MAX_ADDRESS);
			if (k == 0) {
				addr_type = ACM_ADDRESS_LID;
				*lid_addr = htons(dlid);
			} else {
				dgid.global.interface_id = lid2guid_cached[dlid];
				addr_type = ACM_ADDRESS_GID;
				memcpy(gid_addr, &dgid, sizeof(dgid));
			}

			pthread_mutex_lock(&ep->lock);
			if (addr_type == ACM_ADDRESS_LID)
				tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_lid);
			else if (addr_type == ACM_ADDRESS_GID)
				tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_gid);
#if 0
			else
				tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest);
#endif
			if (tdest) {
				dest = *tdest;
				ssa_log(SSA_LOG_VERBOSE, "removing cached dest %s\n", dest->name);
				if (addr_type == ACM_ADDRESS_LID)
					tdelete(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_lid);
				else if (addr_type == ACM_ADDRESS_GID)
					tdelete(addr, &ep->dest_map[addr_type - 1], acm_compare_dest_by_gid);
#if 0
				else
					tdelete(addr, &ep->dest_map[addr_type - 1], acm_compare_dest);
#endif
				acm_put_dest(dest);
			} else {
				acm_format_name(SSA_LOG_VERBOSE, log_data, sizeof log_data,
						addr_type, addr, ACM_MAX_ADDRESS);
				ssa_log(SSA_LOG_VERBOSE,
					"ERROR: %s not found\n", log_data);
			}
			pthread_mutex_unlock(&ep->lock);
		}
	}
}

static int acm_parse_access_v1(struct acm_ep *ep)
{
	struct ssa_db *p_ssa_db;
	uint64_t *lid2guid;
	int ret = 1;

	if (!(p_ssa_db = ssa_db_load(route_data_dir, SSA_DB_HELPER_DEBUG))) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR - couldn't load PRDB from %s\n",
			route_data_dir);
		return ret;
	}

	lid2guid = calloc(IB_LID_MCAST_START, sizeof(*lid2guid));
	if (!lid2guid) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR - no memory for path record parsing\n");
		goto err;
	}

	acm_parse_access_v1_lid2guid(p_ssa_db, lid2guid);
	ret = acm_parse_access_v1_paths(p_ssa_db, lid2guid, ep);
	acm_parse_access_v1_paths_update(lid2guid, lid2guid_cached, ep);
	if (lid2guid_cached)
		free(lid2guid_cached);
	lid2guid_cached = lid2guid;
err:
	ssa_db_destroy(p_ssa_db);
	return ret;
}

static void acm_parse_hosts_file(struct acm_ep *ep)
{
	FILE *f;
	char s[120];
	char addr[INET6_ADDRSTRLEN], gid[INET6_ADDRSTRLEN];
	uint8_t name[ACM_MAX_ADDRESS];
	struct in6_addr ip_addr, ib_addr;
	struct acm_dest *dest, *gid_dest;
	uint8_t addr_type;

	if (!(f = fopen(addr_data_file, "r"))) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR - couldn't open %s\n",
			addr_data_file);
		return;
        }

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%46s%46s", addr, gid) != 2)
			continue;

		ssa_log(SSA_LOG_VERBOSE, "%s", s);
		if (inet_pton(AF_INET6, gid, &ib_addr) <= 0) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - %s is not IB GID\n", gid);
			continue;
		}
		memset(name, 0, ACM_MAX_ADDRESS);
		if (inet_pton(AF_INET, addr, &ip_addr) > 0) {
			addr_type = ACM_ADDRESS_IP;
			memcpy(name, &ip_addr, 4);
		} else if (inet_pton(AF_INET6, addr, &ip_addr) > 0) {
			addr_type = ACM_ADDRESS_IP6;
			memcpy(name, &ip_addr, sizeof(ip_addr));
		} else {
			addr_type = ACM_ADDRESS_NAME;
			strncpy((char *)name, addr, ACM_MAX_ADDRESS);
		}

		dest = acm_acquire_dest(ep, addr_type, name);
		if (!dest) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to create dest %s\n", addr);
			continue;
		}

		memset(name, 0, ACM_MAX_ADDRESS);
		memcpy(name, &ib_addr, sizeof(ib_addr));
		gid_dest = acm_get_dest(ep, ACM_ADDRESS_GID, name);
		if (gid_dest) {
			dest->path = gid_dest->path;
			dest->state = ACM_READY;
			acm_put_dest(gid_dest);
		} else {
			memcpy(&dest->path.dgid, &ib_addr, 16);
			if (acm_mode == ACM_MODE_ACM) {
				//ibv_query_gid(((struct acm_port *)ep->port)->dev->verbs,
				//		((struct acm_port *)ep->port)->port_num,
				//		0, &dest->path.sgid);
				dest->path.slid = htons(((struct acm_port *)ep->port)->lid);
			} else {	/* ACM_MODE_SSA */
				//ibv_query_gid(((struct ssa_port *)ep->port)->dev->verbs,
				//		((struct ssa_port *)ep->port)->port_num,
				//		0, &dest->path.sgid);
				dest->path.slid = htons(((struct ssa_port *)ep->port)->lid);
			}
			dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
			dest->path.pkey = htons(ep->pkey);
			dest->state = ACM_ADDR_RESOLVED;
		}

		dest->remote_qpn = 1;
		dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
		dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
		acm_put_dest(dest);
		ssa_log(SSA_LOG_VERBOSE,
			"added host %s address type %d IB GID %s\n",
			addr, addr_type, gid);
	}

	fclose(f);
}

static int acm_assign_ep_names(struct acm_ep *ep)
{
	FILE *faddr;
	char *dev_name;
	uint8_t *port_num;
	char s[120];
	char dev[32], addr[INET6_ADDRSTRLEN], pkey_str[8];
	uint16_t pkey;
	uint8_t type;
	int port, index = 0;
	struct in6_addr ip_addr;

	if (acm_mode == ACM_MODE_ACM)
		dev_name = ((struct acm_port *)ep->port)->dev->verbs->device->name;
	else /* ACM_MODE_SSA */
		dev_name = ((struct ssa_port *)ep->port)->dev->name;

	port_num = GET_PORT_FIELD_PTR(ep->port, uint8_t, port_num);
	ssa_log(SSA_LOG_VERBOSE, "device %s, port %d, pkey 0x%x\n",
		dev_name, *port_num, ep->pkey);
	if (!(faddr = acm_open_addr_file())) {
		ssa_log_err(0, "address file not found\n");
		return -1;
	}

	while (fgets(s, sizeof s, faddr)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%46s%32s%d%8s", addr, dev, &port, pkey_str) != 4)
			continue;

		ssa_log(SSA_LOG_VERBOSE, "%s", s);
		if (inet_pton(AF_INET, addr, &ip_addr) > 0)
			type = ACM_ADDRESS_IP;
		else if (inet_pton(AF_INET6, addr, &ip_addr) > 0)
			type = ACM_ADDRESS_IP6;
		else
			type = ACM_ADDRESS_NAME;

		if (strcasecmp(pkey_str, "default")) {
			if (sscanf(pkey_str, "%hx", &pkey) != 1) {
				ssa_log_err(0, "bad pkey format %s\n", pkey_str);
				continue;
			}
		} else {
			pkey = 0xFFFF;
		}

		if (!strcasecmp(dev_name, dev) && (*port_num == (uint8_t) port) &&
			(ep->pkey == pkey)) {

			ep->addr_type[index] = type;
			ssa_log(SSA_LOG_VERBOSE, "assigning %s\n", addr);
			strncpy(ep->name[index], addr, ACM_MAX_ADDRESS);
			if (type == ACM_ADDRESS_IP)
				memcpy(ep->addr[index].addr, &ip_addr, 4);
			else if (type == ACM_ADDRESS_IP6)
				memcpy(ep->addr[index].addr, &ip_addr, sizeof ip_addr);
			else
				strncpy((char *) ep->addr[index].addr, addr, ACM_MAX_ADDRESS);

			if (++index == MAX_EP_ADDR) {
				ssa_log(SSA_LOG_VERBOSE,
					"maximum number of names assigned to EP\n");
				break;
			}
		}
	}
	fclose(faddr);

	return !index;
}

/*
 * We currently require that the routing data be preloaded in order to
 * load the address data.  This is backwards from normal operation, which
 * usually resolves the address before the route.
 */
static void acm_ep_preload(struct acm_ep *ep)
{
	switch (route_preload) {
	case ACM_ROUTE_PRELOAD_OSM_FULL_V1:
		if (acm_parse_osm_fullv1(ep))
			ssa_log(SSA_LOG_DEFAULT, "ERROR - failed to preload EP\n");
		break;
	case ACM_ROUTE_PRELOAD_ACCESS_V1:
		if (acm_parse_access_v1(ep))
			ssa_log(SSA_LOG_DEFAULT, "ERROR - failed to preload EP\n");
		break;
	default:
		break;
	}

	switch (addr_preload) {
	case ACM_ADDR_PRELOAD_HOSTS:
		acm_parse_hosts_file(ep);
		break;
	default:
		break;
	}
}

static int acm_init_ep_loopback(struct acm_ep *ep)
{
	struct acm_dest *dest;
	struct ibv_context *verbs;
	uint16_t *lid;
	uint8_t *port_num, *mtu, *rate;
	int i, ret;

	ssa_log_func(SSA_LOG_VERBOSE);
	if (loopback_prot != ACM_LOOPBACK_PROT_LOCAL)
		return 0;

	if (acm_mode == ACM_MODE_ACM)
		verbs = ((struct acm_port *)ep->port)->dev->verbs;
	else /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)ep->port)->dev->verbs;

	lid = GET_PORT_FIELD_PTR(ep->port, uint16_t, lid);
	port_num = GET_PORT_FIELD_PTR(ep->port, uint8_t, port_num);
	mtu = GET_PORT_FIELD_PTR(ep->port, uint8_t, mtu);
	rate = GET_PORT_FIELD_PTR(ep->port, uint8_t, rate);
	for (i = 0; i < MAX_EP_ADDR && ep->addr_type[i]; i++) {
		dest = acm_acquire_dest(ep, ep->addr_type[i], ep->addr[i].addr);
		if (!dest) {
			acm_format_name(SSA_LOG_DEFAULT, log_data, sizeof log_data,
					ep->addr_type[i], ep->addr[i].addr,
					sizeof ep->addr[i].addr);
			ssa_log_err(0, "unable to create loopback dest %s\n", log_data);
			return -1;
		}

		ret = ibv_query_gid(verbs, *port_num, 0, &dest->path.sgid);
		if (ret < 0) {
			ssa_log_err(0, "unable to query gid for port num %d\n",
				    port_num);
			return -1;
		}

		dest->path.dgid = dest->path.sgid;
		dest->path.dlid = dest->path.slid = htons(*lid);
		dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
		dest->path.pkey = htons(ep->pkey);
		dest->path.mtu = (uint8_t) *mtu;
		dest->path.rate = (uint8_t) *rate;

		dest->remote_qpn = ep->qp->qp_num;
		dest->addr_timeout = (uint64_t) ~0ULL;
		dest->route_timeout = (uint64_t) ~0ULL;
		dest->state = ACM_READY;
		acm_put_dest(dest);
		ssa_log(SSA_LOG_VERBOSE, "added loopback dest %s\n", dest->name);
	}
	return 0;
}

static struct acm_ep *acm_find_ep(void *port, uint16_t pkey)
{
	struct acm_ep *ep, *res = NULL;
	DLIST_ENTRY *ep_list, *entry;
	pthread_mutex_t *lock;

	ssa_log(SSA_LOG_VERBOSE, "pkey 0x%x\n", pkey);

	lock = GET_PORT_FIELD_PTR(port, pthread_mutex_t, lock);
	pthread_mutex_lock(lock);
	ep_list = GET_PORT_FIELD_PTR(port, DLIST_ENTRY, ep_list);
	for (entry = ep_list->Next; entry != ep_list; entry = entry->Next) {
		ep = container_of(entry, struct acm_ep, entry);
		if (ep->pkey == pkey) {
			res = ep;
			break;
		}
	}
	pthread_mutex_unlock(lock);
	return res;
}

static struct acm_ep *
acm_alloc_ep(void *port, uint16_t pkey, uint16_t pkey_index)
{
	struct acm_ep *ep;

	ssa_log_func(SSA_LOG_VERBOSE);
	ep = calloc(1, sizeof *ep);
	if (!ep)
		return NULL;

	ep->port = port;
	ep->pkey = pkey;
	ep->pkey_index = pkey_index;
	ep->resolve_queue.credits = resolve_depth;
	ep->sa_queue.credits = sa_depth;
	ep->resp_queue.credits = send_depth;
	DListInit(&ep->resolve_queue.pending);
	DListInit(&ep->sa_queue.pending);
	DListInit(&ep->resp_queue.pending);
	DListInit(&ep->active_queue);
	DListInit(&ep->wait_queue);
	pthread_mutex_init(&ep->lock, NULL);

	return ep;
}

static void *acm_issue_query(void *context)
{
	struct ssa_svc *svc = context;
	int i, ret = -SSA_DB_QUERY_NO_UPSTREAM_CONN;

	SET_THREAD_NAME(query_thread, "QUERY");

	ssa_log_func(SSA_LOG_CTRL);

	while (svc->state != SSA_STATE_CONNECTED)
		usleep(acm_query_timeout);

	usleep(acm_query_timeout);	/* delay - so first attempt likely to succeed */

	for (i = 0; i <= acm_query_retries; i++) {	/* for total default max of ~1 second */
		ret = ssa_upstream_query_db(svc);
		if (!ret || !acm_query_retries)
			break;
		usleep(acm_query_timeout);	/* delay before next attempt */
	}

	if (ret)
		ssa_log_warn(SSA_LOG_CTRL,
			     "terminating without successful DB query last ret %d\n", ret);
	acm_issue_query_done = 1;
	return NULL;
}

void acm_ep_up(void *port, uint16_t pkey_index)
{
	struct acm_ep *ep;
	struct ibv_context *verbs;
	struct ibv_comp_channel *channel;
	struct ibv_pd *pd;
	DLIST_ENTRY *ep_list;
	pthread_mutex_t *lock;
	uint8_t *port_num;
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr attr;
	int ret, sq_size;
	uint16_t pkey;

	ssa_log_func(SSA_LOG_VERBOSE);

	if (acm_mode == ACM_MODE_ACM) {
		verbs = ((struct acm_port *)port)->dev->verbs;
		channel = ((struct acm_port *)port)->dev->channel;
		pd = ((struct acm_port *)port)->dev->pd;
	} else { /* ACM_MODE_SSA */
		verbs = ((struct ssa_port *)port)->dev->verbs;
		channel = ((struct ssa_port *)port)->dev->channel;
		pd = ((struct ssa_port *)port)->dev->pd;
	}

	port_num = GET_PORT_FIELD_PTR(port, uint8_t, port_num);
	lock = GET_PORT_FIELD_PTR(port, pthread_mutex_t, lock);
	ret = ibv_query_pkey(verbs, *port_num, pkey_index, &pkey);
	if (ret)
		return;

	pkey = ntohs(pkey);	/* ibv_query_pkey returns pkey in network order */
	if (acm_find_ep(port, pkey)) {
		ssa_log(SSA_LOG_VERBOSE,
			"endpoint for pkey 0x%x already exists\n", pkey);
		return;
	}

	ssa_log(SSA_LOG_VERBOSE, "creating endpoint for pkey 0x%x\n", pkey);
	ep = acm_alloc_ep(port, pkey, pkey_index);
	if (!ep)
		return;

	ret = acm_assign_ep_names(ep);
	if (ret) {
		ssa_log_err(0, "unable to assign EP name for pkey 0x%x\n", pkey);
		goto err0;
	}

	sq_size = resolve_depth + sa_depth + send_depth;
	ep->cq = ibv_create_cq(verbs, sq_size + recv_depth, ep, channel, 0);
	if (!ep->cq) {
		ssa_log_err(0, "failed to create CQ\n");
		goto err0;
	}

	ret = ibv_req_notify_cq(ep->cq, 0);
	if (ret) {
		ssa_log_err(0, "failed to arm CQ\n");
		goto err1;
	}

	memset(&init_attr, 0, sizeof init_attr);
	init_attr.cap.max_send_wr = sq_size;
	init_attr.cap.max_recv_wr = recv_depth;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_context = ep;
	init_attr.sq_sig_all = 1;
	init_attr.qp_type = IBV_QPT_UD;
	init_attr.send_cq = ep->cq;
	init_attr.recv_cq = ep->cq;
	ep->qp = ibv_create_qp(pd, &init_attr);
	if (!ep->qp) {
		ssa_log_err(0, "failed to create QP\n");
		goto err1;
	}

	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = *port_num;
	attr.pkey_index = pkey_index;
	attr.qkey = ACM_QKEY;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
		IBV_QP_PORT | IBV_QP_QKEY);
	if (ret) {
		ssa_log_err(0, "failed to modify QP to init\n");
		goto err2;
	}

	attr.qp_state = IBV_QPS_RTR;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE);
	if (ret) {
		ssa_log_err(0, "failed to modify QP to rtr\n");
		goto err2;
	}

	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN);
	if (ret) {
		ssa_log_err(0, "failed to modify QP to rts\n");
		goto err2;
	}

	ret = acm_post_recvs(ep);
	if (ret)
		goto err2;

	ret = acm_init_ep_loopback(ep);
	if (ret) {
		ssa_log_err(0, "unable to init loopback\n");
		goto err2;
	}

	/* TODO: this is done instead of in port_join method */
	ep->state = ACM_READY;

	pthread_mutex_lock(lock);
	ep_list = GET_PORT_FIELD_PTR(port, DLIST_ENTRY, ep_list);
	DListInsertHead(&ep->entry, ep_list);
	pthread_mutex_unlock(lock);

	acm_ep_preload(ep);
	return;

err2:
	ibv_destroy_qp(ep->qp);
err1:
	ibv_destroy_cq(ep->cq);
err0:
	free(ep);
}

static int acm_parse_ssa_db(struct ssa_db *p_ssa_db, struct ssa_svc *svc)
{
	struct ssa_device *ssa_dev1 = NULL;
	struct ssa_port *port;
	struct acm_ep *acm_ep;
	uint64_t *lid2guid;
	uint16_t pkey;
	int d, ret = 1;

	if (!p_ssa_db)
		return ret;

	for (d = 0; d < ssa.dev_cnt; d++) {
		ssa_dev1 = ssa_dev(&ssa, d);
		if (ssa_dev1->guid == svc->port->dev->guid)
			break;
	}

	if (!ssa_dev1 || d == ssa.dev_cnt) {
		ssa_log(SSA_LOG_DEFAULT,
			"ERROR - no matching SSA device found "
			"(with guid: 0x%" PRIx64 ")\n",
			ntohll(svc->port->dev->guid));
		goto err;
	}

	port = ssa_dev_port(ssa_dev1, svc->port->port_num);

	/* assume single pkey per port */
	ret = ibv_query_pkey(port->dev->verbs, port->port_num, 0, &pkey);
	if (ret)
		goto err;

	ssa_log(SSA_LOG_VERBOSE,
		"updating cache with new prdb epoch 0x%" PRIx64 "\n",
		ssa_db_get_epoch(p_ssa_db, DB_DEF_TBL_ID));

	acm_ep = acm_find_ep(port, pkey);
	if (!acm_ep) {
		ret = 1;
		goto err;
	}

	lid2guid = calloc(IB_LID_MCAST_START, sizeof(*lid2guid));
	if (!lid2guid) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR - no memory for path record parsing\n");
		goto err;
	}

	acm_parse_access_v1_lid2guid(p_ssa_db, lid2guid);
	ret = acm_parse_access_v1_paths(p_ssa_db, lid2guid, acm_ep);
	acm_parse_access_v1_paths_update(lid2guid, lid2guid_cached, acm_ep);
	if (lid2guid_cached)
		free(lid2guid_cached);
	lid2guid_cached = lid2guid;

	ssa_log(SSA_LOG_VERBOSE,
		"cache update complete with prdb epoch 0x%" PRIx64 "\n",
		ssa_db_get_epoch(p_ssa_db, DB_DEF_TBL_ID));
err:
	/* TODO: decide whether the destroy call is needed */
	/* ssa_db_destroy(p_ssa_db); */
	return ret;
}

static void acm_port_up(struct acm_port *port)
{
	struct ibv_port_attr attr;
	union ibv_gid gid;
	uint16_t pkey;
	int i, ret;

	ssa_log(SSA_LOG_VERBOSE, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (ret) {
		ssa_log_err(0, "unable to get port state ERROR %d (%s)\n",
			    errno, strerror(errno));
		return;
	}

	if (attr.state != IBV_PORT_ACTIVE) {
		ssa_log(SSA_LOG_VERBOSE, "port not active\n");
		return;
	}

	port->mtu = attr.active_mtu;
	port->rate = acm_get_rate(attr.active_width, attr.active_speed);
	if (attr.subnet_timeout >= 8)
		port->subnet_timeout = 1 << (attr.subnet_timeout - 8);
	for (port->gid_cnt = 0;; port->gid_cnt++) {
		ret = ibv_query_gid(port->dev->verbs, port->port_num, port->gid_cnt, &gid);
		if (ret)
			ssa_log_err(0, "unable to query gid for port num %d\n",
				    port->port_num);
		if (ret || !gid.global.interface_id)
			break;
	}

	for (port->pkey_cnt = 0;; port->pkey_cnt++) {
		ret = ibv_query_pkey(port->dev->verbs, port->port_num, port->pkey_cnt, &pkey);
		if (ret || !pkey)
			break;
	}
	port->lid = attr.lid;
	port->lid_mask = 0xffff - ((1 << attr.lmc) - 1);

	port->sa_dest.av.src_path_bits = 0;
	port->sa_dest.av.dlid = attr.sm_lid;
	port->sa_dest.av.sl = attr.sm_sl;
	port->sa_dest.av.port_num = port->port_num;
	port->sa_dest.remote_qpn = 1;
	attr.sm_lid = htons(attr.sm_lid);
	acm_set_dest_addr(&port->sa_dest, ACM_ADDRESS_LID,
		(uint8_t *) &attr.sm_lid, sizeof(attr.sm_lid));

	port->sa_dest.ah = ibv_create_ah(port->dev->pd, &port->sa_dest.av);
	if (!port->sa_dest.ah)
		return;

	atomic_set(&port->sa_dest.refcnt, 1);
	for (i = 0; i < port->pkey_cnt; i++)
		 acm_ep_up(port, (uint16_t) i);

	acm_port_join(port);
	port->state = IBV_PORT_ACTIVE;
	ssa_log(SSA_LOG_VERBOSE, "%s %d is up\n",
		port->dev->verbs->device->name, port->port_num);
}

static void acm_port_down(struct acm_port *port)
{
	struct ibv_port_attr attr;
	int ret;

	ssa_log(SSA_LOG_VERBOSE, "%s %d\n",
		port->dev->verbs->device->name, port->port_num);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (ret) {
		ssa_log_err(0, "unable to get port state ERROR %d (%s)\n",
			    errno, strerror(errno));
		return;
	}
	if (!ret && attr.state == IBV_PORT_ACTIVE) {
		ssa_log(SSA_LOG_VERBOSE, "port active\n");
		return;
	}

	port->state = attr.state;

	/*
	 * We wait for the SA destination to be released.  We could use an
	 * event instead of a sleep loop, but it's not worth it given how
	 * infrequently we should be processing a port down event in practice.
	 */
	atomic_dec(&port->sa_dest.refcnt);
	while (atomic_get(&port->sa_dest.refcnt))
		sleep(0);
	ibv_destroy_ah(port->sa_dest.ah);
	ssa_log(SSA_LOG_VERBOSE, "%s %d is down\n",
		port->dev->verbs->device->name, port->port_num);
}

/*
 * There is one event handler thread per device.  This is the only thread that
 * modifies the port state or a port endpoint list.  Other threads which access
 * those must synchronize against changes accordingly, but this thread only
 * needs to lock when making modifications.
 */
static void *acm_event_handler(void *context)
{
	struct acm_device *dev = (struct acm_device *) context;
	struct ibv_async_event event;
	int i, ret;

	SET_THREAD_NAME(event_thread, "EVENT_0x%" PRIx64, dev->guid);

	ssa_log(SSA_LOG_VERBOSE, "started\n");
	for (i = 0; i < dev->port_cnt; i++) {
		acm_port_up(&dev->port[i]);
	}

	for (;;) {
		ret = ibv_get_async_event(dev->verbs, &event);
		if (ret)
			continue;

		ssa_log(SSA_LOG_VERBOSE, "processing async event %s\n",
			ibv_event_type_str(event.event_type));
		i = event.element.port_num - 1;
		switch (event.event_type) {
		case IBV_EVENT_PORT_ACTIVE:
			if (dev->port[i].state != IBV_PORT_ACTIVE)
				acm_port_up(&dev->port[i]);
			break;
		case IBV_EVENT_PORT_ERR:
			if (dev->port[i].state == IBV_PORT_ACTIVE)
				acm_port_down(&dev->port[i]);
			break;
		default:
			break;
		}

		ibv_ack_async_event(&event);
	}
	return context;
}

static void acm_activate_devices()
{
	struct acm_device *dev;
	struct ssa_device *ssa_dev1;
	DLIST_ENTRY *dev_entry;
	int d;

	ssa_log_func(SSA_LOG_VERBOSE);
	if (acm_mode == ACM_MODE_ACM) {
		for (dev_entry = device_list.Next; dev_entry != &device_list;
			dev_entry = dev_entry->Next) {

			dev = container_of(dev_entry, struct acm_device, entry);
			pthread_create(&event_thread, NULL, acm_event_handler, dev);
			pthread_create(&comp_thread, NULL, acm_comp_handler, dev);
		}
	} else { /* ACM_MODE_SSA */
		for (d = 0; d < ssa.dev_cnt; d++) {
			ssa_dev1 = ssa_dev(&ssa, d);
			pthread_create(&comp_thread, NULL, acm_comp_handler, ssa_dev1);
		}
	}
}

static void acm_open_port(struct acm_port *port, struct acm_device *dev, uint8_t port_num)
{
	ssa_log(SSA_LOG_VERBOSE, "%s %d\n", dev->verbs->device->name, port_num);
	port->dev = dev;
	port->port_num = port_num;
	pthread_mutex_init(&port->lock, NULL);
	DListInit(&port->ep_list);
	acm_init_dest(&port->sa_dest, ACM_ADDRESS_LID, NULL, 0);

	port->mad_portid = umad_open_port(dev->verbs->device->name, port->port_num);
	if (port->mad_portid < 0) {
		ssa_log_err(0, "unable to open MAD port\n");
		return;
	}

	port->mad_agentid = umad_register(port->mad_portid,
		IB_MGMT_CLASS_SA, 1, 1, NULL);
	if (port->mad_agentid < 0) {
		ssa_log_err(0, "unable to register MAD client\n");
		goto err;
	}

	port->state = IBV_PORT_DOWN;
	return;
err:
	umad_close_port(port->mad_portid);
}

static void acm_open_dev(struct ibv_device *ibdev)
{
	struct acm_device *dev;
	struct ibv_device_attr attr;
	struct ibv_context *verbs;
	size_t size;
	int i, ret;

	ssa_log(SSA_LOG_VERBOSE, "%s\n", ibdev->name);
	verbs = ibv_open_device(ibdev);
	if (verbs == NULL) {
		ssa_log_err(0, "opening device %s\n", ibdev->name);
		return;
	}

	ret = ibv_query_device(verbs, &attr);
	if (ret) {
		ssa_log_err(0, "ibv_query_device (%s) %d\n", ret, ibdev->name);
		goto err1;
	}

	size = sizeof(*dev) + sizeof(struct acm_port) * attr.phys_port_cnt;
	dev = (struct acm_device *) calloc(1, size);
	if (!dev)
		goto err1;

	dev->verbs = verbs;
	dev->guid = ibv_get_device_guid(ibdev);
	dev->port_cnt = attr.phys_port_cnt;

	dev->pd = ibv_alloc_pd(dev->verbs);
	if (!dev->pd) {
		ssa_log_err(0, "unable to allocate PD\n");
		goto err2;
	}

	dev->channel = ibv_create_comp_channel(dev->verbs);
	if (!dev->channel) {
		ssa_log_err(0, "unable to create comp channel\n");
		goto err3;
	}

	for (i = 0; i < dev->port_cnt; i++)
		acm_open_port(&dev->port[i], dev, i + 1);

	DListInsertHead(&dev->entry, &device_list);

	ssa_log(SSA_LOG_VERBOSE, "%s opened\n", ibdev->name);
	return;

err3:
	ibv_dealloc_pd(dev->pd);
err2:
	free(dev);
err1:
	ibv_close_device(verbs);
}

static int acm_open_devices(void)
{
	struct ibv_device **ibdev;
	int dev_cnt;
	int i;

	ssa_log_func(SSA_LOG_VERBOSE);
	ibdev = ibv_get_device_list(&dev_cnt);
	if (!ibdev) {
		ssa_log_err(0, "unable to get device list ERROR %d (%s)\n",
			    errno, strerror(errno));
		return -1;
	}

	for (i = 0; i < dev_cnt; i++)
		acm_open_dev(ibdev[i]);

	ibv_free_device_list(ibdev);
	if (DListEmpty(&device_list)) {
		ssa_log_err(0, "no devices\n");
		return -1;
	}

	return 0;
}

static void acm_process_parent_set(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	/* First, handle set of parent in SSA */
	ssa_upstream_mad(svc, msg);

	/* Now, initiate rsocket client connection to parent */
	if (svc->state == SSA_STATE_HAVE_PARENT)
		ssa_ctrl_conn(svc->port->dev->ssa, svc);
}

static int acm_process_ssa_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_umad *umad;

	umad = &msg->data.umad;
	if (umad->umad.status) {
		ssa_log(SSA_LOG_DEFAULT,
			"SSA MAD method 0x%x (%s) attribute 0x%x (%s) received with status 0x%x\n",
			umad->packet.mad_hdr.method,
			ssa_method_str(umad->packet.mad_hdr.method),
			ntohs(umad->packet.mad_hdr.attr_id),
			ssa_attribute_str(umad->packet.mad_hdr.attr_id),
			umad->umad.status);
		return 0;
	}

	switch (umad->packet.mad_hdr.method) {
	case UMAD_METHOD_SET:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_INFO_REC) {
			acm_process_parent_set(svc, msg);
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

static void acm_process_sm_lid_change(struct ssa_svc *svc)
{
	acm_update_sa_dest(svc->port);
}

static int acm_process_dev_event(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n",
		svc->name, ibv_event_type_str(msg->data.event));
	switch (msg->data.event) {
	case IBV_EVENT_SM_CHANGE:
		acm_process_sm_lid_change(svc);
		break;
	default:
		break;
	};
	return 0;
}

static int acm_process_msg(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	switch(msg->hdr.type) {
	case SSA_CTRL_MAD:
		return acm_process_ssa_mad(svc, msg);
	case SSA_CONN_DONE:
ssa_log(SSA_LOG_DEFAULT, "client (upstream) connection completed on rsock %d\n", ((struct ssa_conn_done_msg *)msg)->conn->rsock);
		/* Request ssa_db ? */
		return 1;
	case SSA_DB_UPDATE:
ssa_log(SSA_LOG_DEFAULT, "SSA DB update ssa_db %p epoch 0x%" PRIx64 "\n", ((struct ssa_db_update_msg *)msg)->db_upd.db, ((struct ssa_db_update_msg *)msg)->db_upd.epoch);
		if (prdb_dump)
			ssa_db_save(prdb_dump_dir,
				    ((struct ssa_db_update_msg *)msg)->db_upd.db,
				    prdb_dump);
		if (acm_parse_ssa_db((struct ssa_db *)(((struct ssa_db_update_msg *)msg)->db_upd.db), svc))
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to preload ACM cache\n");
		return 1;
	case SSA_CTRL_DEV_EVENT:
		return acm_process_dev_event(svc, msg);
	case SSA_CONN_REQ:
	case SSA_CTRL_EXIT:
		break;
	default:
		ssa_log_warn(SSA_LOG_CTRL,
			     "ignoring unexpected message type %d\n",
			     msg->hdr.type);
		break;
	}
	return 0;
}

static void acm_set_options(void)
{
	FILE *f;
	char s[160];
	char opt[32], value[128];

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%32s%128s", opt, value) != 2)
			continue;

		if (!strcasecmp("log_file", opt))
			strcpy(log_file, value);
		else if (!strcasecmp("log_level", opt))
			ssa_set_log_level(atoi(value));
		else if (!strcasecmp("log_flush", opt))
			log_flush = atoi(value);
		else if (!strcasecmp("accum_log_file", opt))
			accum_log_file = atoi(value);
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("addr_prot", opt))
			addr_prot = acm_convert_addr_prot(value);
		else if (!strcasecmp("addr_timeout", opt))
			addr_timeout = atoi(value);
		else if (!strcasecmp("route_prot", opt))
			route_prot = acm_convert_route_prot(value);
		else if (!strcmp("route_timeout", opt))
			route_timeout = atoi(value);
		else if (!strcasecmp("loopback_prot", opt))
			loopback_prot = acm_convert_loopback_prot(value);
		else if (!strcasecmp("server_port", opt))
			server_port = (short) atoi(value);
		else if (!strcasecmp("prdb_port", opt))
			prdb_port = (short) atoi(value);
		else if (!strcasecmp("prdb_dump", opt))
			prdb_dump = atoi(value);
		else if (!strcasecmp("prdb_dump_dir", opt))
		        strcpy(prdb_dump_dir, value);
		else if (!strcasecmp("timeout", opt))
			timeout = atoi(value);
		else if (!strcasecmp("retries", opt))
			retries = atoi(value);
		else if (!strcasecmp("resolve_depth", opt))
			resolve_depth = atoi(value);
		else if (!strcasecmp("sa_depth", opt))
			sa_depth = atoi(value);
		else if (!strcasecmp("send_depth", opt))
			send_depth = atoi(value);
		else if (!strcasecmp("recv_depth", opt))
			recv_depth = atoi(value);
		else if (!strcasecmp("min_mtu", opt))
			min_mtu = acm_convert_mtu(atoi(value));
		else if (!strcasecmp("min_rate", opt))
			min_rate = acm_convert_rate(atoi(value));
		else if (!strcasecmp("route_preload", opt))
		        route_preload = acm_convert_route_preload(value);
		else if (!strcasecmp("route_data_file", opt))
		        strcpy(route_data_file, value);
		else if (!strcasecmp("route_data_dir", opt))
		        strcpy(route_data_dir, value);
		else if (!strcasecmp("addr_preload", opt))
			addr_preload = acm_convert_addr_preload(value);
		else if (!strcasecmp("addr_data_file", opt))
			strcpy(addr_data_file, value);
		else if (!strcasecmp("acm_mode", opt))
			acm_mode = acm_convert_mode(value);
		else if (!strcasecmp("acm_query_timeout", opt))
			acm_query_timeout = atol(value);
		else if (!strcasecmp("acm_query_retries", opt))
			acm_query_retries = atoi(value);
		else if (!strcasecmp("keepalive", opt))
			keepalive = atoi(value);
		else if (!strcasecmp("reconnect_max_count", opt))
			 reconnect_max_count = atoi(value);
		else if (!strcasecmp("reconnect_timeout", opt))
			 reconnect_timeout = atoi(value);
		else if (!strcasecmp("rejoin_timeout", opt))
			 rejoin_timeout = atoi(value);
	}

	fclose(f);
}

static void acm_log_options(void)
{
	ssa_log_options();
	ssa_log(SSA_LOG_DEFAULT, "config file %s\n", opts_file);
	ssa_log(SSA_LOG_DEFAULT, "lock file %s\n", lock_file);
	ssa_log(SSA_LOG_DEFAULT, "address resolution %d\n", addr_prot);
	ssa_log(SSA_LOG_DEFAULT, "address timeout %d\n", addr_timeout);
	ssa_log(SSA_LOG_DEFAULT, "route resolution %d\n", route_prot);
	ssa_log(SSA_LOG_DEFAULT, "route timeout %d\n", route_timeout);
	ssa_log(SSA_LOG_DEFAULT, "loopback resolution %d\n", loopback_prot);
	ssa_log(SSA_LOG_DEFAULT, "server port %d\n", server_port);
	ssa_log(SSA_LOG_DEFAULT, "prdb port %u\n", prdb_port);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump %d\n", prdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump dir %s\n", prdb_dump_dir);
	ssa_log(SSA_LOG_DEFAULT, "timeout %d ms\n", timeout);
	ssa_log(SSA_LOG_DEFAULT, "retries %d\n", retries);
	ssa_log(SSA_LOG_DEFAULT, "resolve depth %d\n", resolve_depth);
	ssa_log(SSA_LOG_DEFAULT, "sa depth %d\n", sa_depth);
	ssa_log(SSA_LOG_DEFAULT, "send depth %d\n", send_depth);
	ssa_log(SSA_LOG_DEFAULT, "receive depth %d\n", recv_depth);
	ssa_log(SSA_LOG_DEFAULT, "minimum mtu %d\n", min_mtu);
	ssa_log(SSA_LOG_DEFAULT, "minimum rate %d\n", min_rate);
	ssa_log(SSA_LOG_DEFAULT, "route preload %d\n", route_preload);
	ssa_log(SSA_LOG_DEFAULT, "route data file %s\n", route_data_file);
	ssa_log(SSA_LOG_DEFAULT, "route data directory %s\n", route_data_dir);
	ssa_log(SSA_LOG_DEFAULT, "address preload %d\n", addr_preload);
	ssa_log(SSA_LOG_DEFAULT, "address data file %s\n", addr_data_file);
	ssa_log(SSA_LOG_DEFAULT, "acm mode %d\n", acm_mode);
	ssa_log(SSA_LOG_DEFAULT, "acm_query_timeout %lu\n",acm_query_timeout);
	ssa_log(SSA_LOG_DEFAULT, "acm_query_retries %d\n", acm_query_retries);
	ssa_log(SSA_LOG_DEFAULT, "keepalive time %d\n", keepalive);
	if (reconnect_max_count < 0 || reconnect_timeout < 0) {
		ssa_log(SSA_LOG_DEFAULT, "reconnection to upstream node disabled\n");
	} else {
		ssa_log(SSA_LOG_DEFAULT, "max. number of reconnections to upstream node %d\n", reconnect_max_count);

		ssa_log(SSA_LOG_DEFAULT, "timeout between reconnections (in sec.) %d\n", reconnect_timeout);
	}
	if (rejoin_timeout < 0)
		ssa_log(SSA_LOG_DEFAULT, "rejoin to distribution tree after previous request failure disabled\n");
	else
		ssa_log(SSA_LOG_DEFAULT, "timeout before next join request (in sec.) %d\n", rejoin_timeout );
}

static int acm_init_svc(struct ssa_svc *svc)
{
	return 0;
}

static void acm_destroy_svc(struct ssa_svc *svc)
{
}

static void *acm_ctrl_handler(void *context)
{
	struct ssa_svc *svc;
	int ret;

	SET_THREAD_NAME(ctrl_thread, "CTRL");

	/* TODO: check for existing IB port in ssa device */
	if (ssa_dev_port(ssa_dev(&ssa, 0), 1)->link_layer != IBV_LINK_LAYER_INFINIBAND) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "%s:%d link layer %d is not IB\n",
			    ssa_dev(&ssa, 0)->name, 1,
			    ssa_dev_port(ssa_dev(&ssa, 0), 1)->link_layer);
		goto close;
	}

	svc = ssa_start_svc(ssa_dev_port(ssa_dev(&ssa, 0), 1), SSA_DB_PATH_DATA,
			    sizeof *svc, acm_process_msg, acm_init_svc,
			    acm_destroy_svc);
	if (!svc) {
		ssa_log_err(0, "starting service\n");
		goto close;
	}

	if (acm_mode == ACM_MODE_SSA)
		pthread_create(&query_thread, NULL, acm_issue_query, svc);

	ret = ssa_ctrl_run(&ssa);
	if (ret) {
		ssa_log_err(0, "processing control\n");
		goto close;
	}
close:
	ssa_log(SSA_LOG_VERBOSE, "closing SSA framework\n");
	if (acm_mode == ACM_MODE_SSA)
		pthread_join(query_thread, NULL);
	ssa_close_devices(&ssa);
	return context;
}

static void show_usage(char *program)
{
	printf("usage: %s\n", program);
	printf("   [-D]             - run as a daemon (default)\n");
	printf("   [-P]             - run as a standard process\n");
	printf("   [-A addr_file]   - address configuration file\n");
	printf("                      (default %s/%s)\n", RDMA_CONF_DIR, ACM_ADDR_FILE);
	printf("   [-O option_file] - option configuration file\n");
	printf("                      (default %s/%s)\n", RDMA_CONF_DIR, ACM_OPTS_FILE);
	printf("   [-v]             - print ibacm version\n");
}

int main(int argc, char **argv)
{
	int ret, i, op, daemon = 1;
	char msg[1024] = {};

	while ((op = getopt(argc, argv, "vDPA:O:")) != -1) {
		switch (op) {
		case 'D':
			/* option no longer required */
			break;
		case 'P':
			daemon = 0;
			break;
		case 'A':
			addr_file = optarg;
			break;
		case 'O':
			opts_file = optarg;
			break;
		case 'v':
			printf("ibacm version %s\n", IB_SSA_VERSION);
			exit(0);
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}

	if (daemon)
		ssa_daemonize();

	srand(time(NULL));

	acm_set_options();

	ret = ssa_open_lock_file(lock_file, msg, sizeof msg);
	if (ret) {
		if (!daemon)
			fprintf(stderr, "%s\n", msg);
		openlog("ibacm", LOG_PERROR | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "%s", msg);
		closelog();
		return -1;
	}

	ssa_open_log(log_file);
	ssa_log(SSA_LOG_DEFAULT, "Assistant to the InfiniBand Communication Manager\n");
	acm_log_options();

	ssa_set_ssa_signal_handler();

	ret = ssa_init(&ssa, SSA_NODE_CONSUMER, sizeof(struct ssa_device),
		       sizeof(struct ssa_port));
	if (ret) {
		ssa_close_log();
		ssa_close_lock_file();
		return ret;
	}

	atomic_init(&tid);
	atomic_init(&wait_cnt);
	DListInit(&device_list);
	DListInit(&timeout_list);
	event_init(&timeout_event);
	for (i = 0; i < ACM_MAX_COUNTER; i++)
		atomic_init(&counter[i]);

	if (acm_mode == ACM_MODE_ACM) {
		if (acm_open_devices()) {
			ssa_log_err(0, "unable to open any ACM device\n");
			ssa_close_lock_file();
			return -1;
		}
	} else { /* ACM_MODE_SSA */
		ssa_log(SSA_LOG_VERBOSE, "starting SSA framework\n");
		if (ssa_open_devices(&ssa)) {
			ssa_log_err(0, "unable to open any SSA device\n");
			ssa_close_lock_file();
			return -1;
		}
		pthread_create(&ctrl_thread, NULL, acm_ctrl_handler, NULL);
	}

	acm_activate_devices();
	ssa_log(SSA_LOG_VERBOSE, "starting timeout/retry thread\n");
	pthread_create(&retry_thread, NULL, acm_retry_handler, NULL);

	ssa_log(SSA_LOG_VERBOSE, "starting server\n");
	acm_server();

	ssa_log(SSA_LOG_DEFAULT, "shutting down\n");
	pthread_join(ctrl_thread, NULL);
	ssa_cleanup(&ssa);
	ssa_close_log();
	ssa_close_lock_file();
	free(lid2guid_cached);
	return 0;
}
