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
#include <infiniband/acm.h>
#include <infiniband/umad.h>
#include <infiniband/verbs.h>
#include <dlist.h>
#include <search.h>

DLIST_ENTRY dev_list;

static atomic_t tid;

static FILE *flog;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

//PER_THREAD char log_data[SSA_MAX_ADDRESS];
//static atomic_t counter[SSA_MAX_COUNTER];

int log_level = SSA_LOG_DEFAULT;
char lock_file[128];
//static short server_port = 6125;

int ssa_open_log(char *log_file)
{
	if (!strcasecmp(log_file, "stdout")) {
		flog = stdout;
		return 0;
	}

	if (!strcasecmp(log_file, "stderr")) {
		flog = stderr;
		return 0;
	}

	if ((flog = fopen(log_file, "w")))
		return 0;

	f = stderr;
	return -1;
}

void ssa_close_log()
{
	fclose(flog);
}

void ssa_write_log(int level, const char *format, ...)
{
	va_list args;
	struct timeval tv;

	if (!(level & log_level))
		return;

	gettimeofday(&tv, NULL);
	va_start(args, format);
	pthread_mutex_lock(&log_lock);
	fprintf(flog, "%u.%03u: ", (unsigned) tv.tv_sec, (unsigned) (tv.tv_usec / 1000));
	vfprintf(flog, format, args);
	fflush(flog);
	pthread_mutex_unlock(&log_lock);
	va_end(args);
}


/*
static void
ssa_format_name(int level, char *name, size_t name_size,
		uint8_t addr_type, uint8_t *addr, size_t addr_size)
{
	struct ibv_path_record *path;

	if (level > log_level)
		return;

	switch (addr_type) {
	case SSA_EP_INFO_NAME:
		memcpy(name, addr, addr_size);
		break;
	case SSA_EP_INFO_ADDRESS_IP:
		inet_ntop(AF_INET, addr, name, name_size);
		break;
	case SSA_EP_INFO_ADDRESS_IP6:
	case SSA_ADDRESS_GID:
		inet_ntop(AF_INET6, addr, name, name_size);
		break;
	case SSA_EP_INFO_PATH:
		path = (struct ibv_path_record *) addr;
		if (path->dlid) {
			snprintf(name, name_size, "SLID(%u) DLID(%u)",
				ntohs(path->slid), ntohs(path->dlid));
		} else {
			ssa_format_name(level, name, name_size, SSA_ADDRESS_GID,
					path->dgid.raw, sizeof path->dgid);
		}
		break;
	case SSA_ADDRESS_LID:
		snprintf(name, name_size, "LID(%u)", ntohs(*((uint16_t *) addr)));
		break;
	default:
		strcpy(name, "Unknown");
		break;
	}
}
*/

/*
 * Not sure we need to reference count the SA dest or if the AH is needed
struct ssa_dest * ssa_acquire_sa_dest(struct ssa_port *port)
{
	struct ssa_dest *dest;

	pthread_mutex_lock(&port->lock);
	if (port->state == IBV_PORT_ACTIVE) {
		dest = &port->sa_dest;
		atomic_inc(&port->sa_dest.refcnt);
	} else {
		dest = NULL;
	}
	pthread_mutex_unlock(&port->lock);
	return dest;
}

void ssa_release_sa_dest(struct ssa_dest *dest)
{
	atomic_dec(&dest->refcnt);
}
*/

/*
uint8_t ssa_gid_index(struct ssa_port *port, union ibv_gid *gid)
{
	union ibv_gid cmp_gid;
	uint8_t i;

	for (i = 0; i < port->gid_cnt; i++) {
		ibv_query_gid(port->dev->verbs, port->port_num, i, &cmp_gid);
		if (!memcmp(&cmp_gid, gid, sizeof cmp_gid))
			break;
	}
	return i;
}
*/

/*
static void ssa_process_join_resp(struct ssa_ep *ep, struct ib_user_mad *umad)
{
	struct ssa_dest *dest;
	struct ib_mc_member_rec *mc_rec;
	struct ib_sa_mad *mad;
	int index, ret;

	mad = (struct ib_sa_mad *) umad->data;
	//ssa_log(1, "response status: 0x%x, mad status: 0x%x\n",
	//	umad->status, mad->status);
	if (umad->status) {
		//ssa_log(0, "ERROR - send join failed 0x%x\n", umad->status);
		return;
	}
	if (mad->status) {
		//ssa_log(0, "ERROR - join response status 0x%x\n", mad->status);
		return;
	}

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	pthread_mutex_lock(&ep->lock);
	index = ssa_mc_index(ep, &mc_rec->mgid);
	if (index < 0) {
		//ssa_log(0, "ERROR - MGID in join response not found\n");
		goto out;
	}

	dest = &ep->mc_dest[index];
	dest->remote_qpn = IB_MC_QPN;
	dest->mgid = mc_rec->mgid;
	ssa_record_mc_av(ep->port, mc_rec, dest);

	if (index == 0) {
		dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
		if (!dest->ah) {
			//ssa_log(0, "ERROR - unable to create ah\n");
			goto out;
		}
		ret = ibv_attach_mcast(ep->qp, &mc_rec->mgid, mc_rec->mlid);
		if (ret) {
			//ssa_log(0, "ERROR - unable to attach QP to multicast group\n");
			goto out;
		}
	}

	atomic_set(&dest->refcnt, 1);
	dest->state = SSA_READY;
	//ssa_log(1, "join successful\n");
out:
	pthread_mutex_unlock(&ep->lock);
}
*/

/*
 * This is setup for multicast - not SSA
static void ssa_init_join(struct ib_sa_mad *mad, union ibv_gid *port_gid,
	uint16_t pkey, uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ib_mc_member_rec *mc_rec;

	//ssa_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
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
	ssa_format_mgid(&mc_rec->mgid, pkey, tos, rate, mtu);
	mc_rec->port_gid = *port_gid;
	mc_rec->qkey = SSA_QKEY;
	mc_rec->mtu = 0x80 | mtu;
	mc_rec->tclass = tclass;
	mc_rec->pkey = htons(pkey);
	mc_rec->rate = 0x80 | rate;
	mc_rec->sl_flow_hop = htonl(((uint32_t) sl) << 28);
	mc_rec->scope_state = 0x51;
}
 */

/*
 * Convert from MC join to SSA
static void ssa_join_group(struct ssa_ep *ep, union ibv_gid *port_gid,
	uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ssa_port *port;
	struct ib_sa_mad *mad;
	struct ib_user_mad *umad;
	struct ib_mc_member_rec *mc_rec;
	int ret, len;

	//ssa_log(2, "\n");
	len = sizeof(*umad) + sizeof(*mad);
	umad = (struct ib_user_mad *) calloc(1, len);
	if (!umad) {
		//ssa_log(0, "ERROR - unable to allocate MAD for join\n");
		return;
	}

	port = ep->port;
	umad->addr.qpn = htonl(port->sa_dest.remote_qpn);
	umad->addr.qkey = htonl(SSA_QKEY);
	umad->addr.pkey_index = ep->pkey_index;
	umad->addr.lid = htons(port->sa_dest.av.dlid);
	umad->addr.sl = port->sa_dest.av.sl;
	umad->addr.path_bits = port->sa_dest.av.src_path_bits;

	//ssa_log(0, "%s %d pkey 0x%x, sl 0x%x, rate 0x%x, mtu 0x%x\n",
	//	ep->port->dev->verbs->device->name, ep->port->port_num,
	//	ep->pkey, sl, rate, mtu);
	mad = (struct ib_sa_mad *) umad->data;
	ssa_init_join(mad, port_gid, ep->pkey, tos, tclass, sl, rate, mtu);
	mc_rec = (struct ib_mc_member_rec *) mad->data;
	ssa_set_dest_addr(&ep->mc_dest[ep->mc_cnt++], SSA_ADDRESS_GID,
		mc_rec->mgid.raw, sizeof(mc_rec->mgid));

	ret = umad_send(port->mad_portid, port->mad_agentid, (void *) umad,
		sizeof(*mad), timeout, retries);
	if (ret) {
		//ssa_log(0, "ERROR - failed to send multicast join request %d\n", ret);
		goto out;
	}

	//ssa_log(1, "waiting for response from SA to join request\n");
	ret = umad_recv(port->mad_portid, (void *) umad, &len, -1);
	if (ret < 0) {
		//ssa_log(0, "ERROR - recv error for multicast join response %d\n", ret);
		goto out;
	}

	ssa_process_join_resp(ep, umad);
out:
	free(umad);
}
 */

static void ssa_port_join(struct ssa_port *port)
{
	struct ssa_device *dev;
//	struct ssa_ep *ep;
	union ibv_gid port_gid;
	DLIST_ENTRY *ep_entry;
	int ret;

	dev = port->dev;
	//ssa_log(1, "device %s port %d\n", dev->verbs->device->name,
	//	port->port_num);

	ret = ibv_query_gid(dev->verbs, port->port_num, 0, &port_gid);
	if (ret) {
		//ssa_log(0, "ERROR - ibv_query_gid %d device %s port %d\n",
		//	ret, dev->verbs->device->name, port->port_num);
		return;
	}

	// TODO: join all services/endpoints
	/*
	for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
		 ep_entry = ep_entry->Next) {

		ep = container_of(ep_entry, struct ssa_ep, entry);
		ep->mc_cnt = 0;
		ssa_join_group(ep, &port_gid, 0, 0, 0, min_rate, min_mtu);

		if ((ep->state = ep->mc_dest[0].state) != SSA_READY)
			continue;

		if ((route_prot == SSA_ROUTE_PROT_ACM) &&
		    (port->rate != min_rate || port->mtu != min_mtu))
			ssa_join_group(ep, &port_gid, 0, 0, 0, port->rate, port->mtu);
	}
	*/
	//ssa_log(1, "joins for device %s port %d complete\n", dev->verbs->device->name,
	//	port->port_num);
}

void ssa_init_server(void)
{
	FILE *f;
	int i;

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		pthread_mutex_init(&client[i].lock, NULL);
		client[i].index = i;
		client[i].sock = -1;
		atomic_init(&client[i].refcnt);
	}

	// TODO: change port file
	//if (!(f = fopen("/var/run/ibacm.port", "w"))) {
		//ssa_log(0, "notice - cannot publish ibacm port number\n");
	//	return;
	//}
	//fprintf(f, "%hu\n", server_port);
	//fclose(f);
}

int ssa_listen(void)
{
	struct sockaddr_in addr;
	int ret;

	//ssa_log(2, "\n");
	listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_socket == -1) {
		//ssa_log(0, "ERROR - unable to allocate listen socket\n");
		return errno;
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ret = bind(listen_socket, (struct sockaddr *) &addr, sizeof addr);
	if (ret == -1) {
		//ssa_log(0, "ERROR - unable to bind listen socket\n");
		return errno;
	}
	
	ret = listen(listen_socket, 0);
	if (ret == -1) {
		//ssa_log(0, "ERROR - unable to start listen\n");
		return errno;
	}

	//ssa_log(2, "listen active\n");
	return 0;
}

void ssa_disconnect_client(struct ssa_client *client)
{
	pthread_mutex_lock(&client->lock);
	shutdown(client->sock, SHUT_RDWR);
	close(client->sock);
	client->sock = -1;
	pthread_mutex_unlock(&client->lock);
	(void) atomic_dec(&client->refcnt);
}

static void ssa_svr_accept(void)
{
	int s, i;

	//ssa_log(2, "\n");
	s = accept(listen_socket, NULL, NULL);
	if (s == -1) {
		//ssa_log(0, "ERROR - failed to accept connection\n");
		return;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		if (!atomic_get(&client[i].refcnt))
			break;
	}

	if (i == FD_SETSIZE - 1) {
		//ssa_log(0, "ERROR - all connections busy - rejecting\n");
		close(s);
		return;
	}

	client[i].sock = s;
	atomic_set(&client[i].refcnt, 1);
	//ssa_log(2, "assigned client %d\n", i);
}

/* Caller must hold dest lock */
static uint8_t
ssa_svr_queue_req(struct ssa_dest *dest, struct ssa_client *client,
	struct ssa_msg *msg)
{
	struct ssa_request *req;

	//ssa_log(2, "client %d\n", client->index);
	req = ssa_alloc_req(client, msg);
	if (!req) {
		return SSA_STATUS_ENOMEM;
	}

	DListInsertTail(&req->entry, &dest->req_queue);
	return SSA_STATUS_SUCCESS;
}

/*
static int ssa_svr_perf_query(struct ssa_client *client, struct ssa_msg *msg)
{
	int ret, i;
	uint16_t len;

	//ssa_log(2, "client %d\n", client->index);
	msg->hdr.opcode |= SSA_OP_ACK;
	msg->hdr.status = SSA_STATUS_SUCCESS;
	msg->hdr.data[0] = SSA_MAX_COUNTER;
	msg->hdr.data[1] = 0;
	msg->hdr.data[2] = 0;
	len = SSA_MSG_HDR_LENGTH + (SSA_MAX_COUNTER * sizeof(uint64_t));
	msg->hdr.length = htons(len);

	for (i = 0; i < SSA_MAX_COUNTER; i++)
		msg->perf_data[i] = htonll((uint64_t) atomic_get(&counter[i]));

	ret = send(client->sock, (char *) msg, len, 0);
	if (ret != len)
		//ssa_log(0, "ERROR - failed to send response\n");
	else
		ret = 0;

	return ret;
}
*/

static void ssa_svr_receive(struct ssa_client *client)
{
	struct ssa_msg msg;
	int ret;

	//ssa_log(2, "client %d\n", client->index);
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
//	if (ret <= 0 || ret != ssa_msg_length(&msg)) {
		//ssa_log(2, "client disconnected\n");
//		ret = SSA_STATUS_ENOTCONN;
//		goto out;
//	}

//	if (msg.hdr.version != SSA_VERSION) {
		//ssa_log(0, "ERROR - unsupported version %d\n", msg.hdr.version);
//		goto out;
//	}

//	switch (msg.hdr.opcode & SSA_OP_MASK) {
//	case SSA_OP_PERF_QUERY:
//		ret = ssa_svr_perf_query(client, &msg);
//		break;
//	default:
		//ssa_log(0, "ERROR - unknown opcode 0x%x\n", msg.hdr.opcode);
//		break;
//	}

out:
	if (ret)
		ssa_disconnect_client(client);
}

static void ssa_server(void)
{
	fd_set readfds;
	int i, n, ret;

	//ssa_log(0, "started\n");
	ssa_init_server();
	ret = ssa_listen();
	if (ret) {
		//ssa_log(0, "ERROR - server listen failed\n");
		return;
	}

	while (1) {
		n = (int) listen_socket;
		FD_ZERO(&readfds);
		FD_SET(listen_socket, &readfds);

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client[i].sock != -1) {
				FD_SET(client[i].sock, &readfds);
				n = max(n, (int) client[i].sock);
			}
		}

		ret = select(n + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			//ssa_log(0, "ERROR - server select error\n");
			continue;
		}

		if (FD_ISSET(listen_socket, &readfds))
			ssa_svr_accept();

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client[i].sock != -1 &&
				FD_ISSET(client[i].sock, &readfds)) {
				//ssa_log(2, "receiving from client %d\n", i);
				ssa_svr_receive(&client[i]);
			}
		}
	}
}

static void ssa_port_up(struct ssa_port *port)
{
	struct ibv_port_attr attr;
	union ibv_gid gid;
	uint16_t pkey;
	int i, ret;

	//ssa_log(1, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (ret) {
		//ssa_log(0, "ERROR - unable to get port state\n");
		return;
	}
	if (attr.state != IBV_PORT_ACTIVE) {
		//ssa_log(1, "port not active\n");
		return;
	}

//	port->mtu = attr.active_mtu;
//	port->rate = ssa_get_rate(attr.active_width, attr.active_speed);
	if (attr.subnet_timeout >= 8)
		port->subnet_timeout = 1 << (attr.subnet_timeout - 8);
	for (port->gid_cnt = 0;; port->gid_cnt++) {
		ret = ibv_query_gid(port->dev->verbs, port->port_num, port->gid_cnt, &gid);
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
//	ssa_set_dest_addr(&port->sa_dest, SSA_ADDRESS_LID,
//		(uint8_t *) &attr.sm_lid, sizeof(attr.sm_lid));

	port->sa_dest.ah = ibv_create_ah(port->dev->pd, &port->sa_dest.av);
	if (!port->sa_dest.ah)
		return;

	atomic_set(&port->sa_dest.refcnt, 1);
//	for (i = 0; i < port->pkey_cnt; i++)
//		 ssa_ep_up(port, (uint16_t) i);

	ssa_port_join(port);
	port->state = IBV_PORT_ACTIVE;
	//ssa_log(1, "%s %d is up\n", port->dev->verbs->device->name, port->port_num);
}

static void ssa_port_down(struct ssa_port *port)
{
	struct ibv_port_attr attr;
	int ret;

	//ssa_log(1, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (!ret && attr.state == IBV_PORT_ACTIVE) {
		//ssa_log(1, "port active\n");
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
	//ssa_log(1, "%s %d is down\n", port->dev->verbs->device->name, port->port_num);
}

/*
 * There is one event handler thread per device.  This is the only thread that
 * modifies the port state or a port endpoint list.  Other threads which access
 * those must synchronize against changes accordingly, but this thread only
 * needs to lock when making modifications.
 */
static void ssa_event_handler(void *context)
{
	struct ssa_device *dev = (struct ssa_device *) context;
	struct ibv_async_event event;
	int i, ret;

	//ssa_log(1, "started\n");
	for (i = 0; i < dev->port_cnt; i++) {
		ssa_port_up(&dev->port[i]);
	}

	for (;;) {
		ret = ibv_get_async_event(dev->verbs, &event);
		if (ret)
			continue;

		//ssa_log(2, "processing async event %s\n",
			ibv_event_type_str(event.event_type));
		i = event.element.port_num - 1;
		switch (event.event_type) {
		case IBV_EVENT_PORT_ACTIVE:
			if (dev->port[i].state != IBV_PORT_ACTIVE)
				ssa_port_up(&dev->port[i]);
			break;
		case IBV_EVENT_PORT_ERR:
			if (dev->port[i].state == IBV_PORT_ACTIVE)
				ssa_port_down(&dev->port[i]);
			break;
		default:
			break;
		}

		ibv_ack_async_event(&event);
	}
}

void ssa_activate_devices()
{
	struct ssa_device *dev;
	DLIST_ENTRY *dev_entry;

	//ssa_log(1, "\n");
	for (dev_entry = dev_list.Next; dev_entry != &dev_list;
		dev_entry = dev_entry->Next) {

		dev = container_of(dev_entry, struct ssa_device, entry);
		beginthread(ssa_event_handler, dev);
//		beginthread(ssa_comp_handler, dev);
	}
}

static void ssa_open_port(struct ssa_port *port, struct ssa_device *dev, uint8_t port_num)
{
	//ssa_log(1, "%s %d\n", dev->verbs->device->name, port_num);
	port->dev = dev;
	port->port_num = port_num;
	pthread_mutex_init(&port->lock, NULL);
	DListInit(&port->ep_list);
//	ssa_init_dest(&port->sa_dest, SSA_ADDRESS_LID, NULL, 0);

	port->mad_portid = umad_open_port(dev->verbs->device->name, port->port_num);
	if (port->mad_portid < 0) {
		//ssa_log(0, "ERROR - unable to open MAD port\n");
		return;
	}

	port->mad_agentid = umad_register(port->mad_portid,
		IB_MGMT_CLASS_SA, 1, 1, NULL);
	if (port->mad_agentid < 0) {
		//ssa_log(0, "ERROR - unable to register MAD client\n");
		goto err;
	}

	port->state = IBV_PORT_DOWN;
	return;
err:
	umad_close_port(port->mad_portid);
}

static void ssa_open_dev(struct ibv_device *ibdev)
{
	struct ssa_device *dev;
	struct ibv_device_attr attr;
	struct ibv_context *verbs;
	size_t size;
	int i, ret;

	//ssa_log(1, "%s\n", ibdev->name);
	verbs = ibv_open_device(ibdev);
	if (verbs == NULL) {
		//ssa_log(0, "ERROR - opening device %s\n", ibdev->name);
		return;
	}

	ret = ibv_query_device(verbs, &attr);
	if (ret) {
		//ssa_log(0, "ERROR - ibv_query_device (%s) %d\n", ret, ibdev->name);
		goto err1;
	}

	size = sizeof(*dev) + sizeof(struct ssa_port) * attr.phys_port_cnt;
	dev = (struct ssa_device *) calloc(1, size);
	if (!dev)
		goto err1;

	dev->verbs = verbs;
	dev->guid = ibv_get_device_guid(ibdev);
	dev->port_cnt = attr.phys_port_cnt;

	dev->pd = ibv_alloc_pd(dev->verbs);
	if (!dev->pd) {
		//ssa_log(0, "ERROR - unable to allocate PD\n");
		goto err2;
	}

	dev->channel = ibv_create_comp_channel(dev->verbs);
	if (!dev->channel) {
		//ssa_log(0, "ERROR - unable to create comp channel\n");
		goto err3;
	}

	for (i = 0; i < dev->port_cnt; i++)
		ssa_open_port(&dev->port[i], dev, i + 1);

	DListInsertHead(&dev->entry, &dev_list);

	//ssa_log(1, "%s opened\n", ibdev->name);
	return;

err3:
	ibv_dealloc_pd(dev->pd);
err2:
	free(dev);
err1:
	ibv_close_device(verbs);
}

int ssa_open_devices(void)
{
	struct ibv_device **ibdev;
	int dev_cnt;
	int i;

	//ssa_log(1, "\n");
	ibdev = ibv_get_device_list(&dev_cnt);
	if (!ibdev) {
		//ssa_log(0, "ERROR - unable to get device list\n");
		return -1;
	}

	for (i = 0; i < dev_cnt; i++)
		ssa_open_dev(ibdev[i]);

	ibv_free_device_list(ibdev);
	if (DListEmpty(&dev_list)) {
		//ssa_log(0, "ERROR - no devices\n");
		return -1;
	}

	return 0;
}

int ssa_open_lock_file(char *lock_file)
{
	int lock_fd;
	char pid[16];

	lock_fd = open(lock_file, O_RDWR | O_CREAT, 0640);
	if (lock_fd < 0)
		return lock_fd;

	if (lockf(lock_fd, F_TLOCK, 0)) {
		close(lock_fd);
		return -1;
	}

	snprintf(pid, sizeof pid, "%d\n", getpid());
	write(lock_fd, pid, strlen(pid));
	return 0;
}

void ssa_daemonize(void)
{
	pid_t pid, sid;

	pid = fork();
	if (pid)
		exit(pid < 0);

	sid = setsid();
	if (sid < 0)
		exit(1);

	if (chdir("/"))
		exit(1);

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}
