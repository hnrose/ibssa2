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
#include <rdma/rsocket.h>
#include <syslog.h>
#include <netinet/tcp.h>
#include <infiniband/umad.h>
#include <infiniband/umad_str.h>
#include <infiniband/verbs.h>
#include <infiniband/ssa_mad.h>
#include <infiniband/ib.h>
#include <dlist.h>
#include <search.h>
#include <common.h>
#include <ssa_ctrl.h>


#define DEFAULT_TIMEOUT 1000
#define MAX_TIMEOUT	120 * DEFAULT_TIMEOUT

static FILE *flog;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

__thread char log_data[128];
//static atomic_t counter[SSA_MAX_COUNTER];

static const char * month_str[] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

static int log_level = SSA_LOG_DEFAULT;
//static short server_port = 6125;

void ssa_set_log_level(int level)
{
	log_level = level;
}

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

	syslog(LOG_WARNING, "Failed to open log file %s\n", log_file);
	flog = stderr;
	return -1;
}

void ssa_close_log()
{
	fclose(flog);
}

void ssa_write_log(int level, const char *format, ...)
{
	va_list args;
	pid_t tid;
	struct timeval tv;
	time_t tim;
	struct tm result;

	if (!(level & log_level))
		return;

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec;
	localtime_r(&tim, &result);
	tid = pthread_self();
	va_start(args, format);
	pthread_mutex_lock(&log_lock);
	fprintf(flog, "%s %02d %02d:%02d:%02d %06d [%04X]: ",
		(result.tm_mon < 12 ? month_str[result.tm_mon] : "???"),
		result.tm_mday, result.tm_hour, result.tm_min,
		result.tm_sec, (unsigned int)tv.tv_usec, tid);
	vfprintf(flog, format, args);
	fflush(flog);
	pthread_mutex_unlock(&log_lock);
	va_end(args);
}

void ssa_sprint_addr(int level, char *str, size_t str_size,
		     enum ssa_addr_type addr_type, uint8_t *addr, size_t addr_size)
{
	struct ibv_path_record *path;

	if (!(level & log_level))
		return;

	switch (addr_type) {
	case SSA_ADDR_NAME:
		memcpy(str, addr, addr_size);
		break;
	case SSA_ADDR_IP:
		inet_ntop(AF_INET, addr, str, str_size);
		break;
	case SSA_ADDR_IP6:
	case SSA_ADDR_GID:
		inet_ntop(AF_INET6, addr, str, str_size);
		break;
	case SSA_ADDR_PATH:
		path = (struct ibv_path_record *) addr;
		if (path->dlid) {
			snprintf(str, str_size, "SLID(%u) DLID(%u)",
				ntohs(path->slid), ntohs(path->dlid));
		} else {
			ssa_sprint_addr(level, str, str_size, SSA_ADDR_GID,
					path->dgid.raw, sizeof path->dgid);
		}
		break;
	case SSA_ADDR_LID:
		snprintf(str, str_size, "LID(%u)", ntohs(*((uint16_t *) addr)));
		break;
	default:
		strcpy(str, "Unknown");
		break;
	}
}

void ssa_log_options()
{
	ssa_log(SSA_LOG_DEFAULT, "log level 0x%x\n", log_level);
}

const char *ssa_method_str(uint8_t method)
{
	return umad_method_str(UMAD_CLASS_SUBN_ADM, method);
}

const char *ssa_attribute_str(be16_t attr_id)
{
	switch  (ntohs(attr_id)) {
	case SSA_ATTR_MEMBER_REC:
		return "MemberRecord";
	case SSA_ATTR_INFO_REC:
		return "InfoRecord";
	default:
		return umad_attribute_str(UMAD_CLASS_SUBN_ADM, attr_id);
	}
}

const char *ssa_mad_status_str(be16_t status)
{
	return umad_sa_mad_status_str(status);
}

int ssa_compare_gid(const void *gid1, const void *gid2)
{
	return memcmp(gid1, gid2, 16);
}

static be64_t ssa_svc_tid(struct ssa_svc *svc)
{
	return htonll((((uint64_t) svc->index) << 16) | svc->tid++);
}

static struct ssa_svc *ssa_svc_from_tid(struct ssa_port *port, be64_t tid)
{
	uint16_t index = (uint16_t) (ntohll(tid) >> 16);
	return (index < port->svc_cnt) ? port->svc[index] : NULL;
}

static struct ssa_svc *ssa_find_svc(struct ssa_port *port, uint64_t database_id)
{
	int i;
	for (i = 0; i < port->svc_cnt; i++) {
		if (port->svc[i] && port->svc[i]->database_id == database_id)
			return port->svc[i];
	}
	return NULL;
}

void ssa_init_mad_hdr(struct ssa_svc *svc, struct umad_hdr *hdr,
		      uint8_t method, uint16_t attr_id)
{
	hdr->base_version = UMAD_BASE_VERSION;
	hdr->mgmt_class = SSA_CLASS;
	hdr->class_version = SSA_CLASS_VERSION;
	hdr->method = method;
	hdr->tid = ssa_svc_tid(svc);
	hdr->attr_id = htons(attr_id);
}

static void sa_init_mad_hdr(struct ssa_svc *svc, struct umad_hdr *hdr,
			    uint8_t method, uint16_t attr_id)
{
	hdr->base_version = UMAD_BASE_VERSION;
	hdr->mgmt_class = UMAD_CLASS_SUBN_ADM;
	hdr->class_version = UMAD_SA_CLASS_VERSION;
	hdr->method = method;
	hdr->tid = ssa_svc_tid(svc);
	hdr->attr_id = htons(attr_id);
}

static void ssa_init_join(struct ssa_svc *svc, struct ssa_mad_packet *mad)
{
	struct ssa_member_record *rec;

	ssa_init_mad_hdr(svc, &mad->mad_hdr, UMAD_METHOD_SET, SSA_ATTR_MEMBER_REC);
	mad->ssa_key = 0;	/* TODO: set for real */

	rec = (struct ssa_member_record *) &mad->data;
	memcpy(rec->port_gid, svc->port->gid.raw, 16);
	rec->database_id = htonll(svc->database_id);
	rec->node_type = svc->port->dev->ssa->node_type;
}

static void sa_init_path_query(struct ssa_svc *svc, struct umad_sa_packet *mad,
			       union ibv_gid *dgid, union ibv_gid *sgid)
{
	struct ibv_path_record *path;

	sa_init_mad_hdr(svc, &mad->mad_hdr, UMAD_METHOD_GET,
			UMAD_SA_ATTR_PATH_REC);
	mad->comp_mask = htonll(((uint64_t)1) << 2 |	/* DGID */
				((uint64_t)1) << 3 |	/* SGID */
				((uint64_t)1) << 11 |	/* Reversible */
				((uint64_t)1) << 13);	/* P_Key */

	path = (struct ibv_path_record *) &mad->data;
	memcpy(path->dgid.raw, dgid, 16);
	memcpy(path->sgid.raw, sgid, 16);
	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
	path->pkey = 0xFFFF;	/* default partition */
}

static void ssa_svc_join(struct ssa_svc *svc)
{
	struct ssa_umad umad;
	int ret;

	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, svc->port->gid.raw, sizeof svc->port->gid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", svc->name, log_data);
	memset(&umad, 0, sizeof umad);
	umad_set_addr(&umad.umad, svc->port->sm_lid, 1, svc->port->sm_sl, UMAD_QKEY);
	ssa_init_join(svc, &umad.packet);
	svc->state = SSA_STATE_JOINING;

	ret = umad_send(svc->port->mad_portid, svc->port->mad_agentid,
			(void *) &umad, sizeof umad.packet, svc->timeout, 0);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - failed to send join request\n");
		svc->state = SSA_STATE_IDLE;
	}
}

static int ssa_svc_modify(struct ssa_svc *svc, int fd_slot, int events)
{
	struct ssa_class *ssa;

	ssa = svc->port->dev->ssa;
	if (ssa->fds[fd_slot].fd == svc->rsock) {
		ssa->fds[fd_slot].events = events;
		return fd_slot;
	}
	return -1;
}

static int ssa_svc_insert(struct ssa_svc *svc, int events)
{
	struct ssa_class *ssa;
	int i;

	ssa = svc->port->dev->ssa;
	for (i = ssa->sfds_start; i < ssa->sfds_start + ssa->nsfds; i++) {
		if ((ssa->fds[i].fd == -1) && (ssa->fds_obj[i].svc == NULL)) {
			ssa->fds[i].fd = svc->rsock;
			ssa->fds[i].events = events;
			ssa->fds_obj[i].svc = svc;
			ssa->nfds++;
			return i;
		}
	}
	return -1;
}

static void ssa_svc_listen(struct ssa_svc *svc)
{
	int sport = 7470;
	struct sockaddr_ib src_addr;
	int ret, val;

	/* Only listening on rsocket when server (not consumer - ACM) */
	if (svc->port->dev->ssa->node_type == SSA_NODE_CONSUMER)
		return;

	if (svc->rsock >= 0)
		return;

	ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "%s\n", svc->port->name);

	svc->rsock = rsocket(AF_IB, SOCK_STREAM, 0);
	if (svc->rsock < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsocket ERROR %d (%s)\n",
			errno, strerror(errno));
		return;
	}

	val = 1;
	ret = rsetsockopt(svc->rsock, SOL_SOCKET, SO_REUSEADDR,
			  &val, sizeof val);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsetsockopt SO_REUSEADDR ERROR %d (%s)\n",
			errno, strerror(errno));
		goto err;
	}

	ret = rsetsockopt(svc->rsock, IPPROTO_TCP, TCP_NODELAY,
			  (void *) &val, sizeof(val));
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsetsockopt TCP_NODELAY ERROR %d (%s)\n",
			errno, strerror(errno));
		goto err;
	}
	ret = rfcntl(svc->rsock, F_SETFL, O_NONBLOCK);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rfcntl ERROR %d (%s)\n",
			errno, strerror(errno));
		goto err;
	}

	src_addr.sib_family = AF_IB;
	src_addr.sib_pkey = 0xFFFF;
	src_addr.sib_flowinfo = 0;
	src_addr.sib_sid = htonll(((uint64_t) RDMA_PS_TCP << 16) + sport);
	src_addr.sib_sid_mask = htonll(RDMA_IB_IP_PS_MASK | RDMA_IB_IP_PORT_MASK);
	src_addr.sib_scope_id = 0;
	memcpy(&src_addr.sib_addr, &svc->port->gid, 16);

	ret = rbind(svc->rsock, (const struct sockaddr *) &src_addr, sizeof(src_addr));
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rbind ERROR %d (%s)\n",
			errno, strerror(errno));
		goto err;
	}
	ret = rlisten(svc->rsock, 1);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rlisten ERROR %d (%s)\n",
			errno, strerror(errno));
		goto err;
	}

	svc->slot = ssa_svc_insert(svc, POLLIN);
	if (svc->slot >= 0)
		return;

	ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "ERROR - no service slot available\n");

err:
	rclose(svc->rsock);
	svc->rsock = -1;
}

void ssa_svc_query_path(struct ssa_svc *svc, union ibv_gid *dgid,
			union ibv_gid *sgid)
{
	struct sa_umad umad;
	int ret;

	memset(&umad, 0, sizeof umad);
	umad_set_addr(&umad.umad, svc->port->sm_lid, 1, svc->port->sm_sl, UMAD_QKEY);
	sa_init_path_query(svc, &umad.packet, dgid, sgid);

	ret = umad_send(svc->port->mad_portid, svc->port->mad_agentid,
			(void *) &umad, sizeof umad.packet, svc->timeout, 0);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - failed to send path query to SA\n");
        }
}

static void ssa_upstream_dev_event(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", svc->name,
		ibv_event_type_str(msg->data.event));
	switch (msg->data.event) {
	case IBV_EVENT_CLIENT_REREGISTER:
	case IBV_EVENT_PORT_ERR:
		if (svc->rsock >= 0) {
			rclose(svc->rsock);
			svc->rsock = -1;
		}
		svc->state = SSA_STATE_IDLE;
		/* fall through to reactivate */
	case IBV_EVENT_PORT_ACTIVE:
		if (svc->port->state == IBV_PORT_ACTIVE && svc->state == SSA_STATE_IDLE) {
			svc->timeout = DEFAULT_TIMEOUT;
			ssa_svc_join(svc);
		}
		break;
	default:
		break;
	}
}

void ssa_upstream_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_umad *umad;
	struct ssa_mad_packet *mad;
	struct ssa_info_record *info_rec;

	umad = &msg->data.umad;
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	if (svc->state == SSA_STATE_IDLE) {
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "in idle state, discarding MAD\n");
		svc->timeout = DEFAULT_TIMEOUT;
		return;
	}

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "method %s attr %s\n",
		ssa_method_str(umad->packet.mad_hdr.method),
		ssa_attribute_str(umad->packet.mad_hdr.attr_id));
	/* TODO: do we need to check umad->packet.mad_hdr.status too? */
	if (umad->umad.status) {
		ssa_log(SSA_LOG_DEFAULT, "send failed - status 0x%x (%s)\n",
			umad->umad.status, strerror(umad->umad.status));
		if (svc->state != SSA_STATE_JOINING)
			return;

		svc->timeout = min(svc->timeout << 1, MAX_TIMEOUT);
		ssa_svc_join(svc);
		return;
	}

	svc->timeout = DEFAULT_TIMEOUT;
	if (svc->state == SSA_STATE_JOINING) {
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "join successful\n");
		svc->state = SSA_STATE_ORPHAN;
	}

	if (ntohs(umad->packet.mad_hdr.attr_id) != SSA_ATTR_INFO_REC)
		return;

	umad->packet.mad_hdr.method = UMAD_METHOD_GET_RESP;
	umad_send(svc->port->mad_portid, svc->port->mad_agentid,
		  (void *) umad, sizeof umad->packet, 0, 0);

	switch (svc->state) {
	case SSA_STATE_ORPHAN:
		svc->state = SSA_STATE_HAVE_PARENT;
	case SSA_STATE_HAVE_PARENT:
		mad = &umad->packet;
		info_rec = (struct ssa_info_record *) &mad->data;
		memcpy(&svc->primary_parent, &info_rec->path_data,
		       sizeof(svc->primary_parent));
		break;
	case SSA_STATE_CONNECTING:
	case SSA_STATE_CONNECTED:		/* TODO compare against current parent, if same done */
		/* if parent is different, save parent, close rsock, and reopen */
		break;
	default:
		break;
	}
}

static void *ssa_upstream_handler(void *context)
{
	struct ssa_svc *svc = context;
	struct ssa_ctrl_msg_buf msg;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	msg.hdr.len = sizeof msg;
	msg.hdr.type = SSA_CTRL_ACK;
	write(svc->sock[1], (char *) &msg, sizeof msg.hdr);

	while (msg.hdr.type != SSA_CTRL_EXIT) {
		read(svc->sock[1], (char *) &msg, sizeof msg.hdr);
		if (msg.hdr.len > sizeof msg.hdr) {
			read(svc->sock[1], (char *) &msg.hdr.data,
			     msg.hdr.len - sizeof msg.hdr);
		}
		if (svc->process_msg && svc->process_msg(svc, &msg))
			continue;

		switch (msg.hdr.type) {
		case SSA_CTRL_MAD:
			ssa_upstream_mad(svc, &msg);
			break;
		case SSA_CTRL_DEV_EVENT:
			ssa_upstream_dev_event(svc, &msg);
			break;
		case SSA_CTRL_EXIT:
			break;
		default:
			ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
				"WARNING ignoring unexpected message type %d\n",
				msg.hdr.type);
			break;
		}
	}

	return NULL;
}

static void ssa_ctrl_port_send(struct ssa_port *port, struct ssa_ctrl_msg *msg)
{
	int i;
	for (i = 0; i < port->svc_cnt; i++)
		write(port->svc[i]->sock[0], msg, msg->len);
}

/*
static void ssa_ctrl_dev_send(struct ssa_device *dev, struct ssa_ctrl_msg *msg)
{
	int i;
	for (i = 1; i <= dev->port_cnt; i++)
		ssa_ctrl_port_send(ssa_dev_port(dev, i), msg);
}
*/

static void ssa_ctrl_send_event(struct ssa_port *port, enum ibv_event_type event)
{
	struct ssa_ctrl_dev_event_msg msg;

	msg.hdr.len = sizeof msg;
	msg.hdr.type = SSA_CTRL_DEV_EVENT;
	msg.event = event;
	ssa_ctrl_port_send(port, &msg.hdr);
}

static void ssa_ctrl_update_port(struct ssa_port *port)
{
	struct ibv_port_attr attr;

	ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (attr.state == IBV_PORT_ACTIVE) {
		port->sm_lid = attr.sm_lid;
		port->sm_sl = attr.sm_sl;
		ibv_query_gid(port->dev->verbs, port->port_num, 0, &port->gid);
	}
	port->state = attr.state;
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s state %s SM LID %d\n",
		port->name, ibv_port_state_str(port->state), port->sm_lid);
}

static void ssa_ctrl_device(struct ssa_device *dev)
{
	struct ibv_async_event event;
	int ret;

	ssa_log(SSA_LOG_CTRL, "%s\n", dev->name);
	ret = ibv_get_async_event(dev->verbs, &event);
	if (ret)
		return;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL,
		"async event %s\n", ibv_event_type_str(event.event_type));
	switch (event.event_type) {
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_CLIENT_REREGISTER:
	case IBV_EVENT_PORT_ERR:
		ssa_ctrl_update_port(ssa_dev_port(dev, event.element.port_num));
		ssa_ctrl_send_event(ssa_dev_port(dev, event.element.port_num),
				    event.event_type);
		break;
	default:
		break;
	}

	ibv_ack_async_event(&event);
}

static void ssa_ctrl_port(struct ssa_port *port)
{
	struct ssa_svc *svc;
	struct ssa_ctrl_umad_msg msg;
	struct ssa_member_record *member_rec;
	struct ssa_info_record *info_rec;
	int len, ret, parent = 0;

	ssa_log(SSA_LOG_CTRL, "%s receiving MAD\n", port->name);
	len = sizeof msg.umad;
	ret = umad_recv(port->mad_portid, (void *) &msg.umad, &len, 0);
	if (ret < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"WARNING receive MAD failure\n");
		return;
	}

	if ((msg.umad.packet.mad_hdr.method & UMAD_METHOD_RESP_MASK) ||
	     msg.umad.umad.status) {
		svc = ssa_svc_from_tid(port, msg.umad.packet.mad_hdr.tid);
		if (msg.umad.packet.mad_hdr.mgmt_class == UMAD_CLASS_SUBN_ADM)
			msg.hdr.type = SSA_SA_MAD;
		else
			msg.hdr.type = SSA_CTRL_MAD;
	} else {
		switch (ntohs(msg.umad.packet.mad_hdr.attr_id)) {
		case SSA_ATTR_INFO_REC:
			parent = 1;
			info_rec = (struct ssa_info_record *) msg.umad.packet.data;
			svc = ssa_find_svc(port, ntohll(info_rec->database_id));
			break;
		case SSA_ATTR_MEMBER_REC:
			member_rec = (struct ssa_member_record *) msg.umad.packet.data;
			svc = ssa_find_svc(port, ntohll(member_rec->database_id));
			break;
		default:
			svc = NULL;
			break;
		}
		msg.hdr.type = SSA_CTRL_MAD;
	}

	if (!svc) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - no matching service for received MAD\n");
		return;
	}

	msg.hdr.len = sizeof msg;
	/* set qkey for possible response */
	msg.umad.umad.addr.qkey = htonl(UMAD_QKEY);
	write(svc->sock[0], (void *) &msg, msg.hdr.len);

	if (parent)
		ssa_svc_listen(svc);
}

static void ssa_ctrl_svc_client(struct ssa_svc *svc, int errnum)
{
	int ret, err;
	socklen_t len;

	if (errnum == EINPROGRESS)
		return;

	if (svc->state != SSA_STATE_CONNECTING) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"Unexpected consumer event in state %d\n",
			svc->state);
		return;
	}

	len = sizeof err;
	ret = rgetsockopt(svc->rsock, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rgetsockopt fd %d ERROR %d (%s)\n",
			svc->rsock, errno, strerror(errno));
		return;
	}
	if (err) {
		errno = err;
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"async rconnect fd %d ERROR %d (%s)\n",
			svc->rsock, errno, strerror(errno));
		return;
	}

	if (ssa_svc_modify(svc, svc->slot, 0) < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"clearing POLLOUT on slot %d for fd %d failed\n",
			svc->slot, svc->rsock);
	}

	svc->state = SSA_STATE_CONNECTED;
}

static void ssa_ctrl_svc_server(struct ssa_svc *svc, int errnum)
{
	int fd;
	struct sockaddr_ib peer_addr;
	socklen_t peer_len;

	fd = raccept(svc->rsock, NULL, 0);
	if (fd < 0) {
		if ((errno == EAGAIN || errno == EWOULDBLOCK))
			return;		/* ignore these errors */
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"raccept fd %d ERROR %d (%s)\n",
			svc->rsock, errno, strerror(errno)); 
		return;
	}

	ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
		"new connection accepted on fd %d\n", fd);

	if (!rgetpeername(fd, (struct sockaddr *) &peer_addr, &peer_len)) {
		if (peer_addr.sib_family == AF_IB) {
			ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data, sizeof log_data,
				SSA_ADDR_GID, (uint8_t *) &peer_addr.sib_addr, peer_len);
			ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "peer GID %s\n", log_data);
		}
	}
}

static void ssa_ctrl_svc(struct ssa_svc *svc, int errnum)
{
	if (svc->port->dev->ssa->node_type == SSA_NODE_CONSUMER)
		ssa_ctrl_svc_client(svc, errnum);
	else
		ssa_ctrl_svc_server(svc, errnum);
}

static void ssa_ctrl_initiate_conn(struct ssa_svc *svc)
{
	int dport = 7470;
	struct sockaddr_ib dst_addr;
	int ret, val;

	svc->rsock = rsocket(AF_IB, SOCK_STREAM, 0);
	if (svc->rsock < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsocket ERROR %d (%s)\n",
			errno, strerror(errno));
		return;
	}

	val = 1;
	ret = rsetsockopt(svc->rsock, SOL_SOCKET, SO_REUSEADDR,
			  &val, sizeof val);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsetsockopt SO_REUSEADDR ERROR %d (%s)\n",
			errno, strerror(errno));
		goto close;
	}

	ret = rsetsockopt(svc->rsock, IPPROTO_TCP, TCP_NODELAY,
			  (void *) &val, sizeof(val));
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsetsockopt TCP_NODELAY ERROR %d (%s)\n",
			errno, strerror(errno));
		goto close;
	}
	ret = rfcntl(svc->rsock, F_SETFL, O_NONBLOCK);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rfcntl ERROR %d (%s)\n",
			errno, strerror(errno));
		goto close;
	}

	ret = rsetsockopt(svc->rsock, SOL_RDMA, RDMA_ROUTE, &svc->primary_parent,
			  sizeof(svc->primary_parent));
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rsetsockopt RDMA_ROUTE ERROR %d (%s)\n",
			errno, strerror(errno));
		goto close;
	}

	dst_addr.sib_family = AF_IB;
	dst_addr.sib_pkey = 0xFFFF;
	dst_addr.sib_flowinfo = 0;
	dst_addr.sib_sid = htonll(((uint64_t) RDMA_PS_TCP << 16) + dport);
	dst_addr.sib_sid_mask = htonll(RDMA_IB_IP_PS_MASK);
	dst_addr.sib_scope_id = 0;
	memcpy(&dst_addr.sib_addr, &svc->primary_parent.path.dgid, 16);
	ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, (uint8_t *) &dst_addr.sib_addr,
			sizeof dst_addr.sib_addr);
	ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "dest GID %s\n", log_data);

	svc->slot = ssa_svc_insert(svc, POLLOUT);
	if (svc->slot < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - no service slot available\n");
		goto close;
	}

	ret = rconnect(svc->rsock, (const struct sockaddr *) &dst_addr,
		       sizeof(dst_addr));
	if (ret && (errno != EINPROGRESS)) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"rconnect ERROR %d (%s)\n",
			errno, strerror(errno));
		goto close;
	}

	svc->state = SSA_STATE_CONNECTING;

	if (ret == 0)
		ssa_ctrl_svc_client(svc, 0);

	return;

close:
	rclose(svc->rsock);
	svc->rsock = -1;
}

static int ssa_ctrl_init_fds(struct ssa_class *ssa)
{
	struct ssa_device *dev;
	struct ssa_port *port;
	int d, p, s, i = 0;

	ssa->nfds = 1;			/* ssa socketpair */
	ssa->nfds += ssa->dev_cnt;	/* async device events */
	for (d = 0; d < ssa->dev_cnt; d++) {
		dev = ssa_dev(ssa, d);
		ssa->nfds += dev->port_cnt;	/* mads */
		for (p = 1; p <= dev->port_cnt; p++) {
			port = ssa_dev_port(dev, p);
			ssa->nsfds += port->svc_cnt;	/* service listen */
		}
	}
	ssa->nsfds++;

	ssa->fds = calloc(ssa->nfds + ssa->nsfds,
			  sizeof(*ssa->fds) + sizeof(*ssa->fds_obj));
	if (!ssa->fds)
		return seterr(ENOMEM);

	ssa->fds_obj = (struct ssa_obj *) (&ssa->fds[ssa->nfds + ssa->nsfds]);
	ssa->fds[i].fd = ssa->sock[1];
	ssa->fds[i].events = POLLIN;
	ssa->fds_obj[i++].type = SSA_OBJ_CLASS;
	for (d = 0; d < ssa->dev_cnt; d++) {
		dev = ssa_dev(ssa, d);
		ssa->fds[i].fd = dev->verbs->async_fd;
		ssa->fds[i].events = POLLIN;
		ssa->fds_obj[i].type = SSA_OBJ_DEVICE;
		ssa->fds_obj[i++].dev = dev;

		for (p = 1; p <= dev->port_cnt; p++) {
			port = ssa_dev_port(dev, p);
			ssa->fds[i].fd = umad_get_fd(port->mad_portid);
			ssa->fds[i].events = POLLIN;
			ssa->fds_obj[i].type = SSA_OBJ_PORT;
			ssa->fds_obj[i++].port = port;
		}
	}
	ssa->sfds_start = i;
	for (s = 0; s < ssa->nsfds; s++) {
		ssa->fds[i].fd = -1;
		ssa->fds_obj[i].type = SSA_OBJ_SVC;
		ssa->fds_obj[i++].svc = NULL;
	}
	return 0;
}

static void ssa_ctrl_activate_ports(struct ssa_class *ssa)
{
	struct ssa_device *dev;
	struct ssa_port *port;
	int d, p;

	for (d = 0; d < ssa->dev_cnt; d++) {
		dev = ssa_dev(ssa, d);
		for (p = 1; p <= dev->port_cnt; p++) {
			port = ssa_dev_port(dev, p);
			ssa_ctrl_update_port(port);
			if (port->state == IBV_PORT_ACTIVE) {
				ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", port->name);
				ssa_ctrl_send_event(port, IBV_EVENT_PORT_ACTIVE);
			}
		}
	}
}

int ssa_ctrl_run(struct ssa_class *ssa)
{
	struct ssa_ctrl_msg_buf msg;
	int i, ret, errnum;
	struct ssa_ctrl_conn_msg *conn;

	ssa_log_func(SSA_LOG_CTRL);
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, ssa->sock);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - creating socketpair\n");
		return ret;
	}

	ret = ssa_ctrl_init_fds(ssa);
	if (ret)
		goto err;

	ssa_ctrl_activate_ports(ssa);

	for (;;) {
		ret = rpoll(ssa->fds, ssa->nfds, -1);
		if (ret < 0) {
			ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
				"ERROR - polling fds %d (%s)\n",
				errno, strerror(errno));
			continue;
		}
		errnum = errno;

		for (i = 0; i < ssa->nfds; i++) {
			if (!ssa->fds[i].revents)
				continue;

			ssa->fds[i].revents = 0;
			switch (ssa->fds_obj[i].type) {
			case SSA_OBJ_CLASS:
				ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL,
					"class event on fd %d\n", ssa->fds[i]);

				read(ssa->sock[1], (char *) &msg, sizeof msg.hdr);
				if (msg.hdr.len > sizeof msg.hdr)
					read(ssa->sock[1],
					     (char *) &msg.hdr.data,
					     msg.hdr.len - sizeof msg.hdr);
				switch (msg.hdr.type) {
				case SSA_CTRL_CONN:
					conn = (struct ssa_ctrl_conn_msg *) &msg;
					ssa_ctrl_initiate_conn(conn->svc);
					break;
				case SSA_CTRL_EXIT:
					goto out;
				default:
					ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
						"WARNING ignoring unexpected message type %d\n",
						msg.hdr.type);
					break;
				}
				break;
			case SSA_OBJ_DEVICE:
				ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL,
					"device event on fd %d\n", ssa->fds[i]);
				ssa_ctrl_device(ssa->fds_obj[i].dev);
				break;
			case SSA_OBJ_PORT:
				ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL,
					"port event on fd %d\n", ssa->fds[i]);
				ssa_ctrl_port(ssa->fds_obj[i].port);
				break;
			case SSA_OBJ_SVC:
				ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL,
					"service event on fd %d\n", ssa->fds[i]);
				ssa_ctrl_svc(ssa->fds_obj[i].svc, errnum);
				break;
			}
		}
	}
out:
	msg.hdr.type = SSA_CTRL_ACK;
	write(ssa->sock[1], (char *) &msg, sizeof msg.hdr);
	free(ssa->fds);
	return 0;

err:
	close(ssa->sock[0]);
	close(ssa->sock[1]);
	return ret;
}

void ssa_ctrl_conn(struct ssa_class *ssa, struct ssa_svc *svc)
{
	struct ssa_ctrl_conn_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	msg.hdr.type = SSA_CTRL_CONN;
	msg.hdr.len = sizeof msg;
	msg.svc = svc;
	write(ssa->sock[0], (char *) &msg, sizeof msg);
}

void ssa_ctrl_stop(struct ssa_class *ssa)
{
	struct ssa_ctrl_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	msg.len = sizeof msg;
	msg.type = SSA_CTRL_EXIT;
	write(ssa->sock[0], (char *) &msg, sizeof msg);
	read(ssa->sock[0], (char *) &msg, sizeof msg);

	close(ssa->sock[0]);
	close(ssa->sock[1]);
}

struct ssa_svc *ssa_start_svc(struct ssa_port *port, uint64_t database_id,
			      size_t svc_size,
			      int (*process_msg)(struct ssa_svc *svc,
					         struct ssa_ctrl_msg_buf *msg))
{
	struct ssa_svc *svc, **list;
	struct ssa_ctrl_msg msg;
	int ret;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s:%llu\n", port->name, database_id);
	list = realloc(port->svc, (port->svc_cnt + 1) * sizeof(svc));
	if (!list)
		return NULL;

	port->svc = list;
	svc = calloc(1, svc_size);
	if (!svc)
		return NULL;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, svc->sock);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - creating socketpair\n");
		goto err1;
	}

	svc->index = port->svc_cnt;
	svc->port = port;
	snprintf(svc->name, sizeof svc->name, "%s:%llu", port->name,
		 (unsigned long long) database_id);
	svc->database_id = database_id;
	svc->rsock = -1;
	svc->slot = -1;
	svc->state = SSA_STATE_IDLE;
	svc->process_msg = process_msg;
	//pthread_mutex_init(&svc->lock, NULL);

	ret = pthread_create(&svc->upstream, NULL, ssa_upstream_handler, svc);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - creating upstream thread\n");
		errno = ret;
		goto err2;
	}

	ret = read(svc->sock[0], (char *) &msg, sizeof msg);
	if ((ret != sizeof msg) || (msg.type != SSA_CTRL_ACK)) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR with upstream thread\n");
		goto err3;

	}

	port->svc[port->svc_cnt++] = svc;
	return svc;

err3:
	pthread_join(svc->upstream, NULL);
err2:
	close(svc->sock[0]);
	close(svc->sock[1]);
err1:
	free(svc);
	return NULL;
}

static void ssa_open_port(struct ssa_port *port, struct ssa_device *dev, uint8_t port_num)
{
	long methods[16 / sizeof(long)];
	int ret;

	port->dev = dev;
	port->port_num = port_num;
	snprintf(port->name, sizeof port->name, "%s:%d", dev->name, port_num);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", port->name);
	//pthread_mutex_init(&port->lock, NULL);

	port->mad_portid = umad_open_port(dev->name, port->port_num);
	if (port->mad_portid < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - unable to open MAD port %s\n",
			port->name);
		return;
	}

	ret = fcntl(umad_get_fd(port->mad_portid), F_SETFL, O_NONBLOCK);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"WARNING - MAD fd is blocking\n");
	}

	memset(methods, 0xFF, sizeof methods);
	port->mad_agentid = umad_register(port->mad_portid,
		SSA_CLASS, SSA_CLASS_VERSION, 0, methods);
	if (port->mad_agentid < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - unable to register SSA class on port %s\n",
			port->name);
		goto err;
	}

	/* Only registering for solicited SA MADs */
	port->sa_agentid = umad_register(port->mad_portid,
		UMAD_CLASS_SUBN_ADM, UMAD_SA_CLASS_VERSION, 0, NULL);
	if (port->sa_agentid < 0) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - unable to register SA class on port %s\n",
			port->name);
		goto err2;
	}

	return;
err2:
	umad_unregister(port->mad_portid, port->mad_agentid);
err:
	umad_close_port(port->mad_portid);
}

static void ssa_open_dev(struct ssa_device *dev, struct ssa_class *ssa,
			 struct ibv_device *ibdev)
{
	struct ibv_device_attr attr;
	int i, ret;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", ibdev->name);
	dev->verbs = ibv_open_device(ibdev);
	if (dev->verbs == NULL) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - opening device %s\n", ibdev->name);
		return;
	}

	ret = ibv_query_device(dev->verbs, &attr);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - ibv_query_device (%s) %d\n", ibdev->name, ret);
		goto err1;
	}

	ret = fcntl(dev->verbs->async_fd, F_SETFL, O_NONBLOCK);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"WARNING - event fd is blocking\n");
	}

	dev->port = (struct ssa_port *) calloc(attr.phys_port_cnt, ssa->port_size);
	if (!dev)
		goto err1;

	dev->ssa = ssa;
	dev->guid = ibv_get_device_guid(ibdev);
	snprintf(dev->name, sizeof dev->name, ibdev->name);
	dev->port_cnt = attr.phys_port_cnt;
	dev->port_size = ssa->port_size;

	for (i = 1; i <= dev->port_cnt; i++)
		ssa_open_port(ssa_dev_port(dev, i), dev, i);

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s opened\n", dev->name);
	return;

err1:
	ibv_close_device(dev->verbs);
	dev->verbs = NULL;
}

int ssa_open_devices(struct ssa_class *ssa)
{
	struct ibv_device **ibdev;
	int i, ret = 0;

	ssa_log_func(SSA_LOG_VERBOSE | SSA_LOG_CTRL);
	ibdev = ibv_get_device_list(&ssa->dev_cnt);
	if (!ibdev) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - unable to get device list\n");
		return -1;
	}

	ssa->dev = (struct ssa_device *) calloc(ssa->dev_cnt, ssa->dev_size);
	if (!ssa->dev) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL, "ERROR allocating devices\n");
		ret = seterr(ENOMEM);
		goto free;
	}

	for (i = 0; i < ssa->dev_cnt; i++)
		ssa_open_dev(ssa_dev(ssa, i), ssa, ibdev[i]);

free:
	ibv_free_device_list(ibdev);
	return ret;
}

static void ssa_stop_svc(struct ssa_svc *svc)
{
	struct ssa_ctrl_msg msg;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	msg.len = sizeof msg;
	msg.type = SSA_CTRL_EXIT;
	write(svc->sock[0], (char *) &msg, sizeof msg);
	pthread_join(svc->upstream, NULL);

	svc->port->svc[svc->index] = NULL;
	if (svc->rsock >= 0) {
		rclose(svc->rsock);
		svc->rsock = -1;
	}
	close(svc->sock[0]);
	close(svc->sock[1]);
	free(svc);
}

static void ssa_close_port(struct ssa_port *port)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", port->name);
	while (port->svc_cnt)
		ssa_stop_svc(port->svc[--port->svc_cnt]);
	if (port->svc)
		free(port->svc);

	if (port->sa_agentid >= 0)
		umad_unregister(port->mad_portid, port->sa_agentid);
	if (port->mad_agentid >= 0)
		umad_unregister(port->mad_portid, port->mad_agentid);
	if (port->mad_portid >= 0)
		umad_close_port(port->mad_portid);
}

void ssa_close_devices(struct ssa_class *ssa)
{
	struct ssa_device *dev;
	int d, p;

	ssa_log_func(SSA_LOG_VERBOSE | SSA_LOG_CTRL);
	for (d = 0; d < ssa->dev_cnt; d++) {
		dev = ssa_dev(ssa, d);
		for (p = 1; p <= dev->port_cnt; p++)
			ssa_close_port(ssa_dev_port(dev, p));

		ibv_close_device(dev->verbs);
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s closed\n", dev->name);
		free(dev->port);
	}
	free(ssa->dev);
	ssa->dev_cnt = 0;
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

int ssa_init(struct ssa_class *ssa, uint8_t node_type, size_t dev_size, size_t port_size)
{
	int ret;

	memset(ssa, 0, sizeof *ssa);
	ssa->node_type = node_type;
	ssa->dev_size = dev_size;
	ssa->port_size = port_size;
	ret = umad_init();
	if (ret)
		return ret;

	return 0;
}

void ssa_cleanup(struct ssa_class *ssa)
{
	umad_done();
}
