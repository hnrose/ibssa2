/*
 * Copyright (c) 2012-2013 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012-2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2012 Lawrence Livermore National Securities.  All rights reserved.
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

#include <infiniband/osm_headers.h>
#include <search.h>
#include <common.h>
#include <infiniband/ssa_mad.h>
#include <infiniband/ssa_extract.h>
#include <infiniband/ssa_comparison.h>
#include <ssa_ctrl.h>

#include <infiniband/ssa_db_helper.h>
#define SMDB_DUMP_PATH RDMA_CONF_DIR "/smdb_dump"

#define INITIAL_SUBNET_UP_DELAY 100000		/* 100 msec */

/*
 * Service options - may be set through ibssa_opts.cfg file.
 */
static char *opts_file = RDMA_CONF_DIR "/" SSA_OPTS_FILE;
static int node_type = SSA_NODE_CORE;
static int smdb_dump = 0;
int smdb_deltas = 0;
static char log_file[128] = "/var/log/ibssa.log";
static char lock_file[128] = "/var/run/ibssa.pid";

extern short smdb_port;
extern short prdb_port;

int first = 1;

struct ssa_member {
	struct ssa_member_record	rec;
	struct ssa_member		*primary;
	struct ssa_member		*secondary;
	uint16_t			lid;
	uint8_t				sl;
	DLIST_ENTRY			list;
	DLIST_ENTRY			entry;
};

struct ssa_core {
	struct ssa_svc			svc;
	void				*member_map;
	DLIST_ENTRY			orphan_list;
};

static struct ssa_class ssa;
struct ssa_database *ssa_db;
static struct ssa_db_diff *ssa_db_diff = NULL;
pthread_mutex_t ssa_db_diff_lock;
pthread_t ctrl_thread, extract_thread;
static osm_opensm_t *osm;

static int sock_coreextract[2];

static void core_build_tree(struct ssa_svc *svc, union ibv_gid *gid,
			    uint8_t node_type)
{
	static int access_init = 0;
	static int distrib_init = 0;
	static union ibv_gid access_gid;
	static union ibv_gid distrib_gid;

	/*
	 * For now, issue SA path query here.
	 * DGID is from incoming join.
	 *
	 * Latest prototype is to support either
	 * plugin/core <-> distribution <-> access <-> ACM 
	 * or plugin/core <-> access <-> ACM. Also, it
	 * is a current requirement (limitation) that
	 * the access node needs to join prior to the
	 * ACM. Similarly, the distribution node should
	 * join prior to the access node.
	 *
	 * With those assumptions, the SGID depends on the
	 * node type. If it's a distribution node, the SGID
	 * is the port GID that the join came in on. 
	 * If it's an access node, the SGID is the port GID of
	 * the previously joined distribution node, and if no
	 * distribution nodes have yet joined, then it's
	 * the port GID that the join came in on.
	 * If it's a consumer (ACM) node, the SGID is the
	 * port GID of the previous joined access node.
	 * If there is no previous access node, this
	 * is treated as an error.
	 *
	 * Longer term, SGID needs to come from the tree
	 * calculation code so rather than query PathRecord
	 * here, this would inform the tree calculation
	 * that a parent is needed for joining port and
	 * when parent is determined, then the SA path
	 * query would be issued.
	 *
	 */
	switch (node_type) {
	case SSA_NODE_DISTRIBUTION:
	case (SSA_NODE_DISTRIBUTION | SSA_NODE_ACCESS):
		if (distrib_init)
			ssa_log_warn(SSA_LOG_CTRL, "distribution node previously joined\n");
		distrib_init =1;
		memcpy(&distrib_gid, gid, 16);
		ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				distrib_gid.raw, sizeof distrib_gid.raw);
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "distribution node GID %s\n", log_data);
		if (node_type & SSA_NODE_ACCESS) {
			if (access_init)
				ssa_log_warn(SSA_LOG_CTRL, "access node previously joined\n");
			access_init = 1;
			memcpy(&access_gid, gid, 16);
			ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data,
					sizeof log_data, SSA_ADDR_GID,
					access_gid.raw, sizeof access_gid.raw);
			ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "access node GID %s\n", log_data);
		}
		ssa_svc_query_path(svc, &svc->port->gid, gid);
		break;
	case SSA_NODE_ACCESS:
		if (access_init)
			ssa_log_warn(SSA_LOG_CTRL, "access node previously joined\n");
		access_init = 1;
		memcpy(&access_gid, gid, 16);
		ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				access_gid.raw, sizeof access_gid.raw);
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "access node GID %s\n", log_data);
		if (distrib_init) {
			ssa_svc_query_path(svc, &distrib_gid, gid);
		} else
			ssa_svc_query_path(svc, &svc->port->gid, gid);
		break;
	case (SSA_NODE_CORE | SSA_NODE_ACCESS):
		if (access_init)
			ssa_log_warn(SSA_LOG_CTRL, "access node previously joined\n");
		access_init = 1;
		memcpy(&access_gid, gid, 16);
		ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				access_gid.raw, sizeof access_gid.raw);
		ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "access node GID %s\n", log_data);
	case SSA_NODE_CORE:
		ssa_svc_query_path(svc, &svc->port->gid, gid);
		break;
	case SSA_NODE_CONSUMER:
		if (access_init)
			ssa_svc_query_path(svc, &access_gid, gid);
		else
			ssa_log_err(SSA_LOG_CTRL, "no access node joined as yet\n");
		break;
	}
}

/*
 * Process received SSA membership requests.  On errors, we simply drop
 * the request and let the remote node retry.
 */
static void core_process_join(struct ssa_core *core, struct ssa_umad *umad,
			      struct ssa_svc *svc)
{
	struct ssa_member_record *rec;
	struct ssa_member *member;
	uint8_t **tgid;

	/* TODO: verify ssa_key with core nodes */
	rec = (struct ssa_member_record *) &umad->packet.data;
	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, rec->port_gid, sizeof rec->port_gid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", core->svc.name, log_data);

	tgid = tfind(rec->port_gid, &core->member_map, ssa_compare_gid);
	if (!tgid) {
		ssa_log(SSA_LOG_CTRL, "adding new member\n");
		member = calloc(1, sizeof *member);
		if (!member)
			return;

		member->rec = *rec;
		member->lid = ntohs(umad->umad.addr.lid);
		DListInit(&member->list);
		if (!tsearch(&member->rec.port_gid, &core->member_map, ssa_compare_gid)) {
			free(member);
			return;
		}
		DListInsertBefore(&member->entry, &core->orphan_list);
	}

	ssa_log(SSA_LOG_CTRL, "sending join response\n");
	umad->packet.mad_hdr.method = UMAD_METHOD_GET_RESP;
	umad_send(core->svc.port->mad_portid, core->svc.port->mad_agentid,
		  (void *) umad, sizeof umad->packet, 0, 0);

	/*
	 * TODO: Really need to wait for first
	 * SUBNET UP event.
	 *
	 * Just a one time artificial delay for now.
	 */
	if (first) {
		usleep(INITIAL_SUBNET_UP_DELAY);
		first = 0;
	}

	core_build_tree(svc, (union ibv_gid *) rec->port_gid, rec->node_type);
}

static void core_process_leave(struct ssa_core *core, struct ssa_umad *umad)
{
	struct ssa_member_record *rec;
	struct ssa_member *member;
	uint8_t **tgid;

	rec = (struct ssa_member_record *) &umad->packet.data;
	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, rec->port_gid, sizeof rec->port_gid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", core->svc.name, log_data);

	tgid = tdelete(rec->port_gid, &core->member_map, ssa_compare_gid);
	if (tgid) {
		ssa_log(SSA_LOG_CTRL, "removing member\n");
		rec = container_of(*tgid, struct ssa_member_record, port_gid);
		member = container_of(rec, struct ssa_member, rec);
		DListRemove(&member->entry);
		free(member);
	}

	ssa_log(SSA_LOG_CTRL, "sending leave response\n");
	umad->packet.mad_hdr.method = SSA_METHOD_DELETE_RESP;
	umad_send(core->svc.port->mad_portid, core->svc.port->mad_agentid,
		  (void *) umad, sizeof umad->packet, 0, 0);
}

void core_init_parent(struct ssa_core *core, struct ssa_mad_packet *mad,
		      struct ssa_member_record *member,
		      struct ibv_path_record *path)
{
	struct ssa_info_record *rec;

	ssa_init_mad_hdr(&core->svc, &mad->mad_hdr, UMAD_METHOD_SET, SSA_ATTR_INFO_REC);
	mad->ssa_key = 0;	/* TODO: set for real */

	rec = (struct ssa_info_record *) &mad->data;
	rec->database_id = member->database_id;
	rec->path_data.flags = IBV_PATH_FLAG_GMP | IBV_PATH_FLAG_PRIMARY |
			       IBV_PATH_FLAG_BIDIRECTIONAL;
	rec->path_data.path = *path;
}

static void core_process_parent_set(struct ssa_core *core, struct ssa_umad *umad)
{
	/* Ignoring this for now */
}

static void core_process_path_rec(struct ssa_core *core, struct sa_umad *umad)
{
	struct ibv_path_record *path;
	struct ssa_member **member;
	struct ssa_umad umad_sa;
	int ret;

	path = (struct ibv_path_record *) &umad->packet.data;
	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, (uint8_t *) &path->sgid, sizeof path->sgid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", core->svc.name, log_data);

	/* Joined port GID is SGID in PathRecord */
	member = tfind(&path->sgid, &core->member_map, ssa_compare_gid);
	if (!member) {
		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &path->sgid, sizeof path->sgid);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - couldn't find joined port GID %s\n", log_data);
		return;
	}

	/*
	 * TODO: SL should come from another PathRecord between core
	 * and joined client.
	 *
	 * In prototype, since core is coresident with SM, this is SL
	 * from the PathRecord between the client and the parent
	 * since the (only) parent is the core.
	 */
	(*member)->sl = ntohs(path->qosclass_sl) & 0xF;

	memset(&umad_sa, 0, sizeof umad_sa);
	umad_set_addr(&umad_sa.umad, (*member)->lid, 1, (*member)->sl, UMAD_QKEY);
	core_init_parent(core, &umad_sa.packet, &(*member)->rec, path);

	ssa_log(SSA_LOG_CTRL, "sending set parent\n");
	ret = umad_send(core->svc.port->mad_portid, core->svc.port->mad_agentid,
			(void *) &umad_sa, sizeof umad_sa.packet, core->svc.timeout, 0);
	if (ret)
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - failed to send set parent\n");
}

static int core_process_sa_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_core *core;
	struct sa_umad *umad_sa;

	umad_sa = &msg->data.umad_sa;
	if (umad_sa->umad.status)
		return 0;

	core = container_of(svc, struct ssa_core, svc);

	switch (umad_sa->packet.mad_hdr.method) {
	case UMAD_METHOD_GET_RESP:
		if (ntohs(umad_sa->packet.mad_hdr.attr_id) == UMAD_SA_ATTR_PATH_REC) {
			core_process_path_rec(core, umad_sa);
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int core_process_ssa_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_core *core;
	struct ssa_umad *umad;

	umad = &msg->data.umad;
	if (umad->umad.status)
		return 0;

	core = container_of(svc, struct ssa_core, svc);

	switch (umad->packet.mad_hdr.method) {
	case UMAD_METHOD_SET:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_MEMBER_REC) {
			core_process_join(core, umad, svc);
			return 1;
		}
		break;
	case SSA_METHOD_DELETE:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_MEMBER_REC) {
			core_process_leave(core, umad);
			return 1;
		}
		break;
	case UMAD_METHOD_GET_RESP:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_INFO_REC) {
			core_process_parent_set(core, umad);
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int core_process_msg(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	switch(msg->hdr.type) {
	case SSA_CTRL_MAD:
		return core_process_ssa_mad(svc, msg);
	case SSA_SA_MAD:
		return core_process_sa_mad(svc, msg);
	default:
		break;
	}
	return 0;
}

static void *core_ctrl_handler(void *context)
{
	int ret;

	ret = ssa_ctrl_run(&ssa);
	if (ret)
		ssa_log(SSA_LOG_DEFAULT, "ERROR processing control\n");

	return context;
}

static void core_init_svc(struct ssa_svc *svc)
{
	struct ssa_core *core = container_of(svc, struct ssa_core, svc);
	DListInit(&core->orphan_list);
}

static void core_free_member(void *gid)
{
	struct ssa_member *member;
	struct ssa_member_record *rec;
	rec = container_of(gid, struct ssa_member_record, port_gid);
	member = container_of(rec, struct ssa_member, rec);
	free(member);
}

static void core_destroy_svc(struct ssa_svc *svc)
{
	struct ssa_core *core = container_of(svc, struct ssa_core, svc);
	ssa_log_func(SSA_LOG_CTRL);
	if (core->member_map)
		tdestroy(core->member_map, core_free_member);
}

static const char *sm_state_str(int state)
{
	switch (state) {
	case IB_SMINFO_STATE_DISCOVERING:
		return "Discovering";
	case IB_SMINFO_STATE_STANDBY:
		return "Standby";
	case IB_SMINFO_STATE_NOTACTIVE:
		return "Not Active";
	case IB_SMINFO_STATE_MASTER:
		return "Master";
	}
	return "UNKNOWN";
}

static void handle_trap_event(ib_mad_notice_attr_t *p_ntc)
{
	if (ib_notice_is_generic(p_ntc)) {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_VERBOSE,
			"Generic trap type %d event %d from LID %u\n",
			ib_notice_get_type(p_ntc),
			ntohs(p_ntc->g_or_v.generic.trap_num),
			ntohs(p_ntc->issuer_lid));
	} else {
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_VERBOSE,
			"Vendor trap type %d from LID %u\n",
			ib_notice_get_type(p_ntc),
			ntohs(p_ntc->issuer_lid));
	}
}

static void ssa_extract_send_db_update(struct ssa_db *db, int fd,
				       int flags)
{
#ifndef CORE_INTEGRATION
	struct ssa_db_update_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	msg.hdr.type = SSA_DB_UPDATE;
	msg.hdr.len = sizeof(msg);
	msg.db_upd.db = db;
	msg.db_upd.flags = flags;
	write(fd, (char *) &msg, sizeof(msg));
#endif
}

static void *core_extract_handler(void *context)
{
	osm_opensm_t *p_osm = (osm_opensm_t *) context;
	struct ssa_svc *svc;
	struct pollfd pfds[1];
	struct ssa_db_ctrl_msg msg;
	int d, p, s, ret;

	pfds[0].fd	= sock_coreextract[1];
	pfds[0].events	= POLLIN;
	pfds[0].revents = 0;

	ssa_log(SSA_LOG_VERBOSE, "Starting smdb extract thread\n");

	for (;;) {
		ret = poll(pfds, 1, -1);
		if (ret < 0) {
			ssa_log(SSA_LOG_VERBOSE, "ERROR polling fds\n");
			continue;
		}

		if (pfds[0].revents) {
			pfds[0].revents = 0;
			read(sock_coreextract[1], (char *) &msg, sizeof(msg));
			switch (msg.type) {
			case SSA_DB_START_EXTRACT:
				CL_PLOCK_ACQUIRE(&p_osm->lock);
				ssa_db->p_dump_db = ssa_db_extract(p_osm);
				ssa_db_lft_handle();
				CL_PLOCK_RELEASE(&p_osm->lock);

				/* For verification */
				ssa_db_validate(ssa_db->p_dump_db);
				ssa_db_validate_lft();

				/* Updating SMDB versions */
				ssa_db_update(ssa_db);

				pthread_mutex_lock(&ssa_db_diff_lock);
				/* Clear previous version */
				ssa_db_diff_destroy(ssa_db_diff);

				ssa_db_diff = ssa_db_compare(ssa_db);
				if (ssa_db_diff) {
					ssa_log(SSA_LOG_VERBOSE, "SMDB was changed. Pushing the changes...\n");
					ssa_db_save(SMDB_DUMP_PATH, ssa_db_diff->p_smdb, SSA_DB_HELPER_DEBUG);
					for (d = 0; d < ssa.dev_cnt; d++) {
						for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
							for (s = 0; s < ssa_dev_port(ssa_dev(&ssa, d), p)->svc_cnt; s++) {
								svc = ssa_dev_port(ssa_dev(&ssa, d), p)->svc[s];
								ssa_extract_send_db_update(ssa_db_diff->p_smdb,
											   svc->sock_extractdown[1], 0);
							}
						}
					}

				}
				pthread_mutex_unlock(&ssa_db_diff_lock);
				first = 0;
				break;
			case SSA_DB_LFT_CHANGE:
				ssa_log(SSA_LOG_VERBOSE, "Start handling LFT change events\n");
				ssa_db_lft_handle();
				break;
			case SSA_DB_EXIT:
				goto out;
			default:
				ssa_log(SSA_LOG_VERBOSE, "ERROR: Unknown msg type %d\n", msg.type);
				break;
			}
		}
	}
out:
	ssa_log(SSA_LOG_VERBOSE, "Exiting smdb extract thread\n");
	pthread_exit(NULL);
}

static void ssa_core_send(enum ssa_db_ctrl_msg_type type)
{
	struct ssa_db_ctrl_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	ssa_log(SSA_LOG_VERBOSE, "Sending msg type %d from core "
		"to extract thread\n", type);
	msg.len = sizeof(msg);
	msg.type = type;
	write(sock_coreextract[0], (char *) &msg, sizeof(msg));
}

static void ssa_core_process_lft_change(osm_epi_lft_change_event_t *p_lft_change)
{
	struct ssa_db_lft_change_rec *p_lft_change_rec;
	size_t size;

	if (!p_lft_change || !p_lft_change->p_sw)
		return;

	ssa_log(SSA_LOG_VERBOSE, "LFT change event for SW 0x%" PRIx64"\n",
		ntohll(osm_node_get_node_guid(p_lft_change->p_sw->p_node)));

	size = sizeof(*p_lft_change_rec);
	if (p_lft_change->flags == LFT_CHANGED_BLOCK)
		size += sizeof(p_lft_change_rec->block[0]) * IB_SMP_DATA_SIZE;

	p_lft_change_rec = (struct ssa_db_lft_change_rec *) malloc(size);
	if (!p_lft_change_rec) {
		/* TODO: handle failure in memory allocation */
	}

	memcpy(&p_lft_change_rec->lft_change, p_lft_change,
	       sizeof(p_lft_change_rec->lft_change));
	p_lft_change_rec->lid = osm_node_get_base_lid(p_lft_change->p_sw->p_node, 0);

	if (p_lft_change->flags == LFT_CHANGED_BLOCK)
		memcpy(p_lft_change_rec->block, p_lft_change->p_sw->lft +
		       p_lft_change->block_num * IB_SMP_DATA_SIZE,
		       IB_SMP_DATA_SIZE);

	pthread_mutex_lock(&ssa_db->lft_rec_list_lock);
	cl_qlist_insert_tail(&ssa_db->lft_rec_list, &p_lft_change_rec->list_item);
	pthread_mutex_unlock(&ssa_db->lft_rec_list_lock);

	ssa_core_send(SSA_DB_LFT_CHANGE);
}

static void core_report(void *context, osm_epi_event_id_t event_id, void *event_data)
{
	osm_epi_ucast_routing_flags_t *p_ucast_routing_flag;

	switch (event_id) {
	case OSM_EVENT_ID_TRAP:
		handle_trap_event((ib_mad_notice_attr_t *) event_data);
		break;
	case OSM_EVENT_ID_LFT_CHANGE:
		ssa_log(SSA_LOG_VERBOSE, "LFT change event\n");
		ssa_core_process_lft_change((osm_epi_lft_change_event_t *) event_data);
		break;
	case OSM_EVENT_ID_UCAST_ROUTING_DONE:
		p_ucast_routing_flag = (osm_epi_ucast_routing_flags_t *) event_data;
		if (p_ucast_routing_flag &&
		    *p_ucast_routing_flag == UCAST_ROUTING_REROUTE) {
			/* We get here in case of subnet re-routing not followed by SUBNET_UP */
			/* TODO: notify the distribution thread and push the LFT changes */
		}
		break;
	case OSM_EVENT_ID_SUBNET_UP:
		/* For now, ignore SUBNET UP events when there is subnet init error */
		if (osm->subn.subnet_initialization_error)
			break;

		ssa_log(SSA_LOG_VERBOSE, "Subnet up event\n");

		ssa_core_send(SSA_DB_START_EXTRACT);

		break;
	case OSM_EVENT_ID_STATE_CHANGE:
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_VERBOSE,
			"SM state (%u: %s) change event\n",
			osm->subn.sm_state,
			sm_state_str(osm->subn.sm_state));
		break;
	default:
		/* Ignoring all other events for now... */
		if (event_id >= OSM_EVENT_ID_MAX) {
			ssa_log(SSA_LOG_ALL, "Unknown event (%d)\n", event_id);
			osm_log(&osm->log, OSM_LOG_ERROR,
				"Unknown event (%d) reported to SSA plugin\n",
				event_id);
		}
	}
}

static int core_convert_node_type(const char *node_type_string)
{
	int node_type = SSA_NODE_CORE;

	if (!strcasecmp("combined", node_type_string))
		node_type |= SSA_NODE_ACCESS;
	return node_type;
}

static void core_set_options(void)
{
	FILE *f;
	char s[120];
	char opt[32], value[32];

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%32s%32s", opt, value) != 2)
			continue;

		if (!strcasecmp("log_file", opt))
			strcpy(log_file, value);
		else if (!strcasecmp("log_level", opt))
			ssa_set_log_level(atoi(value));
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("node_type", opt))
			node_type = core_convert_node_type(value);
		else if (!strcasecmp("smdb_port", opt))
			smdb_port = (short) atoi(value);
		else if (!strcasecmp("prdb_port", opt))
			prdb_port = (short) atoi(value);
		else if (!strcasecmp("smdb_dump", opt))
			smdb_dump = atoi(value);
		else if (!strcasecmp("smdb_deltas", opt))
			smdb_deltas = atoi(value);
	}

	fclose(f);
}

static const char *core_node_type_str(int node_type)
{
	if (node_type == SSA_NODE_CORE)
		return "Core";
	if (node_type == (SSA_NODE_CORE | SSA_NODE_ACCESS))
		return "Combined";
	return "Other";
}

static void core_log_options(void)
{
	ssa_log_options();
	ssa_log(SSA_LOG_DEFAULT, "lock file %s\n", lock_file);
	ssa_log(SSA_LOG_DEFAULT, "node type %d (%s)\n", node_type,
		core_node_type_str(node_type));
	ssa_log(SSA_LOG_DEFAULT, "smdb port %u\n", smdb_port);
	ssa_log(SSA_LOG_DEFAULT, "prdb port %u\n", prdb_port);
	ssa_log(SSA_LOG_DEFAULT, "smdb dump %d\n", smdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "smdb deltas %d\n", smdb_deltas);
}

static void *core_construct(osm_opensm_t *opensm)
{
	struct ssa_svc *svc;
	int d, p, ret;

	core_set_options();
	ret = ssa_init(&ssa, node_type, sizeof(struct ssa_device),
			sizeof(struct ssa_port));
	if (ret)
		return NULL;

	if (ssa_open_lock_file(lock_file))
		goto err1;

	ssa_open_log(log_file);
	ssa_log(SSA_LOG_DEFAULT, "Scalable SA Core - OpenSM Plugin\n");
	core_log_options();

	ssa_db = ssa_database_init();
	if (!ssa_db) {
		ssa_log(SSA_LOG_ALL, "SSA database init failed\n");
		goto err1;
	}

	ssa_db->p_previous_db = ssa_db_extract_init();
	if (!ssa_db->p_previous_db) {
		ssa_log(SSA_LOG_ALL, "ssa_db_init failed (previous SMDB)\n");
		goto err2;
	}
	ssa_db->p_current_db = ssa_db_extract_init();
	if (!ssa_db->p_current_db) {
		ssa_log(SSA_LOG_ALL, "ssa_db_init failed (current SMDB)\n");
		goto err2;
	}
	ssa_db->p_dump_db = ssa_db_extract_init();
	if (!ssa_db->p_dump_db) {
		ssa_log(SSA_LOG_ALL, "ssa_db_init failed (dump SMDB)\n");
		goto err2;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_coreextract);
	if (ret) {
		ssa_log(SSA_LOG_ALL, "ERROR %d (%s): creating socketpair\n",
			errno, strerror(errno));
		goto err2;
	}

	pthread_mutex_init(&ssa_db_diff_lock, NULL);

	ret = ssa_open_devices(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR opening devices\n");
		goto err3;
	}

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			svc = ssa_start_svc(ssa_dev_port(ssa_dev(&ssa, d), p),
					    SSA_DB_PATH_DATA, sizeof(struct ssa_core),
					    core_process_msg);
			if (!svc) {
				ssa_log(SSA_LOG_DEFAULT, "ERROR starting service\n");
				goto err4;
			}
			core_init_svc(svc);
		}
	}

	ret = pthread_create(&extract_thread, NULL, core_extract_handler,
			     (void *) opensm);
	if (ret) {
		ssa_log(SSA_LOG_ALL,
			"ERROR %d (%s): error creating smdb extract thread\n",
			ret, strerror(ret));
		goto err4;
	}

	pthread_create(&ctrl_thread, NULL, core_ctrl_handler, NULL);
	osm = opensm;
	return &ssa;

err4:
	ssa_close_devices(&ssa);
err3:
	close(sock_coreextract[0]);
	close(sock_coreextract[1]);
err2:
	ssa_database_delete(ssa_db);
err1:
	ssa_cleanup(&ssa);
	return NULL;
}

static void core_destroy(void *context)
{
	int d, p, s;

	ssa_log(SSA_LOG_DEFAULT, "shutting down control thread\n");
	ssa_ctrl_stop(&ssa);
	pthread_join(ctrl_thread, NULL);

	ssa_log(SSA_LOG_CTRL, "shutting down smdb extract thread\n");
	ssa_core_send(SSA_DB_EXIT);
	pthread_join(extract_thread, NULL);

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			for (s = 0; s < ssa_dev_port(ssa_dev(&ssa, d), p)->svc_cnt; s++) {
				core_destroy_svc(ssa_dev_port(ssa_dev(&ssa, d), p)->svc[s]);
			}
		}
	}

	close(sock_coreextract[0]);
	close(sock_coreextract[1]);

	ssa_log(SSA_LOG_CTRL, "closing devices\n");
	ssa_close_devices(&ssa);

	pthread_mutex_lock(&ssa_db_diff_lock);
	ssa_db_diff_destroy(ssa_db_diff);
	pthread_mutex_unlock(&ssa_db_diff_lock);
	pthread_mutex_destroy(&ssa_db_diff_lock);

	ssa_log(SSA_LOG_CTRL, "destroying SMDB\n");
	ssa_database_delete(ssa_db);

	ssa_log(SSA_LOG_VERBOSE, "that's all folks!\n");
	ssa_close_log();
	ssa_cleanup(&ssa);
}

#if OSM_EVENT_PLUGIN_INTERFACE_VER != 2
#error OpenSM plugin interface version missmatch
#endif
osm_event_plugin_t osm_event_plugin = {
      osm_version:OSM_VERSION,
      create:core_construct,
      delete:core_destroy,
      report:core_report
};
