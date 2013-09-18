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

#include "osm_headers.h"
#include <search.h>
#include <common.h>
#include <infiniband/ssa_mad.h>
#include <ssa_ctrl.h>

#define INITIAL_SUBNET_UP_DELAY 100000		/* 100 msec */

static char log_file[128] = "/var/log/ibssa.log";
static char lock_file[128] = "/var/run/ibssa.pid";

static int first = 1;

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
pthread_t ctrl_thread;
static osm_opensm_t *osm;


/*
 * Process received SSA membership requests.  On errors, we simply drop
 * the request and let the remote node retry.
 */
static void core_process_join(struct ssa_core *core, struct ssa_umad *umad)
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

static int core_process_msg(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_core *core;
	struct ssa_umad *umad;
	struct sa_umad *umad_sa;
	struct ssa_member_record *rec;

	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	if (msg->hdr.type != SSA_CTRL_MAD && msg->hdr.type != SSA_SA_MAD)
		return 0;

	core = container_of(svc, struct ssa_core, svc);
	if (msg->hdr.type == SSA_SA_MAD)
		goto samad;

	umad = &msg->data.umad;
	if (umad->umad.status)
		return 0;

	switch (umad->packet.mad_hdr.method) {
	case UMAD_METHOD_SET:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_MEMBER_REC) {
			core_process_join(core, umad);

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

			/*
			 * For now, issue SA path query here.
			 * DGID is from incoming join.
			 * For now (prototype), SGID is from port join came in on.
			 * Longer term, SGID needs to come from the tree
			 * calculation code so rather than query PathRecord
			 * here, this would inform the tree calculation
			 * that a parent is needed for joining port and
			 * when parent is determined, then the SA path
			 * query would be issued.
			 *
			 */
			rec = (struct ssa_member_record *) &umad->packet.data;
			ssa_svc_query_path(svc, &svc->port->gid,
					   (union ibv_gid *) rec->port_gid);
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

samad:
	umad_sa = &msg->data.umad_sa;
	if (umad_sa->umad.status)
		return 0;

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
	ssa_log(SSA_LOG_CTRL, "\n");
	if (core->member_map)
		tdestroy(core->member_map, core_free_member);
}

static void core_report(void *context, osm_epi_event_id_t event_id, void *event_data)
{
	/* TODO: something amazing */
}

static void *core_construct(osm_opensm_t *opensm)
{
	struct ssa_svc *svc;
	int d, p, ret;

	ret = ssa_init(&ssa, SSA_NODE_CORE, sizeof(struct ssa_device),
			sizeof(struct ssa_port));
	if (ret)
		return NULL;

	/* TODO: ssa_set_options(); */
	ssa_set_log_level(SSA_LOG_ALL);
	if (ssa_open_lock_file(lock_file))
		goto err1;

	ssa_open_log(log_file);
	ssa_log(SSA_LOG_DEFAULT, "Scalable SA Core - OpenSM Plugin\n");
	ssa_log_options();

	ssa_open_devices(&ssa);
	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			svc = ssa_start_svc(ssa_dev_port(ssa_dev(&ssa, d), p),
					    SSA_DB_PATH_DATA, sizeof(struct ssa_core),
					    core_process_msg);
			if (!svc) {
				ssa_log(SSA_LOG_DEFAULT, "ERROR starting service\n");
				goto err2;
			}
			core_init_svc(svc);
		}
	}

	pthread_create(&ctrl_thread, NULL, core_ctrl_handler, NULL);
	osm = opensm;
	return &ssa;

err2:
	ssa_close_devices(&ssa);
err1:
	ssa_cleanup(&ssa);
	return NULL;
}

static void core_destroy(void *context)
{
	int d, p, s;

	ssa_log(SSA_LOG_DEFAULT, "shutting down\n");
	ssa_ctrl_stop(&ssa);
	pthread_join(ctrl_thread, NULL);

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			for (s = 0; s < ssa_dev_port(ssa_dev(&ssa, d), p)->svc_cnt; s++) {
				core_destroy_svc(ssa_dev_port(ssa_dev(&ssa, d), p)->svc[s]);
			}
		}
	}

	ssa_log(SSA_LOG_CTRL, "closing devices\n");
	ssa_close_devices(&ssa);
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

