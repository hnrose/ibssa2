/*
 * Copyright (c) 2012-2014 Mellanox Technologies LTD. All rights reserved.
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

#include <limits.h>
#include <infiniband/osm_headers.h>
#include <search.h>
#include <common.h>
#include <infiniband/ssa_mad.h>
#include <infiniband/ssa_extract.h>
#include <infiniband/ssa_comparison.h>
#include <ssa_ctrl.h>
#include <ssa_log.h>
#include <infiniband/ssa_db_helper.h>

#define INITIAL_SUBNET_UP_DELAY 500000		/* 500 msec */

/*
 * Service options - may be set through ibssa_opts.cfg file.
 */
static char *opts_file = RDMA_CONF_DIR "/" SSA_OPTS_FILE;
static int node_type = SSA_NODE_CORE;
int smdb_deltas = 0;
static char log_file[128] = "/var/log/ibssa.log";
static char lock_file[128] = "/var/run/ibssa.pid";
#if defined(SIM_SUPPORT) || defined(SIM_SUPPORT_SMDB)
static char *smdb_lock_file = "ibssa_smdb.lock";
static int smdb_lock_fd = -1;
#endif

extern int accum_log_file;
extern int smdb_dump;
extern int prdb_dump;
extern char smdb_dump_dir[128];
extern char prdb_dump_dir[128];
extern short smdb_port;
extern short prdb_port;
extern int keepalive;
extern int sock_accessextract[2];

int first = 1;

/* Used for primary/secondary state to properly maintain number of children */
enum {
	SSA_CHILD_IDLE		= 0,
	SSA_CHILD_PARENTED	= (1 << 0)
};

struct ssa_member {
	struct ssa_member_record	rec;
	struct ssa_member		*primary;	/* parent */
	struct ssa_member		*secondary;	/* parent */
	int				primary_state;
	int				secondary_state;
	uint16_t			lid;
	uint8_t				sl;
	int				child_num;
	int				access_child_num; /* used when combined or access node type */
	DLIST_ENTRY			child_list;
	DLIST_ENTRY			access_child_list; /* used when combined or access node type */
	DLIST_ENTRY			entry;
	DLIST_ENTRY			access_entry;
};

struct ssa_core {
	struct ssa_svc			svc;
	void				*member_map;
	DLIST_ENTRY			orphan_list;
	DLIST_ENTRY			core_list;
	DLIST_ENTRY			distrib_list;
	DLIST_ENTRY			access_list;
};

static struct ssa_class ssa;
struct ssa_database *ssa_db;
static struct ssa_db_diff *ssa_db_diff = NULL;
pthread_mutex_t ssa_db_diff_lock;
pthread_t ctrl_thread, extract_thread;
static osm_opensm_t *osm;

static int sock_coreextract[2];

#ifndef SIM_SUPPORT
/* Should the following two DList routines go into a new dlist.c in shared ? */
static DLIST_ENTRY *DListFind(DLIST_ENTRY *entry, DLIST_ENTRY *list)
{
	DLIST_ENTRY *cur_entry;

	for (cur_entry = list->Next; cur_entry != list;
	     cur_entry = cur_entry->Next) {
		if (cur_entry == entry)
			return entry;
	}
	return NULL;
}

static int DListCount(DLIST_ENTRY *list)
{
	DLIST_ENTRY *entry;
	int count = 0;

	for (entry = list->Next; entry != list; entry = entry->Next)
		count++;
	return count;
}

/*
 * Current algorithm for find_best_parent is to merely balance
 * the number of children when a new join arrives at the
 * core.
 *
 * There is join order dependency in the current algorithm.
 * The current assumption is that distribution tree (core,
 * distribution, and access nodes) come up prior to compute
 * nodes.
 *
 * Note that there is currently no rebalancing. Balancing
 * only occurs on join to subnet and not on leaves from subnet.
 * This will be further investigated when fault/error handling
 * is added. Also, there is no way currently for the core
 * to request that a downstream node switchover to new parent.
 * Also, a way for downstream node to request a reparent may
 * also be needed.
 *
 * For now, if the child is an access node and there is no
 * distribution node, the parent will be the core node. This
 * may change depending on how reconnection ends up working.
 *
 * Also, for now, if child is consumer node and there is no
 * access node, this is an error.
 *
 * Subsequent version may be based on some maximum number of hops
 * allowed between child and parent but this requires similar
 * expensive calculations like routing.
 *
 * A simpler approach would be to support a configuration file for this.
 *
 * Another mechanism to influence the algorithm is weighting for
 * combined nodes so these handler fewer access nodes than a "pure"
 * access node when subnet has a mix of such nodes.
 */
static union ibv_gid *find_best_parent(struct ssa_core *core,
				       struct ssa_member *child)
{
	struct ssa_svc *svc;
	DLIST_ENTRY *list, *entry;
	struct ssa_member *member;
	union ibv_gid *parentgid;
	int least_child_num;
	uint8_t node_type;

	if (child->primary)
		return (union ibv_gid *) child->primary->rec.port_gid;

	svc = &core->svc;
	node_type = child->rec.node_type;

	switch (node_type) {
	case SSA_NODE_CORE:
	case SSA_NODE_DISTRIBUTION:
	case (SSA_NODE_CORE | SSA_NODE_ACCESS):
	case (SSA_NODE_DISTRIBUTION | SSA_NODE_ACCESS):
		list = NULL;
		parentgid = &svc->port->gid;
		break;
	case SSA_NODE_ACCESS:
		/* If no distribution nodes yet, parent is core */
		if (DListCount(&core->distrib_list))
			list = &core->distrib_list;
		else {
			list = NULL;
			parentgid = &svc->port->gid;
		}
		break;
	case SSA_NODE_CONSUMER:
		/* If child is consumer, parent is access */
		list = &core->access_list;
		break;
	}

	if (list) {
		least_child_num = INT_MAX;
		parentgid = NULL;
		for (entry = list->Next; entry != list; entry = entry->Next) {
			if (node_type == SSA_NODE_CONSUMER) {
				member = container_of(entry, struct ssa_member,
						      access_entry);
				if (member->access_child_num < least_child_num) {
					parentgid = (union ibv_gid *) member->rec.port_gid;
					least_child_num = member->access_child_num;
					if (!least_child_num)
						break;
				}
			} else {
				member = container_of(entry, struct ssa_member,
						      entry);
				if (member->child_num < least_child_num) {
					parentgid = (union ibv_gid *) member->rec.port_gid;
					least_child_num = member->child_num;
					if (!least_child_num)
						break;
				}
			}
		}
	}
	return parentgid;
}

static int core_build_tree(struct ssa_core *core, struct ssa_member *child)
{
	struct ssa_svc *svc = &core->svc;
	union ibv_gid *gid = (union ibv_gid *) child->rec.port_gid;
	union ibv_gid *parentgid;
	int ret = -1;
	uint8_t node_type = child->rec.node_type;

	switch (node_type) {
	case SSA_NODE_DISTRIBUTION:
	case (SSA_NODE_DISTRIBUTION | SSA_NODE_ACCESS):
		parentgid = find_best_parent(core, child);
		if (parentgid)
			ret = ssa_svc_query_path(svc, parentgid, gid);
		if (parentgid && !ret) {
			if (!DListFind(&child->entry, &core->distrib_list))
				DListInsertBefore(&child->entry,
						  &core->distrib_list);
			if (node_type & SSA_NODE_ACCESS) {
				if (!DListFind(&child->access_entry,
					       &core->access_list))
					DListInsertBefore(&child->access_entry,
							  &core->access_list);
			}
		}
		break;
	case SSA_NODE_ACCESS:
		parentgid = find_best_parent(core, child);
		if (parentgid)
			ret = ssa_svc_query_path(svc, parentgid, gid);
		if (parentgid && !ret &&
		    !DListFind(&child->access_entry, &core->access_list))
			DListInsertBefore(&child->access_entry,
					  &core->access_list);
		break;
	case (SSA_NODE_CORE | SSA_NODE_ACCESS):
	case SSA_NODE_CORE:
		/* TODO: Handle standby SM nodes */
		parentgid = find_best_parent(core, child);
		if (parentgid)
			ret = ssa_svc_query_path(svc, parentgid, gid);
		if (parentgid && !ret) {
			if (!DListFind(&child->entry, &core->core_list))
				DListInsertBefore(&child->entry, &core->core_list);
			if ((node_type & SSA_NODE_ACCESS) &&
			    (!DListFind(&child->access_entry,
					&core->access_list))) {
				DListInsertBefore(&child->access_entry,
						  &core->access_list);
			}
		}
		break;
	case SSA_NODE_CONSUMER:
		parentgid = find_best_parent(core, child);
		if (parentgid)
			ret = ssa_svc_query_path(svc, parentgid, gid);
		else
			ssa_log_err(SSA_LOG_CTRL,
				    "no access node joined as yet\n");
		break;
	}
	return ret;
}

static void core_update_tree(struct ssa_core *core, struct ssa_member *child,
			     union ibv_gid *gid)
{
	struct ssa_member_record *rec;
	struct ssa_member *parent;
	uint8_t **tgid;
	uint8_t node_type;

	if (!child)
		return;

	/*
	 * Find parent of child being removed from tree and
	 * update the number of children.
	 *
	 * No way to force children to reconnect currently.
	 */
	node_type = child->rec.node_type;
	if (node_type & SSA_NODE_CORE)
		return;
	if (!child->primary) {
		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &child->rec.port_gid,
				sizeof child->rec.port_gid);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - no parent for GID %s\n", log_data);
		return;
	}

	/* Should something else be done with children whose parent goes away ? */
	tgid = tfind(&child->rec.port_gid, &core->member_map, ssa_compare_gid);
	if (!tgid) {
		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &child->rec.port_gid,
				sizeof child->rec.port_gid);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - couldn't find parent for GID %s\n", log_data);
		return;
	}
	rec = container_of(*tgid, struct ssa_member_record, port_gid);
	parent = container_of(rec, struct ssa_member, rec);
	if (node_type & SSA_NODE_CONSUMER)
		parent->access_child_num--;
	else
		parent->child_num--;
	child->primary = NULL;
	child->primary_state = SSA_CHILD_IDLE;
}

/*
 * Process received SSA membership requests.  On errors, we simply drop
 * the request and let the remote node retry.
 */
static void core_process_join(struct ssa_core *core, struct ssa_umad *umad)
{
	struct ssa_member_record *rec;
	struct ssa_member *member;
	uint8_t **tgid;
	int ret;

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
		DListInit(&member->child_list);
		DListInit(&member->access_child_list);
		if (!tsearch(&member->rec.port_gid, &core->member_map, ssa_compare_gid)) {
			free(member);
			return;
		}
	} else {
		rec = container_of(*tgid, struct ssa_member_record, port_gid);
		member = container_of(rec, struct ssa_member, rec);
	}

	ssa_log(SSA_LOG_CTRL, "sending join response\n");
	umad->packet.mad_hdr.method = UMAD_METHOD_GET_RESP;
	umad_send(core->svc.port->mad_portid, core->svc.port->mad_agentid,
		  (void *) umad, sizeof umad->packet, 0, 0);

	/*
	 * TODO: Really need to wait for first SUBNET UP event.
	 * Just a one time artificial delay for now.
	 */
	if (first) {
		usleep(INITIAL_SUBNET_UP_DELAY);
		first = 0;
	}

	ret = core_build_tree(core, member);
	if (ret) {
		ssa_log(SSA_LOG_CTRL, "core_build_tree failed %d\n", ret);
		/* member is orphaned */
		DListInsertBefore(&member->entry, &core->orphan_list);
	}
}

static void core_process_leave(struct ssa_core *core, struct ssa_umad *umad)
{
	struct ssa_member_record *rec;
	struct ssa_member *member;
	uint8_t **tgid;
	DLIST_ENTRY *entry;
	uint8_t node_type;

	rec = (struct ssa_member_record *) &umad->packet.data;
	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, rec->port_gid, sizeof rec->port_gid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", core->svc.name, log_data);

	tgid = tfind(rec->port_gid, &core->member_map, ssa_compare_gid);
	if (!tgid)
		core_update_tree(core, NULL, (union ibv_gid *) rec->port_gid);
	else {
		ssa_log(SSA_LOG_CTRL, "removing member\n");
		rec = container_of(*tgid, struct ssa_member_record, port_gid);
		member = container_of(rec, struct ssa_member, rec);
		entry = DListFind(&member->entry, &core->orphan_list);
		if (entry) {
			ssa_log(SSA_LOG_CTRL, "in orphan list\n");
			DListRemove(&member->entry);
		}
		node_type = member->rec.node_type;
		if (node_type & SSA_NODE_CORE) {
			entry = DListFind(&member->entry, &core->core_list);
			if (entry) {
				ssa_log(SSA_LOG_CTRL, "in core list\n");
				DListRemove(&member->entry);	
			}
		}
		if (node_type & SSA_NODE_DISTRIBUTION) {
			entry = DListFind(&member->entry, &core->distrib_list);
			if (entry) {
				ssa_log(SSA_LOG_CTRL, "in distrib list\n");
				DListRemove(&member->entry);
			}
		}
		if (node_type & SSA_NODE_ACCESS) {
			entry = DListFind(&member->access_entry,
					  &core->access_list);
			if (entry) {
				ssa_log(SSA_LOG_CTRL, "in access list\n");
				DListRemove(&member->access_entry);
			}
		}
		core_update_tree(core, member, (union ibv_gid *) rec->port_gid);
		tdelete(rec->port_gid, &core->member_map, ssa_compare_gid);
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
	struct uint8_t **childgid, **parentgid;
	struct ssa_member_record *rec;
	struct ssa_member *child, *parent;
	struct ssa_umad umad_sa;
	int ret;

	path = (struct ibv_path_record *) &umad->packet.data;
	ssa_sprint_addr(SSA_LOG_VERBOSE | SSA_LOG_CTRL, log_data, sizeof log_data,
			SSA_ADDR_GID, (uint8_t *) &path->sgid, sizeof path->sgid);
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s %s\n", core->svc.name, log_data);

	/* Joined port GID is SGID in PathRecord */
	childgid = tfind(&path->sgid, &core->member_map, ssa_compare_gid);
	if (!childgid) {
		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &path->sgid, sizeof path->sgid);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - couldn't find joined port GID %s\n", log_data);
		return;
	}
	rec = container_of(*childgid, struct ssa_member_record, port_gid);
	child = container_of(rec, struct ssa_member, rec);

	parentgid = tfind(&path->dgid, &core->member_map, ssa_compare_gid);
	if (parentgid) {
		rec = container_of(*parentgid, struct ssa_member_record, port_gid);
		parent = container_of(rec, struct ssa_member, rec);
		child->primary = parent;
		if (child->rec.node_type == SSA_NODE_CONSUMER) {
			if (!(child->primary_state & SSA_CHILD_PARENTED))
				parent->access_child_num++;
		} else if ((child->rec.node_type & SSA_NODE_CORE) !=
			 SSA_NODE_CORE) {
			if (!(child->primary_state & SSA_CHILD_PARENTED))
				parent->child_num++;
		}
		child->primary_state |= SSA_CHILD_PARENTED;

		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
				log_data, sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &path->dgid, sizeof path->dgid); 
		ssa_log(SSA_LOG_DEFAULT,
			"child node type %d parent GID %s children %d access children %d\n",
			child->rec.node_type, log_data, parent->child_num,
			parent->access_child_num);

	} else {
		child->primary = NULL;
		child->primary_state = SSA_CHILD_IDLE;
		ssa_sprint_addr(SSA_LOG_DEFAULT | SSA_LOG_CTRL, log_data,
				sizeof log_data, SSA_ADDR_GID,
				(uint8_t *) &path->dgid, sizeof path->dgid);
		ssa_log(SSA_LOG_DEFAULT | SSA_LOG_CTRL,
			"ERROR - couldn't find parent GID %s\n", log_data);
	}

	/*
	 * TODO: SL should come from another PathRecord between core
	 * and joined client.
	 *
	 * In prototype, since core is coresident with SM, this is SL
	 * from the PathRecord between the client and the parent
	 * since the (only) parent is the core.
	 */
	child->sl = ntohs(path->qosclass_sl) & 0xF;

	memset(&umad_sa, 0, sizeof umad_sa);
	umad_set_addr(&umad_sa.umad, child->lid, 1, child->sl, UMAD_QKEY);
	core_init_parent(core, &umad_sa.packet, &child->rec, path);

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
	if (umad_sa->umad.status) {
		ssa_log(SSA_LOG_DEFAULT,
			"SA MAD method 0x%x attribute 0x%x received with status 0x%x\n",
			umad_sa->packet.mad_hdr.method,
			ntohs(umad_sa->packet.mad_hdr.attr_id),
			umad_sa->umad.status);
		return 0;
	}

	core = container_of(svc, struct ssa_core, svc);

	switch (umad_sa->packet.mad_hdr.method) {
	case UMAD_METHOD_GET_RESP:
		if (ntohs(umad_sa->packet.mad_hdr.attr_id) == UMAD_SA_ATTR_PATH_REC) {
			core_process_path_rec(core, umad_sa);
			return 1;
		}
		break;
	default:
		ssa_log(SSA_LOG_DEFAULT,
			"SA MAD method 0x%x attribute 0x%x not expected\n",
			umad_sa->packet.mad_hdr.method,
			ntohs(umad_sa->packet.mad_hdr.attr_id));
		break;
	}

	return 0;
}

static int core_process_ssa_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_core *core;
	struct ssa_umad *umad;

	umad = &msg->data.umad;
	if (umad->umad.status) {
		ssa_log(SSA_LOG_DEFAULT,
			"SSA MAD method 0x%x attribute 0x%x received with status 0x%x\n",
			umad->packet.mad_hdr.method,
			ntohs(umad->packet.mad_hdr.attr_id), umad->umad.status);
		return 1;	/* rerequest ? */
	}

	core = container_of(svc, struct ssa_core, svc);

	switch (umad->packet.mad_hdr.method) {
	case UMAD_METHOD_SET:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_MEMBER_REC) {
			core_process_join(core, umad);
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
		ssa_log(SSA_LOG_DEFAULT,
			"SSA MAD method 0x%x attribute 0x%x not expected\n",
			umad->packet.mad_hdr.method,
			ntohs(umad->packet.mad_hdr.attr_id));
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
	case SSA_CTRL_DEV_EVENT:
		break;
	default:
		ssa_log_warn(SSA_LOG_CTRL,
			     "ignoring unexpected message type %d\n",
			     msg->hdr.type);
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
	DListInit(&core->core_list);
	DListInit(&core->distrib_list);
	DListInit(&core->access_list);
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
#endif

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

#ifndef SIM_SUPPORT
static void ssa_extract_send_db_update(struct ref_count_obj *db,
				       int fd, int flags)
{
#ifndef CORE_INTEGRATION
	struct ssa_db *ssa_db;
	struct ssa_db_update_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	msg.hdr.type = SSA_DB_UPDATE;
	msg.hdr.len = sizeof(msg);
	msg.db_upd.db = db;
	msg.db_upd.svc = NULL;
	msg.db_upd.flags = flags;
	ssa_db = ref_count_object_get(db);
	msg.db_upd.epoch = ssa_db_get_epoch(ssa_db, DB_DEF_TBL_ID);
	write(fd, (char *) &msg, sizeof(msg));
#endif
}

static void ssa_extract_db_update(struct ref_count_obj *db)
{
	struct ssa_svc *svc;
	int d, p, s;

	if (!db)
		return;

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			for (s = 0; s < ssa_dev_port(ssa_dev(&ssa, d), p)->svc_cnt; s++) {
				svc = ssa_dev_port(ssa_dev(&ssa, d), p)->svc[s];
				ssa_extract_send_db_update(db,
							   svc->sock_extractdown[1], 0);
			}
		}
	}

	if (ssa.node_type & SSA_NODE_ACCESS)
		ssa_extract_send_db_update(db, sock_accessextract[0], 0);

}
#endif

#ifdef SIM_SUPPORT_SMDB
static int
ssa_extract_load_smdb(struct ssa_db *p_smdb, struct timespec *last_mtime)
{
	struct ref_count_obj *db;
	struct stat smdb_dir_stats;
	int ret;

	if (!smdb_dump)
		return 0;

	ret = lockf(smdb_lock_fd, F_TLOCK, 0);
	if (ret) {
		if ((errno == EACCES) || (errno == EAGAIN)) {
			ssa_log_warn(SSA_LOG_VERBOSE,
				"smdb lock file is locked\n");
			return 0;
		} else {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "locking smdb lock file ERROR %d (%s)\n",
				    errno, strerror(errno));
			return -1;
		}
	}

	ret = stat(smdb_dump_dir, &smdb_dir_stats);
	if (ret < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to get SMDB directory stats\n");
		lockf(smdb_lock_fd, F_ULOCK, 0);
		return -1;
	}

	if (memcmp(&smdb_dir_stats.st_mtime, last_mtime, sizeof(*last_mtime))) {
		if (p_smdb)
			ssa_db_destroy(p_smdb);
		p_smdb = ssa_db_load(smdb_dump_dir, smdb_dump);
		db = malloc(sizeof(*db));
		if (db) {
			ref_count_obj_init(db, p_smdb);
			ssa_extract_db_update(db);
			memcpy(last_mtime, &smdb_dir_stats.st_mtime,
			       sizeof(*last_mtime));
		}
	}

	lockf(smdb_lock_fd, F_ULOCK, 0);

	return 0;
}
#endif

static void *core_extract_handler(void *context)
{
	osm_opensm_t *p_osm = (osm_opensm_t *) context;
	struct ssa_db *p_smdb = NULL;
	struct pollfd pfds[1];
	struct ssa_db_ctrl_msg msg;
	uint64_t epoch_prev = 0;
	int ret, timeout_msec = -1;
#ifdef SIM_SUPPORT_SMDB
	struct timespec smdb_last_mtime;
	struct ssa_db *p_smdb2 = NULL;

	timeout_msec = 1000;	/* 1 sec */
	memset(&smdb_last_mtime, 0, sizeof(smdb_last_mtime));
#endif

	pfds[0].fd	= sock_coreextract[1];
	pfds[0].events	= POLLIN;
	pfds[0].revents = 0;

	ssa_log(SSA_LOG_VERBOSE, "Starting smdb extract thread\n");

	for (;;) {
		ret = poll(pfds, 1, timeout_msec);
		if (ret < 0) {
			ssa_log(SSA_LOG_VERBOSE, "ERROR polling fds\n");
			continue;
		}

#ifdef SIM_SUPPORT_SMDB
		if (!ret) {
			if (ssa_extract_load_smdb(p_smdb2, &smdb_last_mtime) < 0)
				goto out;
			continue;
		}
#endif

		if (pfds[0].revents) {
			pfds[0].revents = 0;
			read(sock_coreextract[1], (char *) &msg, sizeof(msg));
			switch (msg.type) {
			case SSA_DB_START_EXTRACT:
				CL_PLOCK_ACQUIRE(&p_osm->lock);
				ssa_db->p_dump_db = ssa_db_extract(p_osm);
				ssa_db_lft_handle();
				CL_PLOCK_RELEASE(&p_osm->lock);

				/* For validation */
				ssa_db_validate(ssa_db->p_dump_db);
				ssa_db_validate_lft();

				/* Update SMDB versions */
				ssa_db_update(ssa_db);

				pthread_mutex_lock(&ssa_db_diff_lock);
				/* Clear previous version */
				if (ssa_db_diff) {
					p_smdb = ref_count_object_get(ssa_db_diff->p_smdb);
					epoch_prev = ssa_db_get_epoch(p_smdb,
								      DB_DEF_TBL_ID);
				}

				ssa_db_diff_destroy(ssa_db_diff);

				ssa_db_diff = ssa_db_compare(ssa_db, epoch_prev);
				if (ssa_db_diff) {
					ssa_log(SSA_LOG_VERBOSE,
						"SMDB was changed. Pushing the changes...\n");
					p_smdb = ref_count_object_get(ssa_db_diff->p_smdb);
					/*
					 * TODO: use 'ssa_db_get_epoch(p_smdb, DB_DEF_TBL_ID)'
					 * for getting current epoch and sending it to children nodes.
					 */
#ifdef SIM_SUPPORT
					if (smdb_dump && !lockf(smdb_lock_fd, F_LOCK, 0)) {
						ssa_db_save(smdb_dump_dir,
							    p_smdb,
							    smdb_dump);
						lockf(smdb_lock_fd, F_ULOCK, 0);
					}
#else
					if (smdb_dump)
						ssa_db_save(smdb_dump_dir,
							    p_smdb,
							    smdb_dump);

					ssa_extract_db_update(ssa_db_diff->p_smdb);
#endif

				}
				pthread_mutex_unlock(&ssa_db_diff_lock);
				first = 0;
				break;
			case SSA_DB_LFT_CHANGE:
				ssa_log(SSA_LOG_VERBOSE,
					"Start handling LFT change event\n");
				ssa_db_lft_handle();
				break;
			case SSA_DB_EXIT:
				goto out;
			default:
				ssa_log(SSA_LOG_VERBOSE,
					"ERROR: Unknown msg type %d from extract\n",
					msg.type);
				break;
			}
		}
	}
out:
	ssa_log(SSA_LOG_VERBOSE, "Exiting smdb extract thread\n");
	pthread_exit(NULL);
}

static void core_send_msg(enum ssa_db_ctrl_msg_type type)
{
	struct ssa_db_ctrl_msg msg;

	ssa_log_func(SSA_LOG_CTRL);
	ssa_log(SSA_LOG_VERBOSE,
		"Sending msg type %d from core to extract thread\n", type);
	msg.len = sizeof(msg);
	msg.type = type;
	write(sock_coreextract[0], (char *) &msg, sizeof(msg));
}

#ifndef SIM_SUPPORT_SMDB
static void core_process_lft_change(osm_epi_lft_change_event_t *p_lft_change)
{
	struct ssa_db_lft_change_rec *p_lft_change_rec;
	size_t size;

	if (!p_lft_change || !p_lft_change->p_sw)
		return;

	ssa_log(SSA_LOG_VERBOSE, "LFT change event for switch GUID 0x%" PRIx64"\n",
		ntohll(osm_node_get_node_guid(p_lft_change->p_sw->p_node)));

	size = sizeof(*p_lft_change_rec);
	if (p_lft_change->flags == LFT_CHANGED_BLOCK)
		size += sizeof(p_lft_change_rec->block[0]) * UMAD_LEN_SMP_DATA;

	p_lft_change_rec = (struct ssa_db_lft_change_rec *) malloc(size);
	if (!p_lft_change_rec) {
		/* TODO: handle failure in memory allocation */
	}

	memcpy(&p_lft_change_rec->lft_change, p_lft_change,
	       sizeof(p_lft_change_rec->lft_change));
	p_lft_change_rec->lid = osm_node_get_base_lid(p_lft_change->p_sw->p_node, 0);

	if (p_lft_change->flags == LFT_CHANGED_BLOCK)
		memcpy(p_lft_change_rec->block, p_lft_change->p_sw->lft +
		       p_lft_change->block_num * UMAD_LEN_SMP_DATA,
		       UMAD_LEN_SMP_DATA);

	pthread_mutex_lock(&ssa_db->lft_rec_list_lock);
	cl_qlist_insert_tail(&ssa_db->lft_rec_list, &p_lft_change_rec->list_item);
	pthread_mutex_unlock(&ssa_db->lft_rec_list_lock);

	core_send_msg(SSA_DB_LFT_CHANGE);
}
#endif

#ifdef SIM_SUPPORT_SMDB
static void core_report(void *context, osm_epi_event_id_t event_id, void *event_data)
{
	switch (event_id) {
	case OSM_EVENT_ID_TRAP:
		handle_trap_event((ib_mad_notice_attr_t *) event_data);
		break;
	case OSM_EVENT_ID_LFT_CHANGE:
		ssa_log(SSA_LOG_VERBOSE, "LFT change event\n");
		break;
	case OSM_EVENT_ID_UCAST_ROUTING_DONE:
		ssa_log(SSA_LOG_VERBOSE, "Ucast routing done event\n");
		break;
	case OSM_EVENT_ID_SUBNET_UP:
		ssa_log(SSA_LOG_VERBOSE, "Subnet up event\n");
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
#else
static void core_report(void *context, osm_epi_event_id_t event_id, void *event_data)
{
	osm_epi_ucast_routing_flags_t ucast_routing_flag;

	switch (event_id) {
	case OSM_EVENT_ID_TRAP:
		handle_trap_event((ib_mad_notice_attr_t *) event_data);
		break;
	case OSM_EVENT_ID_LFT_CHANGE:
		ssa_log(SSA_LOG_VERBOSE, "LFT change event\n");
		core_process_lft_change((osm_epi_lft_change_event_t *) event_data);
		break;
	case OSM_EVENT_ID_UCAST_ROUTING_DONE:
		ucast_routing_flag = (osm_epi_ucast_routing_flags_t) event_data;
		if (ucast_routing_flag == UCAST_ROUTING_REROUTE) {
			/* We get here in case of subnet re-routing not followed by SUBNET_UP */
			/* TODO: notify the distribution thread and push the LFT changes */
		}
		break;
	case OSM_EVENT_ID_SUBNET_UP:
		/* For now, ignore SUBNET UP events when there is subnet init error */
		if (osm->subn.subnet_initialization_error)
			break;

		ssa_log(SSA_LOG_VERBOSE, "Subnet up event\n");
		core_send_msg(SSA_DB_START_EXTRACT);
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
#endif

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
		else if (!strcasecmp("accum_log_file", opt))
			accum_log_file = atoi(value);
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("smdb_dump_dir", opt))
			strcpy(smdb_dump_dir, value);
		else if (!strcasecmp("prdb_dump_dir", opt))
			strcpy(prdb_dump_dir, value);
		else if (!strcasecmp("node_type", opt))
			node_type = core_convert_node_type(value);
		else if (!strcasecmp("smdb_port", opt))
			smdb_port = (short) atoi(value);
		else if (!strcasecmp("prdb_port", opt))
			prdb_port = (short) atoi(value);
		else if (!strcasecmp("smdb_dump", opt))
			smdb_dump = atoi(value);
		else if (!strcasecmp("prdb_dump", opt))
			prdb_dump = atoi(value);
		else if (!strcasecmp("smdb_deltas", opt))
			smdb_deltas = atoi(value);
		else if (!strcasecmp("keepalive", opt))
			keepalive = atoi(value);
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
	ssa_log(SSA_LOG_DEFAULT, "config file %s\n", opts_file);
	ssa_log(SSA_LOG_DEFAULT, "lock file %s\n", lock_file);
	ssa_log(SSA_LOG_DEFAULT, "node type %d (%s)\n", node_type,
		core_node_type_str(node_type));
	ssa_log(SSA_LOG_DEFAULT, "smdb port %u\n", smdb_port);
	ssa_log(SSA_LOG_DEFAULT, "prdb port %u\n", prdb_port);
	ssa_log(SSA_LOG_DEFAULT, "smdb dump %d\n", smdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "smdb dump dir %s\n", smdb_dump_dir);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump %d\n", prdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump dir %s\n", prdb_dump_dir);
	ssa_log(SSA_LOG_DEFAULT, "smdb deltas %d\n", smdb_deltas);
	ssa_log(SSA_LOG_DEFAULT, "keepalive time %d\n", keepalive);
#ifdef SIM_SUPPORT_SMDB
	ssa_log(SSA_LOG_DEFAULT, "running in simulated SMDB operation mode\n");
#endif
}

static void *core_construct(osm_opensm_t *opensm)
{
#ifndef SIM_SUPPORT
	struct ssa_svc *svc;
	int d, p;
#endif
	int ret;
#if defined(SIM_SUPPORT) || defined (SIM_SUPPORT_SMDB)
	int i;
	char buf[PATH_MAX];
#endif

	core_set_options();
	ret = ssa_init(&ssa, node_type, sizeof(struct ssa_device),
			sizeof(struct ssa_port));
	if (ret)
		return NULL;

	ssa_open_log(log_file);
	ssa_log(SSA_LOG_DEFAULT, "Scalable SA Core - OpenSM Plugin\n");
	core_log_options();

#if defined(SIM_SUPPORT) || defined (SIM_SUPPORT_SMDB)
	snprintf(buf, PATH_MAX, "%s", smdb_dump_dir);
	for (i = strlen(buf); i > 0; i--) {
		if (buf[i] == '/') {
			buf[++i] = '\0';
			break;
		}
	}
	snprintf(buf + i, PATH_MAX - strlen(buf), "%s", smdb_lock_file);
	smdb_lock_fd = open(buf, O_RDWR | O_CREAT, 0640);
	if (smdb_lock_fd < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "can't open smdb lock file: %s\n", buf);
		goto err1;
	}
#else
	if (ssa_open_lock_file(lock_file)) {
		ssa_log(SSA_LOG_DEFAULT, "can't open lock file: %s\n", lock_file);
		goto err1;
	}
#endif

	ssa_db = ssa_database_init();
	if (!ssa_db) {
		ssa_log(SSA_LOG_ALL, "SSA database init failed\n");
		goto err2;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_coreextract);
	if (ret) {
		ssa_log(SSA_LOG_ALL, "ERROR %d (%s): creating socketpair\n",
			errno, strerror(errno));
		goto err3;
	}

	pthread_mutex_init(&ssa_db_diff_lock, NULL);

#ifndef SIM_SUPPORT
	ret = ssa_open_devices(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR opening devices\n");
		goto err4;
	}

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			svc = ssa_start_svc(ssa_dev_port(ssa_dev(&ssa, d), p),
					    SSA_DB_PATH_DATA, sizeof(struct ssa_core),
					    core_process_msg);
			if (!svc) {
				ssa_log(SSA_LOG_DEFAULT, "ERROR starting service\n");
				goto err5;
			}
			core_init_svc(svc);
		}
	}

	ret = ssa_start_access(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR starting access thread\n");
		goto err5;
	}
#endif

	ret = pthread_create(&extract_thread, NULL, core_extract_handler,
			     (void *) opensm);
	if (ret) {
		ssa_log(SSA_LOG_ALL,
			"ERROR %d (%s): error creating smdb extract thread\n",
			ret, strerror(ret));
		goto err6;
	}

#ifndef SIM_SUPPORT
	ret = pthread_create(&ctrl_thread, NULL, core_ctrl_handler, NULL);
	if (ret) {
		ssa_log(SSA_LOG_ALL,
			"ERROR %d (%s): error creating core ctrl thread\n",
			ret, strerror(ret));
		goto err7;
	}
#endif

	osm = opensm;
	return &ssa;

#ifndef SIM_SUPPORT
err7:
	core_send_msg(SSA_DB_EXIT);
	pthread_join(extract_thread, NULL);
#endif
err6:
#ifndef SIM_SUPPORT
	ssa_stop_access(&ssa);
err5:
	ssa_close_devices(&ssa);
err4:
#endif
	close(sock_coreextract[0]);
	close(sock_coreextract[1]);
err3:
	ssa_database_delete(ssa_db);
err2:
#if defined(SIM_SUPPORT) || defined (SIM_SUPPORT_SMDB)
	if (smdb_lock_fd >= 0)
		close(smdb_lock_fd);
#endif
err1:
	ssa_cleanup(&ssa);
	return NULL;
}

static void core_destroy(void *context)
{
#ifndef SIM_SUPPORT
	int d, p, s;

	ssa_log(SSA_LOG_DEFAULT, "shutting down control thread\n");
	ssa_ctrl_stop(&ssa);
	pthread_join(ctrl_thread, NULL);
#endif

	ssa_log(SSA_LOG_CTRL, "shutting down smdb extract thread\n");
	core_send_msg(SSA_DB_EXIT);
	pthread_join(extract_thread, NULL);

#ifndef SIM_SUPPORT
	ssa_log(SSA_LOG_CTRL, "shutting down access thread\n");
	ssa_stop_access(&ssa);

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			for (s = 0; s < ssa_dev_port(ssa_dev(&ssa, d), p)->svc_cnt; s++) {
				core_destroy_svc(ssa_dev_port(ssa_dev(&ssa, d), p)->svc[s]);
			}
		}
	}
#endif

	close(sock_coreextract[0]);
	close(sock_coreextract[1]);

#ifndef SIM_SUPPORT
	ssa_log(SSA_LOG_CTRL, "closing devices\n");
	ssa_close_devices(&ssa);
#endif

	pthread_mutex_lock(&ssa_db_diff_lock);
	ssa_db_diff_destroy(ssa_db_diff);
	pthread_mutex_unlock(&ssa_db_diff_lock);
	pthread_mutex_destroy(&ssa_db_diff_lock);

	ssa_log(SSA_LOG_CTRL, "destroying SMDB\n");
	ssa_database_delete(ssa_db);

#if defined(SIM_SUPPORT) || defined(SIM_SUPPORT_SMDB)
	if (smdb_lock_fd >= 0)
		close(smdb_lock_fd);
#endif

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
