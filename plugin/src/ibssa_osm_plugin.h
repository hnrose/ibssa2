/*
 * Copyright (c) 2012 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012 Intel Corporation. All rights reserved.
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

#ifndef __IBSSA_OSM_PLUGIN__
#define __IBSSA_OSM_PLUGIN__

#include <infiniband/verbs.h>

/** =========================================================================
 * information about a node which we are managing and is connected in the tree
 */
enum node_state {
	IBSSA_STATE_CONN_REQ,
	IBSSA_STATE_CONNECTED,
	IBSSA_STATE_PARENTED,
	IBSSA_STATE_DISCONNECT_REQ,
};

struct ibssa_node {
	cl_list_item_t      list; /* for children or conn_req list */

	/* parent/child relations */
	struct ibssa_node * primary;
	struct ibssa_node * secondary;
	cl_qlist_t          children;

	/* node information */
	union ibv_gid       port_gid;   /* RID = GID + SID + PKey */
	uint64_t            service_id;
	uint16_t            pkey;
	uint8_t             node_type; /* from ibssa_mad.h */
	uint8_t             ssa_version;

	/* Node state information */
	enum node_state     node_state; /* from ibssa_mad.h */
};

/** =========================================================================
 * Data about the tree (balance information what not...)
 */
struct ibssa_tree {
	cl_map_item_t       map; /* for storage in service_trees */
	struct ibssa_node   self; /* ourselves we are the root of the tree */
	cl_qlist_t          conn_req; /* stores nodes which are in CONN_REQ state */
};

/** =========================================================================
 * Main plugin object
 */
struct ibssa_plugin {
	/* OSM mad layer stuff */
	/* for IB_SSA_CLASS MADs */
	osm_bind_handle_t   qp1_handle;

	cl_qmap_t           service_trees; /* this is a map key'ed by service guid
						of ibssa_tree's */
	cl_thread_t         thread;
	int                 th_run; /* flag to stop running */
	cl_event_t          wake_up;
	osm_opensm_t      * osm; /* pointer to guts of opensm */
};

/* Wrap the OSM_LOG with generics for our purposes */
#define PI_LOG_NONE	OSM_LOG_NONE
#define PI_LOG_ERROR	OSM_LOG_ERROR
#define PI_LOG_INFO	OSM_LOG_INFO
#define PI_LOG_VERBOSE	OSM_LOG_VERBOSE
#define PI_LOG_DEBUG	OSM_LOG_DEBUG
#define PI_LOG_FUNCS	OSM_LOG_FUNCS
#define PI_LOG_FRAMES	OSM_LOG_FRAMES
#define PI_LOG_ROUTING	OSM_LOG_ROUTING
#define PI_LOG_ALL	OSM_LOG_ALL
#define PI_LOG_SYS	OSM_LOG_SYS

#define PI_LOG(pi, level, fmt, ...) OSM_LOG(pi->osm->sm.p_log, level, fmt, ## __VA_ARGS__)
#define PI_LOG_ENTER(pi) OSM_LOG_ENTER(pi->osm->sm.p_log)
#define PI_LOG_EXIT(pi) OSM_LOG_EXIT(pi->osm->sm.p_log)

#endif /* __IBSSA_OSM_PLUGIN__ */

