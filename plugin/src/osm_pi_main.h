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

#ifndef __OSM_PLUGIN_MAIN_H__
#define __OSM_PLUGIN_MAIN_H__

#include <infiniband/verbs.h>
#include "osm_pi_log.h"
#include "osm_pi_config.h"

/** =========================================================================
 * information about a node which we are managing and is connected in the tree
 */
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
	//enum node_state     node_state; /* from ibssa_mad.h */
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

	/* Thread variables */
	cl_thread_t         thread;
	int                 th_run; /* flag to stop running */
	cl_event_t          wake_up;

	/* house keeping */
	struct opensmssa_config * conf;
	osm_log_t                 log; /* our log */
	osm_opensm_t            * osm; /* pointer to guts of opensm */
};

#endif /* __OSM_PLUGIN_MAIN_H__ */
