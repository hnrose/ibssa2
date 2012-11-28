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

/** =========================================================================
 * Thread to handle requests separate from OpenSM
 */
struct ibssa_thread {
	osm_bind_handle_t   bind_handle; /* QP1 wire up handle */
	cl_thread_t         thread;
};

/** =========================================================================
 * a node which is connected in the tree
 */
struct ibssa_node {
	cl_list_item_t      list;

	/* parent/child relations */
	struct ibssa_node * primary;
	struct ibssa_node * alternate;
	cl_qlist_t          children; /* stores ibssa_node *'s */

	/* node information */
	uint8_t             node_type; /* from ibssa_mad.h */
};

/** =========================================================================
 * Main plugin object
 */
struct ibssa_plugin {
	/* list of nodes connected to tree */
	osm_opensm_t      * osm; /* pointer to guts of opensm */
};

#endif /* __IBSSA_OSM_PLUGIN__ */

