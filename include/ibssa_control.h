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


#ifndef __IBSSA_CONTROL_H__
#define __IBSSA_CONTROL_H__

#include "ibssa_umad.h"


enum node_state {
	IBSSA_STATE_IDLE,
	IBSSA_STATE_JOINING,
	IBSSA_STATE_FATAL_ERROR,
	IBSSA_STATE_ORPHAN,
	IBSSA_STATE_HAVE_PARENT,
	IBSSA_STATE_CONNECTING,
	IBSSA_STATE_CONNECTED,
	IBSSA_STATE_NO_BACKUP,
	IBSSA_STATE_HAVE_BACKUP
};

/**
 * "Flush" is there a time when some change is so big that there needs to be a
 * system wide re-read of all the data from the root?
 *    Should this be admin controllable, etc?
 */

enum msg_id {
	/* tree housekeeping information */
	IBSSA_MSG_ID_CTRL_NODE_STATE,

	/* single request messages */
	IBSSA_MSG_ID_RESOLVE = 0x000000FF,

	/* core database transfer operations */
	IBSSA_MSG_ID_DB_START = 0x10000
};

struct ib_ssa_msg_hdr {
	struct ib_mad_hdr	hdr;
	be32_t			msg_id;
	be32_t			msg_len;
	be64_t			rdma_addr;
	be32_t			rdma_len;
	be32_t			reserved;	/* rdma_key, if needed */
};


/** =========================================================================
 * Single request messages
 */

/**
 * I am torn between doing straight up SA queries and specialized messages below.
 *
 * At first I thought specialized messages but if we follow the standard SA
 * queries it might be more straight forward for others to follow.
 *
 * So what about defining both?  We just need to define queries below as an
 * extension of the standard.
 *
 * Also following on my thoughts on service ID's do we want each of the queries
 * in this file to be a separate service id?
 */

/* I think this data may need to go in another .h file */
union ib_ssa_ep_info {
	uint8_t                 addr[SSA_MAX_ADDRESS];
	uint8_t                 name[SSA_MAX_ADDRESS];
	struct ibv_path_record  path;
};

enum {
	SSA_EP_FLAG_SOURCE = 1<<0,
	SSA_EP_FLAG_DEST   = 1<<1
};

struct ib_ssa_ep_addr_data {
	be32_t                  flags;
	be16_t                  type;
	be16_t                  reserved;
	union ib_ssa_ep_info    info;
};

/* This is the message we want to define in this .h */
struct ib_ssa_resolve_msg {
	struct ib_ssa_msg_hdr      hdr;
	struct ib_ssa_ep_addr_data data[0];
};

enum {
	IBSSA_NODE_ACTIVE       = 0,
	IBSSA_NODE_UNRESPONSIVE = 1
};
struct ib_ssa_ctrl_node_state {
	/* information about the node we are reporting on */
	union ibv_gid port_gid;		/* RID = GID + SID + PKey */
	be64_t        service_id;
	be16_t        pkey;
	uint8_t       node_state;
};


#endif /* __IBSSA_CONTROL_H__ */

