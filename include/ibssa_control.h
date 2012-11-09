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

/** =========================================================================
 * The folowing is mostly copied directly out of Sean's email.
 * I have added a couple of things with comments since we did not get a chance
 * to discuss this further than item 16
 */

struct ib_ssa_msg_hdr {
	struct ib_mad_hdr hdr;
	uint32_t          msg_id;
	uint32_t          msg_len;
	/* RDMA response buffer */
};

enum msg_id {
	IBSSA_MSG_ID_PR_QUERY,
};

/* do we need this extra hdr?  Or should eth just be in the standard msg_hdr? */
struct ib_ssa_rdma_hdr {
	struct ib_ssa_msg_hdr  hdr;
	struct eth {
		be64_t                 addr;
		be32_t                 rkey;
		be32_t                 length;
	};
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
	uint32_t                flags;
	uint16_t                type;
	uint16_t                reserved;
	union ib_ssa_ep_info    info;
};

struct ib_ssa_resolve_msg {
	struct ib_ssa_msg_hdr      hdr;
	struct ib_ssa_ep_addr_data data[0];
};

struct ib_ssa_pr_req {
	struct ib_ssa_msg_hdr  hdr;
	union {
		be16_t                  dlid;
		union ibv_gid           dgid;
		struct sockaddr_storage addr;
		char                    node_desc[64];
		char                    hostname[128];
	} addr;
	struct ibv_path_record pr;
};


/** =========================================================================
 * Bulk request messages
 */

/*
 * Query table guids
 * input: none
 * output: Array of available table guids
 * Use: determine what data parent can provide
 */
struct ib_ssa_query_table_guids {
	struct ib_ssa_rdma_hdr hdr;
	uint32_t               table_cnt;
	uint32_t               table_guids[0];
};

/*
 * Query table definition
 * input: table guid
 * output: struct table_def
 * Use: Debugging, logging, version support
 * Note: The table_def fields are included if responding using a data stream or
 *       if the RDMA write buffer is large enough, otherwise only sizeof(struct
 *       table_def) worth of data is returned.
 */

/* Query basic table data
 * input: table guid, epoch
 * output: table guid, epoch, record_cnt, table_size
 * Use: Check if data is current, determine size of parent's table
 */

/*
 * Query all table data
 * input: table guid
 * output: struct table + all data
 * Use: retrieve an entire copy of all available data
 */

/*
 * Publish epoch buffer
 * input: epoch address
 * output: write current epoch
 * Use: Exposes epoch buffer to parent.  Parent can update using RDMA writes when changes occur.
 */

/*
 * Query transaction log
 * Publish transaction log
 * Use: Obtain incremental updates.
 */

#endif /* __IBSSA_CONTROL_H__ */

