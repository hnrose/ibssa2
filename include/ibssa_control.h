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
#include "ibssa_db.h"

/**
 * What about Endianess of the record data?
 * Should we define some flag in these headers to indicate endianess to
 * optimize byte swapping.
 * This could be a config option for the prevalent order to use.
 *
 * "Flush" is there a time when some change is so big that there needs to be a
 * system wide re-read of all the data from the root?
 *    Should this be admin controllable, etc?
 */

/** =========================================================================
 * The folowing is mostly copied directly out of Sean's email.
 * I have added a couple of things with comments since we did not get a chance
 * to discuss this further than item 16
 */

enum msg_id {
	/* tree housekeeping information */
	IBSSA_MSG_ID_CTRL_NODE_STATE,

	/* single request messages */
	IBSSA_MSG_ID_RESOLVE = 0x000000FF,

	/* bulk request messages */
	IBSSA_MSG_ID_QUERY_TABLE_GUIDS = 0xFFFF, /* reserve first 1/2 */
	IBSSA_MSG_ID_QUERY_TABLE_DEF,
	IBSSA_MSG_ID_QUERY_TABLE_DATA,
	IBSSA_MSG_ID_PUBLISH_EPOCH_BUF,
	IBSSA_MSG_ID_QUERY_TRANS_LOG,
	IBSSA_MSG_ID_QUERY_RECORD
};

struct ib_ssa_msg_hdr {
	struct ib_mad_hdr hdr;
	be32_t            msg_id;
	be32_t            msg_len;
	/* RDMA response buffer */
};

struct ib_ssa_rdma_hdr {
	struct ib_ssa_msg_hdr  hdr;
	be64_t                 addr;
	be32_t                 rkey;
	be32_t                 length;
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
#define SSA_MAX_ADDRESS 64
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


/** =========================================================================
 * Bulk request messages
 *
 * Bulk messages all begin with an ib_ssa_rdma_hdr which defines the
 * information for the response to be written to.
 */

/*
 * Query table guids
 * input: <none>
 * output: struct ib_ssa_query_table_guids_data
 * Use: determine what data parent can provide
 */
struct ib_ssa_query_table_guids_data {
	be32_t  table_cnt;
	be32_t  table_guids[0];
};

struct ib_ssa_query_table_guids_msg {
	struct ib_ssa_rdma_hdr hdr;
};

/*
 * Query table definition
 * input: table guid
 * output: struct table_def
 * Use: Debugging, logging, version support
 * Note: The table_def fields are included if responding using a data stream or
 *       if the RDMA write buffer is large enough, otherwise only sizeof(struct
 *       table_def) worth of data is returned.
 *       If we added a field_cnt for each table in query_table_guids then we
 *       would not need this NOTE
 */
struct ib_ssa_query_table_def_msg {
	struct ib_ssa_rdma_hdr hdr;
	be32_t                 guid;
};

/*
 * Query table data
 * input: table guid
 * output: struct table (+ all data if HEADER_ONLY not specified)
 * Use: retrieve an entire copy of all available data
 *      or with header only specified;
 *      Check if data is current, determine size of parent's table
 */
enum ib_ssa_query_table_data_flags {
	IB_SSA_HEADER_ONLY = 1 << 0,
};
struct ib_ssa_query_table_data_msg {
	struct ib_ssa_rdma_hdr hdr;
	be32_t                 guid;
	be32_t                 flags;
};

/*
 * Publish epoch buffer
 * input: epoch address
 * output: write current epoch
 * Use: Exposes epoch buffer to parent.  Parent can update using RDMA writes when changes occur.
 */
struct ib_ssa_publish_epoch_buf_msg {
	struct ib_ssa_rdma_hdr hdr;
};

/*
 * Query transaction log
 * input: start epoch, optional table_guid
 * output: array of transaction logs, latest_epoch for final entry
 * Use: obtain incremental updates potentially for only a single table.
 */
struct ib_ssa_query_trans_log_data {
	be64_t                        latest_epoch;
	be64_t                        trans_cnt;
	struct ib_ssa_trans_log_entry trans[0];
};
struct ib_ssa_query_trans_log_msg {
	struct ib_ssa_rdma_hdr hdr;
	be64_t                 start_epoch;
	be32_t                 table_guid;
};

/*
 * Query record
 * input: table_guid, record_size, record_id
 * output: single record within table
 * Use: get data for incremental update specified in transaction log
 */
/* What about using some sort of scatter/gather here? */
struct ib_ssa_query_record_msg {
	struct ib_ssa_rdma_hdr hdr;
	be32_t                 table_guid;
	be32_t                 record_size;
	be64_t                 record_id;
};

/*
 * Other ideas I think should _not_ be done:
 * Publish table buffer
 * Reason: publishing this means the client is unable to know when the data is
 *         consistent.
 *
 * Publish transaction log
 * Use: Obtain incremental updates.
 */

#endif /* __IBSSA_CONTROL_H__ */

