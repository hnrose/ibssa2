/*
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
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

#ifndef _SSA_CTRL_H
#define _SSA_CTRL_H

#include <linux/types.h>
#include <infiniband/verbs.h>
#include <infiniband/ssa_mad.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ssa_ctrl_msg_type {
	SSA_CTRL_EXIT,
	SSA_CTRL_ACK,
	SSA_CTRL_NACK,
	SSA_CTRL_DEV_EVENT,
	SSA_CTRL_MAD,		/* struct ssa_umad */
	SSA_SA_MAD,		/* struct sa_umad */
	SSA_LISTEN,		/* struct ssa_listen_msg */
	SSA_CONN_REQ,		/* struct ssa_conn_req_msg */
	SSA_CONN_DONE,		/* struct ssa_conn_done_msg */
	SSA_CONN_GONE,		/* struct ssa_conn_done_msg */
	SSA_DB_UPDATE,		/* struct ssa_db_update_msg */
	SSA_DB_QUERY,		/* struct ssa_db_query_msg */
	SSA_DB_UPDATE_PREPARE,	/* struct ssa_db_update_msg */
	SSA_DB_UPDATE_READY	/* struct ssa_db_update_msg */
};

struct ssa_ctrl_msg {
	unsigned int		len;
	enum ssa_ctrl_msg_type	type;
	uint8_t			data[0];
};

struct ssa_ctrl_dev_event_msg {
	struct ssa_ctrl_msg	hdr;
	enum ibv_event_type	event;
};

struct ssa_ctrl_umad_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_umad		umad;
};

struct ssa_listen_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_svc		*svc;
};

struct ssa_conn_req_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_svc		*svc;
};

struct ssa_conn_done_payload {
	int			rsock;
	int			type;
	int 			dbtype;
	union ibv_gid		remote_gid;
	uint16_t		remote_lid;
};

struct ssa_conn_done_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_conn_done_payload data;
};

enum ssa_db_update_flag {
	SSA_DB_UPDATE_CHANGE		= (1 << 0)
};

struct ssa_db_update {
	struct ssa_db		*db;
	struct ssa_svc		*svc;
	union ibv_gid		remote_gid;
	int			rsock;
	int			flags;
	uint64_t		epoch;
	uint16_t		remote_lid;
};

struct ssa_db_update_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_db_update	db_upd;
};

enum ssa_db_query_msg_status {
	SSA_DB_QUERY_EPOCH_CHANGED,
	SSA_DB_QUERY_EPOCH_NOT_CHANGED,
	SSA_DB_QUERY_NO_UPSTREAM_CONN
};

struct ssa_db_query_msg {
	struct ssa_ctrl_msg	hdr;
	int			status;
};

struct ssa_ctrl_msg_buf {
	struct ssa_ctrl_msg	hdr;
	union {
		enum ibv_event_type	event;
		struct ssa_umad		umad;
		struct sa_umad		umad_sa;
		struct ssa_svc		*svc;
		struct ssa_conn_done_payload conn_data;
		struct ssa_db_update	db_upd;
		int			status;
	} data;
};

#ifdef __cplusplus
}
#endif

#endif /* _SSA_CTRL_H */
