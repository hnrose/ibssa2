/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _SSA_ADMIN_H
#define _SSA_ADMIN_H

#include <stdio.h>
#include <infiniband/umad.h>

#define SSA_ADMIN_PROTOCOL_VERSION	1
#define SSA_ADMIN_VERSION_LEN		50

enum {
	SSA_ADMIN_STATUS_SUCCESS = 0,
	SSA_ADMIN_STATUS_FAILURE
};

enum {
	SSA_ADMIN_METHOD_GET	= (1 << 0),
	SSA_ADMIN_METHOD_SET	= (1 << 1),
	SSA_ADMIN_METHOD_RESP	= (1 << 2)
};

enum {
	SSA_ADMIN_CMD_NONE,
	SSA_ADMIN_CMD_STATS,
	SSA_ADMIN_CMD_PING,
	SSA_ADMIN_CMD_NODEINFO,
	SSA_ADMIN_CMD_DISCONNECT,
	SSA_ADMIN_CMD_DBQUERY,
	SSA_ADMIN_CMD_MAX
};

enum ssa_admin_stats_id {
	STATS_ID_NODE_START_TIME = 0,
	STATS_ID_DB_UPDATES_NUM,
	STATS_ID_DB_LAST_UPDATE_TIME,
	STATS_ID_DB_FIRST_UPDATE_TIME,
	STATS_ID_NUM_CHILDREN,
	STATS_ID_NUM_ACCESS_TASKS,
	STATS_ID_NUM_ERR,
	STATS_ID_LAST_ERR,
	STATS_ID_TIME_LAST_UPSTR_CONN,
	STATS_ID_TIME_LAST_DOWNSTR_CONN,
	STATS_ID_TIME_LAST_SSA_MAD_RCV,
	STATS_ID_TIME_LAST_ERR,
	STATS_ID_DB_EPOCH,
	STATS_ID_IPV4_TBL_EPOCH,
	STATS_ID_IPV6_TBL_EPOCH,
	STATS_ID_NAME_TBL_EPOCH,
	STATS_ID_LAST
};

enum ssa_stats_type {
	ssa_stats_obsolete = 0,
	ssa_stats_numeric,
	ssa_stats_signed_numeric,
	ssa_stats_timestamp
};

static const enum ssa_stats_type ssa_admin_stats_type[] = {
	[STATS_ID_NODE_START_TIME] = ssa_stats_timestamp,
	[STATS_ID_DB_UPDATES_NUM] = ssa_stats_numeric,
	[STATS_ID_DB_LAST_UPDATE_TIME] = ssa_stats_timestamp,
	[STATS_ID_DB_FIRST_UPDATE_TIME] = ssa_stats_timestamp,
	[STATS_ID_NUM_CHILDREN] = ssa_stats_numeric,
	[STATS_ID_NUM_ACCESS_TASKS] = ssa_stats_numeric,
	[STATS_ID_NUM_ERR] = ssa_stats_numeric,
	[STATS_ID_LAST_ERR] = ssa_stats_signed_numeric,
	[STATS_ID_TIME_LAST_UPSTR_CONN] = ssa_stats_timestamp,
	[STATS_ID_TIME_LAST_DOWNSTR_CONN] = ssa_stats_timestamp,
	[STATS_ID_TIME_LAST_SSA_MAD_RCV] = ssa_stats_timestamp,
	[STATS_ID_TIME_LAST_ERR] = ssa_stats_timestamp,
	[STATS_ID_DB_EPOCH] = ssa_stats_numeric,
	[STATS_ID_IPV4_TBL_EPOCH] = ssa_stats_numeric,
	[STATS_ID_IPV6_TBL_EPOCH] = ssa_stats_numeric,
	[STATS_ID_NAME_TBL_EPOCH] = ssa_stats_numeric
};


struct ssa_admin_stats {
	be16_t		n;
	uint8_t		reserved[6];
	be64_t		epoch_tv_sec;
	be64_t		epoch_tv_usec;
	be64_t		vals[STATS_ID_LAST];
};

struct ssa_admin_connection_info {
	uint8_t		connection_type;
	uint8_t		dbtype;
	uint8_t		remote_type;
	uint8_t		reserved;
	be16_t		remote_lid;
	uint8_t		reserved2[2];
	be64_t		connection_tv_sec;
	be64_t		connection_tv_usec;
	uint8_t		remote_gid[16];
};

struct ssa_admin_nodeinfo {
	uint8_t		type;
	uint8_t		version[SSA_ADMIN_VERSION_LEN];
	uint8_t		reserved[5];
	be64_t		db_epoch;
	be16_t		connections_num;
	uint8_t		connections[0];
};

struct ssa_admin_disconnect {
	uint8_t		type;
	union {
		be16_t		lid;
		uint8_t		gid[16];
	} id;
};
/*
 * ssa_admin_msg_hdr:
 * @version   - version of this structure
 * @status    - query result
 * @method    - query method (get, set or response)
 * @reserved  - set to 0
 * @opcode    - requested operation to perform
 * @flags     - bitmask of flags to control operation
 * @len       - size of message, including header, in bytes
 * @reserved2 - set to 0
 *
 * All SSA admin messages are preceded by the ssa_admin_msg_hdr structure.
 * The len field indicates the size of the message (header + data).
 */
struct ssa_admin_msg_hdr {
	uint8_t		version;
	uint8_t		status;
	uint8_t		method;
	uint8_t		reserved;
	be16_t		opcode;
	be16_t		flags;
	be16_t		len;
	uint8_t		reserved2[6];
};

struct ssa_admin_msg {
	struct ssa_admin_msg_hdr	hdr;
	union {
		struct ssa_admin_stats		stats;
		struct ssa_admin_nodeinfo	nodeinfo;
		struct ssa_admin_disconnect	disconnect;
	} data;
};

#ifdef SSA_ADMIN_DEBUG
void ssa_format_admin_msg(char *buf, size_t size, const struct ssa_admin_msg *msg);
#endif

#endif /* _SSA_ADMIN_H */
