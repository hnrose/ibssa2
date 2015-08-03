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
	SSA_ADMIN_CMD_COUNTER,
	SSA_ADMIN_CMD_PING,
	SSA_ADMIN_CMD_NODE_INFO,
	SSA_ADMIN_CMD_MAX
};

enum ssa_admin_counter_id {
	COUNTER_ID_NODE_START_TIME = 0,
	COUNTER_ID_DB_UPDATES_NUM,
	COUNTER_ID_DB_LAST_UPDATE_TIME,
	COUNTER_ID_DB_FIRST_UPDATE_TIME,
	COUNTER_ID_NUM_CHILDREN,
	COUNTER_ID_NUM_ACCESS_TASKS,
	COUNTER_ID_NUM_ERR,
	COUNTER_ID_LAST_ERR,
	COUNTER_ID_TIME_LAST_UPSTR_CONN,
	COUNTER_ID_TIME_LAST_DOWNSTR_CONN,
	COUNTER_ID_TIME_LAST_SSA_MAD_RCV,
	COUNTER_ID_TIME_LAST_ERR,
	COUNTER_ID_DB_EPOCH,
	COUNTER_ID_LAST
};

enum ssa_counter_type {
	ssa_counter_obsolete = 0,
	ssa_counter_numeric,
	ssa_counter_signed_numeric,
	ssa_counter_timestamp
};

static const enum ssa_counter_type ssa_admin_counters_type[] = {
	[COUNTER_ID_NODE_START_TIME] = ssa_counter_timestamp,
	[COUNTER_ID_DB_UPDATES_NUM] = ssa_counter_numeric,
	[COUNTER_ID_DB_LAST_UPDATE_TIME] = ssa_counter_timestamp,
	[COUNTER_ID_DB_FIRST_UPDATE_TIME] = ssa_counter_timestamp,
	[COUNTER_ID_NUM_CHILDREN] = ssa_counter_numeric,
	[COUNTER_ID_NUM_ACCESS_TASKS] = ssa_counter_numeric,
	[COUNTER_ID_NUM_ERR] = ssa_counter_numeric,
	[COUNTER_ID_LAST_ERR] = ssa_counter_signed_numeric,
	[COUNTER_ID_TIME_LAST_UPSTR_CONN] = ssa_counter_timestamp,
	[COUNTER_ID_TIME_LAST_DOWNSTR_CONN] = ssa_counter_timestamp,
	[COUNTER_ID_TIME_LAST_SSA_MAD_RCV] = ssa_counter_timestamp,
	[COUNTER_ID_TIME_LAST_ERR] = ssa_counter_timestamp,
	[COUNTER_ID_DB_EPOCH] =ssa_counter_numeric
};


struct ssa_admin_counter {
	be16_t		n;
	uint8_t		reserved[6];
	be64_t		epoch_tv_sec;
	be64_t		epoch_tv_usec;
	be64_t		vals[COUNTER_ID_LAST];
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

struct ssa_admin_node_info {
	uint8_t		type;
	uint8_t		version[SSA_ADMIN_VERSION_LEN];
	be64_t		db_epoch;
	be16_t		connections_num;
	uint8_t		reserved[3];
	uint8_t		connections[0];
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
		struct ssa_admin_counter	counter;
		struct ssa_admin_node_info	node_info;
	} data;
};

#ifdef SSA_ADMIN_DEBUG
void ssa_format_admin_msg(char *buf, size_t size, const struct ssa_admin_msg *msg);
#endif

#endif /* _SSA_ADMIN_H */
