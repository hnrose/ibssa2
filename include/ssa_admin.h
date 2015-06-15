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
	COUNTER_ID_TIME_LAST_UPSTR_CONN,
	COUNTER_ID_TIME_LAST_DOWNSTR_CONN,
	COUNTER_ID_TIME_LAST_SSA_MAD_RCV,
	COUNTER_ID_TIME_LAST_ERR
};

const static int ssa_admin_time_counter_ids[] = {
	COUNTER_ID_NODE_START_TIME,
	COUNTER_ID_TIME_LAST_UPSTR_CONN,
	COUNTER_ID_TIME_LAST_DOWNSTR_CONN,
	COUNTER_ID_TIME_LAST_SSA_MAD_RCV,
	COUNTER_ID_TIME_LAST_ERR
};

struct ssa_admin_counter {
	uint8_t		id;
	be64_t		val;
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
	} data;
};

#endif /* _SSA_ADMIN_H */
