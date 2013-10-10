/*
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
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
	SSA_CTRL_DEV_EVENT,
	SSA_CTRL_MAD,		/* struct ssa_umad */
	SSA_SA_MAD,		/* struct sa_umad */
	SSA_CTRL_CONN		/* struct ssa_ctrl_conn_msg */
};

struct ssa_ctrl_msg {
	int			len;
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

struct ssa_ctrl_conn_msg {
	struct ssa_ctrl_msg	hdr;
	struct ssa_svc		*svc;
};

struct ssa_ctrl_msg_buf {
	struct ssa_ctrl_msg	hdr;
	union {
		enum ibv_event_type	event;
		struct ssa_umad		umad;
		struct sa_umad		umad_sa;
		struct ssa_svc		*svc;
	} data;
};

#ifdef __cplusplus
}
#endif

#endif /* _SSA_CTRL_H */
