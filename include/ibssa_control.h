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

/** =========================================================================
 * For the control channel I wonder if doing straight up SA commands would be best?
 */

struct ibssa_control_hdr {
	uint8_t           version;
	uint8_t           method;
	uint8_t           msg_id;
	uint8_t           pad;
	__be64_t          epoch;
	/* What else here? */
};

#define MSG_ID_PR_QUERY 0x01
struct ibssa_pr_req {
	struct ibssa_control_hdr hdr;
	union {
		__be16_t                dlid;
		union ibv_gid           dgid;
		struct sockaddr_storage addr;
		char                    node_desc[64];
		char                    hostname[128];
	} addr;
};

/**
 * What other queries?
 */

#endif /* __IBSSA_CONTROL_H__ */

