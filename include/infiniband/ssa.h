/*
 * Copyright (c) 2012 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012-2013 Intel Corporation. All rights reserved.
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


#ifndef __SSA_H__
#define __SSA_H__

#include <linux/types.h>
#include <infiniband/ssa_mad.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
	SSA_MSG_VERSION			= 1,

	SSA_MSG_CLASS_CTRL		= 1,
	SSA_MSG_CLASS_DB,
	/* SSA_MSG_CLASS_MAD */

	SSA_MSG_FLAG_RESP		= (1 << 0),
};

enum {
	SSA_MSG_CTRL_SYNC,
};

struct ssa_msg_hdr {
	uint8_t			version;
	uint8_t			class;
	be16_t			op;
	be32_t			len;
	be16_t			flags;
	be16_t			status;
	be32_t			id;
	be32_t			reserved;
	be32_t			rdma_len;
	be64_t			rdma_addr;
};

/*
struct ssa_mad_msg {
	struct ssa_msg_hdr	hdr;
	struct ssa_mad_packet	mad;
};
*/

#ifdef __cplusplus
}
#endif

#endif /* __SSA_H__ */
