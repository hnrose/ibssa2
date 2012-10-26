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

#ifndef __IBSSA_WIREUP_H__
#define __IBSSA_WIREUP_H__

#include <infiniband/umad.h>
#include "ibssa_mad.h"


/**
 * NOTES:
 *
 * I started with the standard OFA copyright/license.  I figure this is
 * just an extension of existing OFA software.
 *
 * Then start with Eitan's basic calls.
 *
 */

/* For those using this interface the tot_ctx is kept opaque for flexibility */
struct ib_ssa_ctx;

union ib_ssa_resp {
	struct ib_mad_hdr         hdr;
	struct ib_ssa_attr_hello  hello;
	struct ib_ssa_attr_parent parent;
	struct ib_ssa_attr_hookup hookup;
};

struct ib_ssa_qp_attr {
	uint16_t  lid;
	uint32_t  qpn;
};

/**
 * Tot does not own umad_fd let the user control that.
 */
struct ib_ssa_ctx *ib_ssa_init(int umad_fd);

/**
 * dest will usually be filled in with SM Lid/SL
 * But could be previous known parent or configured to be any node.
 *    (While complicated I think we want to allow for this?)
 */
int ib_ssa_hello(struct ib_ssa_ctx *ctx, struct ib_mad_pr *dest, char *tree);

/* Simple Blocking Wait for parent resp */
int ib_ssa_wait_resp(struct ib_ssa_ctx *ctx, union ib_ssa_resp *resp);

int ib_ssa_hookup(struct ib_ssa_ctx *ctx, struct ib_mad_pr *dest,
		struct ib_ssa_qp_attr *qp_attr);

#endif /* __IBSSA_WIREUP_H__ */
