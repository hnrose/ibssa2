/*
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

#ifndef __IBSSA_TOT_H__
#define __IBSSA_TOT_H__

#include <infiniband/umad.h>
#include "tot_vs_mad.h"


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
struct tot_ctx;

union tot_resp {
	struct ib_mad_hdr      hdr;
	struct tot_attr_hello  hello;
	struct tot_attr_parent parent;
	struct tot_attr_hookup hookup;
};

struct tot_qp_attr {
	uint16_t  lid;
	uint32_t  qpn;
};

/**
 * Tot does not own umad_fd let the user control that.
 */
struct tot_ctx *tot_init(int umad_fd);

/**
 * dest will usually be filled in with SM Lid/SL
 * But could be previous known parent or configured to be any node.
 *    (While complicated I think we want to allow for this?)
 */
int tot_hello(struct tot_ctx *ctx, struct ib_mad_pr *dest, char *tree);

/* Simple Blocking Wait for parent resp */
int tot_wait_resp(struct tot_ctx *ctx, union tot_resp *resp);

int tot_hookup(struct tot_ctx *ctx, struct ib_mad_pr *dest,
		struct tot_qp_attr *qp_attr);

#endif /* __IBSSA_TOT_H__ */
