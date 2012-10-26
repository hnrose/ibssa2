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

#ifndef __IBSSA_MAD_H__
#define __IBSSA_MAD_H__

#include <linux/types.h>

/** =========================================================================
 * Issues:
 *    1) What length do we want for our tree "names"?  Is 64 bytes enough?
 */

/**
 * What class value is available?
 * I don't see a need for RMPP so use one from 0x09-0xf
 */
#define IB_SSA_CLASS 0x09

/**
 * Methods supported
 *    VendorGet()
 *    VendorSet()
 *    VendorGetResp()
 *    VendorSend()
 *
 *    Do we need Trap???
 *
 * Attributes 
 *    Hello
 *    Parent
 *    Hookup
 */

struct ib_mad_hdr {
	uint8_t	  base_version;
	uint8_t	  mgmt_class;
	uint8_t	  class_version;
	uint8_t	  method;
	__be16_t  status;
	__be16_t  cs_reserved;
	__be64_t  tid;
	__be16_t  attr_id;
	__be16_t  resv;
	__be32_t  attr_mod;
};

/**
 * Hello is like "take a number" when you walk in a store.  It will return the
 * expected wait time.  The client can use that wait time to time out and send
 * another hello if it has not received "service" for the parent info yet.
 */
#define IB_SSA_ATTR_HELLO 0x0010
struct ib_ssa_attr_hello {
	struct ib_mad_hdr hdr;
	__be32_t          wait_time_us;
	char              tree[64];
	uint8_t           padding[164];
	/* Do we need something here to ID the connecting node?
	 * LID?  It seems we could get that from the headers
	 */
};

/**
 * Parent message sent some time after hello is received
 * client can chose to connect to one or both
 */
#define IB_SSA_ATTR_PARENT 0x0011
struct ib_ssa_attr_parent {
	struct ib_mad_hdr       hdr;
	char                    tree[64];
	struct ibv_path_record  primary_pr;
	struct ibv_path_record  secondary_pr; // May be blank
	uint8_t                 padding[76];
};

/**
 * Hookup message sent to parent when requesting to be connected.
 */
#define IB_SSA_ATTR_HOOKUP 0x0012
struct ib_ssa_attr_hookup {
	struct ib_mad_hdr   hdr;
	char                tree[64];
	__be32_t            qpn;
	__be16_t            lid;
	uint8_t             padding[162];
};

#endif /* __IBSSA_MAD_H__ */
