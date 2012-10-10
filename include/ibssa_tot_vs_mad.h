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

#ifndef __IBSSA_TOT_VS_MAD_H__
#define __IBSSA_TOT_VS_MAD_H__

#include <linux/types.h>

#include "ibssa_util.h"

/** =========================================================================
 * Issues:
 *    1) What length do we want for our tree "names"?  Is 64 bytes enough?
 *    2) I am not liking the "TOT" name...
 */

/**
 * What class value is available?
 * I don't see a need for RMPP so use one from 0x09-0xf
 */
#define IBSSA_TOT_VS_CLASS 0x09

/**
 * Methods supported
 *    VendorGet()
 *    VendorSet()
 *    VendorGetResp()
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

struct ib_mad_pr {
	__be32_t      reserved;
	__be32_t      reserved_offset;
	union ibv_gid dgid;
	union ibv_gid sgid;
	__be16_t      dlid;
	__be16_t      slid;
	uint32_t      rt__fl__hl; /*  1: RawTraffic
				   *  3: Reserved
				   * 20: FlowLabel
				   *  8: HopLimit
				   */
	uint8_t       traffic_class;
	uint8_t       rev__numb_path;
	__be16_t      pkey;
	uint8_t       reserved12;
	uint8_t       sl;                       /* 4:reserved     4:SL */
	uint8_t       select__mtu;              /* 2:MtuSelector  6:MTU */
	uint8_t       select__rate;             /* 2:RateSelector 6:Rate */
	uint8_t       select__packet_life_time; /* 2:PLTSelector  6:PLT */
	uint8_t       preference;
	uint8_t       reserved48[6];
};

/**
 * Hello is like "take a number" when you walk in a store.  It will return the
 * expected wait time.  The client can use that wait time to time out and send
 * another hello if it has not received "service" for the parent info yet.
 */
#define TOT_ATTR_HELLO 0x0010
struct tot_attr_hello {
	struct ib_mad_hdr hdr;
	__be32_t          wait_time_us;
	char              tree[64];
	uint8_t           padding[164];
};

/**
 * Parent message sent some time after hello is recieved
 * Father is primary parent, Mother is secondary
 * client can chose to connect to one or both
 */
#define TOT_ATTR_PARENT 0x0011
struct tot_attr_parent {
	struct ib_mad_hdr hdr;
	char              tree[64];
	struct ib_mad_pr  father_pr;
	struct ib_mad_pr  mother_pr; // May be blank
	uint8_t           padding[76];
};

/**
 * Hookup message sent to parent when requesting to be connected.
 */
#define TOT_ATTR_HOOKUP 0x0012
struct tot_attr_hookup {
	struct ib_mad_hdr   hdr;
	char                tree[64];
	__be32_t            qpn;
	__be16_t            lid;
	uint8_t             padding['rest'];
};

#endif /* __IBSSA_TOT_VS_MAD_H__ */
