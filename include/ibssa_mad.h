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
#include <infiniband/umad.h>
#include <infiniband/sa.h>
#include <infiniband/verbs.h>
#include "ibssa_umad.h"

/* From Sean's email for reference */
struct ib_ssa_mad {
	struct ib_mad_hdr hdr;

	uint64_t ssa_key;
	uint8_t reserved[24];
	/* other potential fields - but we need the space
	be16_t attr_offset;
	be16_t reserved3;
	uint32_t reserved4;
	be64_t comp_mask;
	*/

	uint8_t  data[200];
};

/**
 * Sean is right, it is more appropriate to use an Application Class MAD.
 *
 * For now we can borrow the ACM "class" because I don't know if there is a
 * reason we would want this different from control messages.  I don't think it
 * matters but perhaps it does.
 */
enum {
	IB_SSA_CLASS = 0x2C
};

/**
 * Methods supported
 */
enum {
	IB_SSA_METHOD_GET        = 0x01,
	IB_SSA_METHOD_SET        = 0x02,
	IB_SSA_METHOD_GETRESP    = 0x81,
	IB_SSA_METHOD_DELETE     = 0x15,
	IB_SSA_METHOD_DELETERESP = 0x95
};

/**
 * Attributes
 */
enum {
	IB_SSA_ATTR_SSAMemberRecord = 0x1000,
	IB_SSA_ATTR_SSAInfoRecord   = 0x1001
};

/**
 *
 * An AppSet(SSAMemberRecord) request indicates that port/service/pkey wishes
 * to join 1 or more SSA groups.
 *
 * An AppDelete(SSAMemberRecord) request indicates that a port/service/pkey
 * wishes to leave 1 or more SSA groups.
 *
 * The master SSA will respond to a successful Set/Delete request by returning
 * a GetResp/DeleteResp with the current membership indicated in a returned
 * SSAMemberRecord.  (This matches what the SA does for MCMemberRecords)
 *
 */
struct ib_ssa_member_record {
	union ibv_gid port_gid;		/* RID = GID + SID + PKey */
	be64_t        service_id;
	be16_t        pkey;
	uint8_t       reserved[4];
	uint8_t       node_type;
	uint8_t       node_level;
	be64_t        service_mask;	/* set service bit to 1 to indicate join/leave */
};

/* Node type values */
enum {
	SSA_NODE_SERVER = 1 << 0,
	SSA_NODE_CLIENT = 1 << 1
};

/* Service mask values */
enum {
	SSA_SERVICE_META_DATA   = 1 << 0,
	SSA_SERVICE_ADDRESS     = 1 << 1,
	SSA_SERVICE_PATH_RECORD = 1 << 2
};


/**
 * SSAInfoRecord is used to inform registered services of the location of other
 * registered services - basically to setup the communication tree among SSA
 * services which have joined a specific group.
 *
 * Master SSA uses Set method with an SSAInfoRecord attribute to configure
 * joined SSA services.  The clients respond with a GetResp, echoing back the
 * TID.
 *
 * If multiple paths are available Primary/Alternate/GMP those paths are sent
 * individually.
 *
 * Furthermore, the master may issue a second set of SSAInfoRecord with the
 * secondary (backup) parent information if available.
 *
 * Once a node receives an SSAInfoRecord, it can connect to the parent service
 * using the PR information contained within the record.
 */
struct ib_ssa_info_record {
	be64_t               service_mask;
	uint8_t              priority;     /* indicates primary/alternate parent/path */
	uint8_t              reserved[3];
	struct ibv_path_data path_data;
	uint8_t              pad[116];
};

#endif /* __IBSSA_MAD_H__ */
