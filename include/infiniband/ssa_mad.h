/*
 * Copyright (c) 2012-2013 Mellanox Technologies LTD. All rights reserved.
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

#ifndef _SSA_MAD_H
#define _SSA_MAD_H

#include <linux/types.h>
#include <infiniband/umad.h>
#include <infiniband/umad_types.h>
#include <infiniband/umad_sa.h>
#include <infiniband/sa.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Match with SA definitions where possible.
 */
enum {
	SSA_CLASS_VERSION		= 1,
	SSA_CLASS			= 0x2C,

	SSA_METHOD_DELETE		= UMAD_SA_METHOD_DELETE,
	SSA_METHOD_DELETE_RESP		= UMAD_SA_METHOD_DELETE_RESP
};

enum {
	SSA_STATUS_SUCCESS		= UMAD_SA_STATUS_SUCCESS,
	SSA_STATUS_NO_RESOURCES		= UMAD_SA_STATUS_NO_RESOURCES,
	SSA_STATUS_REQ_INVALID		= UMAD_SA_STATUS_REQ_INVALID,
	SSA_STATUS_NO_RECORDS		= UMAD_SA_STATUS_NO_RECORDS,
	SSA_STATUS_TOO_MANY_RECORDS	= UMAD_SA_STATUS_TOO_MANY_RECORDS,
	SSA_STATUS_INVALID_GID		= UMAD_SA_STATUS_INVALID_GID,
	SSA_STATUS_INSUF_COMPS		= UMAD_SA_STATUS_INSUF_COMPS,
	SSA_STATUS_REQ_DENIED		= UMAD_SA_STATUS_REQ_DENIED,
};

enum {
	SSA_ATTR_MEMBER_REC		= 0x1000,
	SSA_ATTR_INFO_REC		= 0x1001
};

enum {
	SSA_MAD_LEN_DATA = 224
};

/**
 * An AppSet(SSAMemberRecord) request indicates that port/service/pkey wishes
 * to join the specified service_guid tree.
 *
 * An AppDelete(SSAMemberRecord) request indicates that a port/service/pkey
 * wishes to leave the specified service_guid tree.
 *
 * The master SSA will respond to a successful Set/Delete request by returning
 * a GetResp/DeleteResp with the current membership indicated in a returned
 * SSAMemberRecord.  (This matches what the SA does for MCMemberRecords)
 */
enum {
	SSA_PROTOCOL_VERSION	= 1,
};

/*
 * Certain combinations of node types are supported
 * Currently, Distribution + Access, and Core + Access
 */
enum {
	SSA_NODE_CORE		= (1 << 0),
	SSA_NODE_DISTRIBUTION	= (1 << 1),
	SSA_NODE_ACCESS		= (1 << 2),
	SSA_NODE_CONSUMER	= (1 << 3) 
};

enum {
	SSA_DB_PATH_DATA	= 1ULL,
};

struct ssa_member_record {
	uint8_t		port_gid[16];
	uint8_t		parent_gid[16];
	be64_t		database_id;
	be64_t		node_guid;
	uint8_t		node_type;
	uint8_t		reserved[7];
};

/**
 * SSAInfoRecord is used to inform registered services of the location of other
 * registered services - basically to setup the communication tree among SSA
 * services which have access to a specific data set.
 *
 * Master SSA uses Set(SSAInfoRecord) attribute to configure
 * joined SSA services.  The clients respond with a GetResp, echoing back the
 * TID.
 *
 * If multiple paths are available Primary/Alternate/GMP those paths are sent
 * separately.
 *
 * Furthermore, the master may issue a second set of SSAInfoRecord with the
 * secondary (backup) parent information if available.
 *
 * Once a node receives an SSAInfoRecord, it can connect to the parent service
 * using the PR information contained within the record.
 */
struct ssa_info_record {
	be64_t			database_id;
	struct ibv_path_data	path_data;
};

struct sa_path_record {
	struct umad_hdr		mad_hdr;
	struct umad_rmpp_hdr	rmpp_hdr;
	uint8_t			sm_key[8]; /* network-byte order */
	be16_t			attr_offset;
	be16_t			reserved;
	be64_t			comp_mask;
	struct ibv_path_record	path;
};

struct ssa_mad_packet {
	struct umad_hdr		mad_hdr;
	be64_t			ssa_key;
	union {
		uint8_t				data[SSA_MAD_LEN_DATA];
		struct ssa_member_record	member;
		struct ssa_info_record		info;
	} ssa_mad;
};

struct ssa_umad {
	struct ib_user_mad	umad;
	struct ssa_mad_packet	packet;
};

struct sa_umad {
	struct ib_user_mad	umad;
	union {
		struct umad_sa_packet	packet;
		struct sa_path_record	path_rec;
	} sa_mad;
};

const char *ssa_method_str(uint8_t method);
const char *ssa_attribute_str(be16_t attr_id);
const char *ssa_mad_status_str(be16_t status);
const char *ssa_node_type_str(int node_type);

#ifdef __cplusplus
}
#endif

#endif /* _SSA_MAD_H */
