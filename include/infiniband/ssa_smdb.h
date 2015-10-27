/*
 * Copyright (c) 2011-2015 Mellanox Technologies LTD. All rights reserved.
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

#ifndef _SSA_SMDB_H_
#define _SSA_SMDB_H_

#include <infiniband/ssa_db.h>
#include <infiniband/ssa_ipdb.h>
#include <infiniband/umad_sm.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

#define IB_NODE_DESCRIPTION_SIZE 64

enum smdb_tbl_id {
	SMDB_TBL_ID_SUBNET_OPTS = 0,
	SMDB_TBL_ID_GUID2LID,
	SMDB_TBL_ID_NODE,
	SMDB_TBL_ID_LINK,
	SMDB_TBL_ID_PORT,
	SMDB_TBL_ID_PKEY,
	SMDB_TBL_ID_LFT_TOP,
	SMDB_TBL_ID_LFT_BLOCK,
	SMDB_TBL_ID_IPv4,
	SMDB_TBL_ID_IPv6,
	SMDB_TBL_ID_NAME,
	SMDB_TBL_ID_MAX
};

enum smdb_subnet_opts_fields {
	SMDB_FIELD_ID_SUBNET_OPTS_CHANGE_MASK = 0,
	SMDB_FIELD_ID_SUBNET_OPTS_SUBNET_PREFIX,
	SMDB_FIELD_ID_SUBNET_OPTS_SM_STATE,
	SMDB_FIELD_ID_SUBNET_OPTS_LMC,
	SMDB_FIELD_ID_SUBNET_OPTS_SUBNET_TIMEOUT,
	SMDB_FIELD_ID_SUBNET_OPTS_ALLOW_BOTH_PKEYS,
	SMDB_FIELD_ID_SUBNET_OPTS_MAX
};

enum smdb_guid2lid_fields {
	SMDB_FIELD_ID_GUID2LID_GUID = 0,
	SMDB_FIELD_ID_GUID2LID_LID,
	SMDB_FIELD_ID_GUID2LID_LMC,
	SMDB_FIELD_ID_GUID2LID_IS_SWITCH,
	SMDB_FIELD_ID_GUID2LID_MAX
};

enum smdb_node_fields {
	SMDB_FIELD_ID_NODE_NODE_GUID = 0,
	SMDB_FIELD_ID_NODE_IS_ENHANCED_SP0,
	SMDB_FIELD_ID_NODE_NODE_TYPE,
	SMDB_FIELD_ID_NODE_DESCRIPTION,
	SMDB_FIELD_ID_NODE_MAX
};

enum smdb_link_fields {
	SMDB_FIELD_ID_LINK_FROM_LID = 0,
	SMDB_FIELD_ID_LINK_TO_LID,
	SMDB_FIELD_ID_LINK_FROM_PORT_NUM,
	SMDB_FIELD_ID_LINK_TO_PORT_NUM,
	SMDB_FIELD_ID_LINK_MAX
};

enum smdb_port_fields {
	SMDB_FIELD_ID_PORT_PKEY_TBL_OFFSET = 0,
	SMDB_FIELD_ID_PORT_PKEY_TBL_SIZE,
	SMDB_FIELD_ID_PORT_PORT_LID,
	SMDB_FIELD_ID_PORT_PORT_NUM,
	SMDB_FIELD_ID_PORT_MTU_CAP,
	SMDB_FIELD_ID_PORT_RATE,
	SMDB_FIELD_ID_PORT_VL_ENFORCE,
	SMDB_FIELD_ID_PORT_MAX
};

enum smdb_lft_top_fields {
	SMDB_FIELD_ID_LFT_TOP_LID = 0,
	SMDB_FIELD_ID_LFT_TOP_LFT_TOP,
	SMDB_FIELD_ID_LFT_TOP_MAX
};

enum smdb_lft_block_fields {
	SMDB_FIELD_ID_LFT_BLOCK_LID = 0,
	SMDB_FIELD_ID_LFT_BLOCK_BLOCK_NUM,
	SMDB_FIELD_ID_LFT_BLOCK_BLOCK,
	SMDB_FIELD_ID_LFT_BLOCK_MAX
};

struct smdb_subnet_opts {
	/* change_mask bits point to the changed data fields */
	be64_t		change_mask;
	be64_t		subnet_prefix;
	uint8_t		sm_state;
	uint8_t		lmc;
	uint8_t		subnet_timeout;
	uint8_t		allow_both_pkeys;
	uint8_t		pad[4];
};

struct smdb_guid2lid {
	be64_t		guid;
	be16_t		lid;
	uint8_t		lmc;
	uint8_t		is_switch;
	uint8_t		pad[4];
};

struct smdb_node {
	be64_t		node_guid;
	uint8_t		is_enhanced_sp0;
	uint8_t		node_type;
	uint8_t		description[IB_NODE_DESCRIPTION_SIZE];
	uint8_t		pad[6];
};

struct smdb_link {
	be16_t		from_lid;
	be16_t		to_lid;
	uint8_t		from_port_num;
	uint8_t		to_port_num;
	uint8_t		pad[2];
};

struct smdb_port {
	be64_t		pkey_tbl_offset;
	be16_t		pkey_tbl_size;
	be16_t		port_lid;
	uint8_t		port_num;
	uint8_t		mtu_cap;
	uint8_t		rate; /* is_fdr10_active(1b), is_switch(1b) (appears in guid2lid record as well), rate(6b) */
	uint8_t		vl_enforce;
};

#define SSA_DB_PORT_RATE_MASK			0x3F
#define SSA_DB_PORT_IS_SWITCH_MASK		0x40
#define SSA_DB_PORT_IS_FDR10_ACTIVE_MASK	0x80

struct smdb_lft_top {
	be16_t		lid;
	be16_t		lft_top;
	uint8_t		pad[4];
};

struct smdb_lft_block {
	be16_t		lid;
	be16_t		block_num;
	uint8_t		block[UMAD_LEN_SMP_DATA];
};

#define SSA_DB_CHANGEMASK_SUBNET_PREFIX		(((uint16_t) 1) << 0)
#define SSA_DB_CHANGEMASK_SM_STATE		(((uint16_t) 1) << 1)
#define SSA_DB_CHANGEMASK_LMC			(((uint16_t) 1) << 2)
#define SSA_DB_CHANGEMASK_SUBNET_TIMEOUT	(((uint16_t) 1) << 3)
#define SSA_DB_CHANGEMASK_ALLOW_BOTH_PKEYS	(((uint16_t) 1) << 4)

#define SSA_TABLE_BLOCK_SIZE			1024

/* each data table has field table, pkey table has no field table */
#define SMDB_TBLS		(SMDB_TBL_ID_MAX * 2 - 1)
#define SMDB_DATA_TBLS		SMDB_TBL_ID_MAX
#define SMDB_FIELDS		(SMDB_FIELD_ID_SUBNET_OPTS_MAX + \
				 SMDB_FIELD_ID_GUID2LID_MAX + \
				 SMDB_FIELD_ID_NODE_MAX + \
				 SMDB_FIELD_ID_LINK_MAX + \
				 SMDB_FIELD_ID_PORT_MAX + \
				 SMDB_FIELD_ID_LFT_TOP_MAX + \
				 SMDB_FIELD_ID_LFT_BLOCK_MAX + \
				 IPDB_FIELDS)
#define SMDB_TBL_OFFSET		8


#define DBT_TABLE_DEF_SUBNET_OPTS(id) DBT_TABLE_DEF(id, "SUBNET_OPTS", sizeof(struct smdb_subnet_opts))
#define DBT_TABLE_DEF_GUID2LID(id) DBT_TABLE_DEF(id, "GUID_to_LID", sizeof(struct smdb_guid2lid))
#define DBT_TABLE_DEF_NODE(id) DBT_TABLE_DEF(id, "NODE", sizeof(struct smdb_node))
#define DBT_TABLE_DEF_LINK(id) DBT_TABLE_DEF(id, "LINK", sizeof(struct smdb_link))
#define DBT_TABLE_DEF_PORT(id) DBT_TABLE_DEF(id, "PORT", sizeof(struct smdb_port))
#define DBT_TABLE_DEF_LFT_TOP(id) DBT_TABLE_DEF(id, "LFT_TOP", sizeof(struct smdb_lft_top))
#define DBT_TABLE_DEF_LFT_BLOCK(id) DBT_TABLE_DEF(id, "LFT_BLOCK", sizeof(struct smdb_lft_block))

#define DBF_TABLE_DEF_SUBNET_OPTS(id, offset) DBF_TABLE_DEF(id, offset, "SUBNET_OPTS")
#define DBF_TABLE_DEF_GUID2LID(id, offset) DBF_TABLE_DEF(id, offset, "GUID_to_LID")
#define DBF_TABLE_DEF_NODE(id, offset) DBF_TABLE_DEF(id, offset, "NODE")
#define DBF_TABLE_DEF_LINK(id, offset) DBF_TABLE_DEF(id, offset, "LINK")
#define DBF_TABLE_DEF_PORT(id, offset) DBF_TABLE_DEF(id, offset, "PORT")
#define DBF_TABLE_DEF_LFT_TOP(id, offset) DBF_TABLE_DEF(id, offset, "LFT_TOP")
#define DBF_TABLE_DEF_LFT_BLOCK(id, offset) DBF_TABLE_DEF(id, offset, "LFT_BLOCK")

#define DB_FIELD_DEF_SUBNET_OPTS_CHANGE_MASK(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_CHANGE_MASK, "change_mask", 64, 0)
#define DB_FIELD_DEF_SUBNET_OPTS_SUBNET_PREFIX(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_SUBNET_PREFIX, "subnet_prefix", 64, 64)
#define DB_FIELD_DEF_SUBNET_OPTS_SM_STATE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_SM_STATE, "sm_state", 8, 128)
#define DB_FIELD_DEF_SUBNET_OPTS_LMC(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_SM_STATE, "lmc", 8, 136)
#define DB_FIELD_DEF_SUBNET_OPTS_SUBNET_TIMEOUT(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_SUBNET_TIMEOUT, "subnet_timeout", 8, 144)
#define DB_FIELD_DEF_SUBNET_OPTS_ALLOW_BOTH_PKEYS(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_SUBNET_OPTS_ALLOW_BOTH_PKEYS, "allow_both_pkeys", 8, 152)

#define DB_FIELD_DEF_GUID2LID_GUID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, SMDB_FIELD_ID_GUID2LID_GUID, "guid", 64, 0)
#define DB_FIELD_DEF_GUID2LID_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_GUID2LID_LID, "lid", 16, 64)
#define DB_FIELD_DEF_GUID2LID_LMC(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_GUID2LID_LMC, "lmc", 8, 80)
#define DB_FIELD_DEF_GUID2LID_IS_SWITCH(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_GUID2LID_IS_SWITCH, "is_switch", 8, 88)

#define DB_FIELD_DEF_NODE_NODE_GUID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, SMDB_FIELD_ID_NODE_NODE_GUID, "node_guid", 64, 0)
#define DB_FIELD_DEF_NODE_IS_ENHANCED_SP0(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_NODE_IS_ENHANCED_SP0, "is_enhanced_sp0", 8, 64)
#define DB_FIELD_DEF_NODE_NODE_TYPE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_NODE_NODE_TYPE, "node_type", 8, 72)
#define DB_FIELD_DEF_NODE_DESCRIPTION(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_NODE_DESCRIPTION, "description", (8 * IB_NODE_DESCRIPTION_SIZE), 80)

#define DB_FIELD_DEF_LINK_FROM_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LINK_FROM_LID, "from_lid", 16, 0)
#define DB_FIELD_DEF_LINK_TO_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LINK_TO_LID, "to_lid", 16, 16)
#define DB_FIELD_DEF_LINK_FROM_PORT_NUM(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_LINK_FROM_PORT_NUM, "from_port_num", 8, 32)
#define DB_FIELD_DEF_LINK_TO_PORT_NUM(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_LINK_TO_PORT_NUM, "to_port_num", 8, 40)

#define DB_FIELD_DEF_PORT_PKEY_TBL_OFFSET(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, SMDB_FIELD_ID_PORT_PKEY_TBL_OFFSET, "pkey_tbl_offset", 64, 0)
#define DB_FIELD_DEF_PORT_PKEY_TBL_SIZE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_PORT_PKEY_TBL_SIZE, "pkey_tbl_size", 16, 64)
#define DB_FIELD_DEF_PORT_PORT_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_PORT_PORT_LID, "port_lid", 16, 80)
#define DB_FIELD_DEF_PORT_PORT_NUM(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_PORT_PORT_NUM, "port_num", 8, 96)
#define DB_FIELD_DEF_PORT_MTU_CAP(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_PORT_MTU_CAP, "mtu_cap", 8, 104)
#define DB_FIELD_DEF_PORT_RATE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_PORT_RATE, "rate", 8, 112)
#define DB_FIELD_DEF_PORT_VL_ENFORCE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_PORT_VL_ENFORCE, "vl_enforce", 8, 120)

#define DB_FIELD_DEF_LFT_TOP_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LFT_TOP_LID, "lid", 16, 0)
#define DB_FIELD_DEF_LFT_TOP_LFT_TOP(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LFT_TOP_LFT_TOP, "lft_top", 16, 16)

#define DB_FIELD_DEF_LFT_BLOCK_LID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LFT_BLOCK_LID, "lid", 16, 0)
#define DB_FIELD_DEF_LFT_BLOCK_BLOCK_NUM(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, SMDB_FIELD_ID_LFT_BLOCK_BLOCK_NUM, "block_num", 16, 16)
#define DB_FIELD_DEF_LFT_BLOCK_BLOCK(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, SMDB_FIELD_ID_LFT_BLOCK_BLOCK, "block", (8 * UMAD_LEN_SMP_DATA), 32)

struct ssa_db *ssa_db_smdb_init(uint64_t epoch, uint64_t data_rec_cnt[SMDB_TBL_ID_MAX]);

void ssa_db_smdb_destroy(struct ssa_db * p_smdb);
END_C_DECLS
#endif				/* _SSA_SMDB_H_ */
