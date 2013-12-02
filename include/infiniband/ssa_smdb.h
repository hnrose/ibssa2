/*
 * Copyright (c) 2011-2013 Mellanox Technologies LTD. All rights reserved.
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

#include <infiniband/osm_headers.h>
#include <infiniband/ssa_db.h>
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

enum ssa_db_smdb_table_id {
	SSA_TABLE_ID_SUBNET_OPTS = 0,
	SSA_TABLE_ID_GUID_TO_LID,
	SSA_TABLE_ID_NODE,
	SSA_TABLE_ID_LINK,
	SSA_TABLE_ID_PORT,
	SSA_TABLE_ID_PKEY,
	SSA_TABLE_ID_LFT_TOP,
	SSA_TABLE_ID_LFT_BLOCK,
	SSA_TABLE_ID_MAX
};

enum ssa_db_smdb_field_table_id {
	SSA_TABLE_ID_SUBNET_OPTS_FIELD_DEF = SSA_TABLE_ID_MAX,
	SSA_TABLE_ID_GUID_TO_LID_FIELD_DEF,
	SSA_TABLE_ID_NODE_FIELD_DEF,
	SSA_TABLE_ID_LINK_FIELD_DEF,
	SSA_TABLE_ID_PORT_FIELD_DEF,
	SSA_TABLE_ID_PKEY_FIELD_DEF,
	SSA_TABLE_ID_LFT_TOP_FIELD_DEF,
	SSA_TABLE_ID_LFT_BLOCK_FIELD_DEF,
	SSA_TABLE_ID_FIELD_DEF_MAX
};

enum ssa_db_smdb_subnet_opts_fields {
	SSA_FIELD_ID_SUBNET_OPTS_CHANGE_MASK = 0,
	SSA_FIELD_ID_SUBNET_OPTS_SUBNET_PREFIX,
	SSA_FIELD_ID_SUBNET_OPTS_SM_STATE,
	SSA_FIELD_ID_SUBNET_OPTS_LMC,
	SSA_FIELD_ID_SUBNET_OPTS_SUBNET_TIMEOUT,
	SSA_FIELD_ID_SUBNET_OPTS_ALLOW_BOTH_PKEYS,
	SSA_FIELD_ID_SUBNET_OPTS_MAX
};

enum ssa_db_smdb_guid_to_lid_fields {
	SSA_FIELD_ID_GUID_TO_LID_GUID = 0,
	SSA_FIELD_ID_GUID_TO_LID_LID,
	SSA_FIELD_ID_GUID_TO_LID_LMC,
	SSA_FIELD_ID_GUID_TO_LID_IS_SWITCH,
	SSA_FIELD_ID_GUID_TO_LID_MAX
};

enum ssa_db_smdb_node_fields {
	SSA_FIELD_ID_NODE_NODE_GUID = 0,
	SSA_FIELD_ID_NODE_IS_ENHANCED_SP0,
	SSA_FIELD_ID_NODE_NODE_TYPE,
	SSA_FIELD_ID_NODE_DESCRIPTION,
	SSA_FIELD_ID_NODE_MAX
};

enum ssa_db_smdb_link_fields {
	SSA_FIELD_ID_LINK_FROM_LID = 0,
	SSA_FIELD_ID_LINK_TO_LID,
	SSA_FIELD_ID_LINK_FROM_PORT_NUM,
	SSA_FIELD_ID_LINK_TO_PORT_NUM,
	SSA_FIELD_ID_LINK_MAX
};

enum ssa_db_smdb_port_fields {
	SSA_FIELD_ID_PORT_PKEY_TBL_OFFSET = 0,
	SSA_FIELD_ID_PORT_PKEY_TBL_SIZE,
	SSA_FIELD_ID_PORT_PORT_LID,
	SSA_FIELD_ID_PORT_PORT_NUM,
	SSA_FIELD_ID_PORT_NEIGHBOR_MTU,
	SSA_FIELD_ID_PORT_RATE,
	SSA_FIELD_ID_PORT_VL_ENFORCE,
	SSA_FIELD_ID_PORT_MAX
};

enum ssa_db_smdb_lft_top_fields {
	SSA_FIELD_ID_LFT_TOP_LID = 0,
	SSA_FIELD_ID_LFT_TOP_LFT_TOP,
	SSA_FIELD_ID_LFT_TOP_MAX
};

enum ssa_db_smdb_lft_block_fields {
	SSA_FIELD_ID_LFT_BLOCK_LID = 0,
	SSA_FIELD_ID_LFT_BLOCK_BLOCK_NUM,
	SSA_FIELD_ID_LFT_BLOCK_BLOCK,
	SSA_FIELD_ID_LFT_BLOCK_MAX
};

struct ep_subnet_opts_tbl_rec {
	/* change_mask bits point to the changed data fields */
	be64_t		change_mask;
	be64_t		subnet_prefix;
	uint8_t		sm_state;
	uint8_t		lmc;
	uint8_t		subnet_timeout;
	uint8_t		allow_both_pkeys;
	uint8_t		pad[4];
};

struct ep_guid_to_lid_tbl_rec {
	be64_t		guid;
	be16_t		lid;
	uint8_t		lmc;
	uint8_t		is_switch;
	uint8_t		pad[4];
};

struct ep_node_tbl_rec {
	be64_t		node_guid;
	uint8_t		is_enhanced_sp0;
	uint8_t		node_type;
	uint8_t		description[IB_NODE_DESCRIPTION_SIZE];
	uint8_t		pad[6];
};

struct ep_link_tbl_rec {
	be16_t		from_lid;
	be16_t		to_lid;
	uint8_t		from_port_num;
	uint8_t		to_port_num;
	uint8_t		pad[2];
};

struct ep_port_tbl_rec {
	be64_t		pkey_tbl_offset;
	be16_t		pkey_tbl_size;
	be16_t		port_lid;
	uint8_t		port_num;
	uint8_t		neighbor_mtu;
	uint8_t		rate; /* is_fdr10_active(1b), is_switch(1b) (appears in guid_to_lid record as well), rate(6b) */
	uint8_t		vl_enforce;
};

#define SSA_DB_PORT_RATE_MASK			0x3F
#define SSA_DB_PORT_IS_SWITCH_MASK		0x40
#define SSA_DB_PORT_IS_FDR10_ACTIVE_MASK	0x80

struct ep_lft_top_tbl_rec {
	be16_t		lid;
	be16_t		lft_top;
	uint8_t		pad[4];
};

struct ep_lft_block_tbl_rec {
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

struct ssa_db *ssa_db_smdb_init(uint64_t guid_to_lid_num_recs, uint64_t node_num_recs,
				uint64_t link_num_recs, uint64_t port_num_recs,
				uint64_t pkey_num_recs, uint64_t lft_top_num_recs,
				uint64_t lft_block_num_recs);

void ssa_db_smdb_destroy(struct ssa_db * p_smdb);

/**********************SUBNET OPTS records*******************************/
void ep_subnet_opts_tbl_rec_init(osm_subn_t *p_subn,
				 struct ep_subnet_opts_tbl_rec * p_rec);

/**********************GUID to LID records*******************************/
void ep_guid_to_lid_tbl_rec_init(osm_port_t *p_port,
				 struct ep_guid_to_lid_tbl_rec * p_rec);

/**********************NODE records**************************************/
void ep_node_tbl_rec_init(osm_node_t *p_node, struct ep_node_tbl_rec * p_rec);

/**********************LINK records**************************************/
void ep_link_tbl_rec_init(osm_physp_t *p_physp, struct ep_link_tbl_rec * p_rec);

/**********************PORT records**************************************/
void ep_port_tbl_rec_init(osm_physp_t *p_physp, struct ep_port_tbl_rec * p_rec);

/********************** LFT Block records*******************************/
void ep_lft_block_tbl_rec_init(osm_switch_t *p_sw, uint16_t lid, uint16_t block,
			       struct ep_lft_block_tbl_rec * p_rec);

/********************** LFT Top records*********************************/
void ep_lft_top_tbl_rec_init(uint16_t lid, uint16_t lft_top,
			     struct ep_lft_top_tbl_rec *p_rec);
END_C_DECLS
#endif				/* _SSA_SMDB_H_ */
