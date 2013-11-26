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

#ifndef _SSA_DATABASE_H_
#define _SSA_DATABASE_H_

#include <iba/ib_types.h>
#include <complib/cl_ptr_vector.h>
#include <complib/cl_qmap.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

struct ep_map_rec {
	cl_map_item_t	map_item;
	uint64_t	offset;
};

struct ssa_db_lft {
	struct ep_lft_top_tbl_rec	*p_db_lft_top_tbl;
	struct ep_lft_block_tbl_rec	*p_db_lft_block_tbl;
	struct ep_lft_top_tbl_rec	*p_dump_lft_top_tbl;
	struct ep_lft_block_tbl_rec	*p_dump_lft_block_tbl;

	cl_qmap_t ep_db_lft_block_tbl;		/* LID + block_num based */
	cl_qmap_t ep_db_lft_top_tbl;		/* LID based */
	cl_qmap_t ep_dump_lft_block_tbl;	/* LID + block_num based */
	cl_qmap_t ep_dump_lft_top_tbl;		/* LID based */
};

struct ssa_db_extract {
	/* mutex ??? */
	struct ep_guid_to_lid_tbl_rec	*p_guid_to_lid_tbl;
	struct ep_node_tbl_rec		*p_node_tbl;
	struct ep_link_tbl_rec		*p_link_tbl;
	struct ep_port_tbl_rec		*p_port_tbl;
	uint16_t			*p_pkey_tbl;
	uint64_t			pkey_tbl_rec_num;

	cl_qmap_t ep_guid_to_lid_tbl;	/* port GUID -> offset */
	cl_qmap_t ep_node_tbl;		/* node GUID -> offset */
	cl_qmap_t ep_port_tbl;		/* LID + port_num based*/
	cl_qmap_t ep_link_tbl;		/* LID + port_num based */

	/* Fabric/SM related */
	uint64_t subnet_prefix;		/* even if full PortInfo used */
	uint8_t sm_state;
	uint8_t lmc;
	uint8_t subnet_timeout;
	boolean_t allow_both_pkeys;
	/* boolean_t qos; */
	/* prefix_routes */
	uint8_t initialized;
};

struct ssa_database {
	/* mutex ??? */
	struct ssa_db_extract *p_current_db;
	struct ssa_db_extract *p_previous_db;
	struct ssa_db_extract *p_dump_db;
	struct ssa_db_lft *p_lft_db;
	pthread_mutex_t lft_rec_list_lock;
	cl_qlist_t lft_rec_list;
};

extern struct ssa_database *ssa_db;

/**********************SSA Database**************************************/
struct ssa_database *ssa_database_init(void);
void ssa_database_delete(struct ssa_database *p_ssa_db);
/**********************SSA DB********************************************/
struct ssa_db_extract *ssa_db_extract_init(void);
void ssa_db_extract_delete(struct ssa_db_extract *p_ssa_db);
/***********************************************************************/
uint64_t ep_rec_gen_key(uint16_t base, uint16_t index);
struct ep_map_rec *ep_map_rec_init(uint64_t offset);
void ep_map_rec_delete(struct ep_map_rec *p_map_rec);
void ep_map_rec_delete_pfn(cl_map_item_t *p_map_item);
void ep_qmap_clear(cl_qmap_t *p_map);
void ssa_qmap_apply_func(cl_qmap_t *p_qmap, void (*destroy_pfn)(cl_map_item_t *));
END_C_DECLS
#endif				/* _SSA_DATABASE_H_ */
