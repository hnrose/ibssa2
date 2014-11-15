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

#ifndef _SSA_COMPARISON_H_
#define _SSA_COMPARISON_H_

#include <infiniband/osm_headers.h>
#include <infiniband/ssa_database.h>
#include <infiniband/ssa_smdb.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

/* used for making comparison between two ssa databases */
struct ssa_db_diff {
	struct ssa_db		*p_smdb;

	/***** guid_to_lid_tbl changes tracking **********/
	cl_qmap_t ep_guid_to_lid_tbl_added;
	cl_qmap_t ep_guid_to_lid_tbl_removed;
	/*************************************************/
	/********* node_tbl  changes tracking ************/
	cl_qmap_t ep_node_tbl_added;
	cl_qmap_t ep_node_tbl_removed;
	/*************************************************/
	/********** port_tbl changes tracking ************/
	cl_qmap_t ep_port_tbl_added;
	cl_qmap_t ep_port_tbl_removed;
	/*************************************************/
	/********** LFT changes tracking *****************/
	cl_qmap_t ep_lft_block_tbl;
	cl_qmap_t ep_lft_top_tbl;
	/*************************************************/
	/********** link_tbl changes tracking ************/
	cl_qmap_t ep_link_tbl_added;
	cl_qmap_t ep_link_tbl_removed;
	/*************************************************/

	/* TODO: add support for changes in SLVL and in future for QoS and LFTs */
	uint8_t dirty;
};

struct ssa_db_diff *ssa_db_diff_init(uint64_t epoch, uint64_t data_rec_cnt[SSA_TABLE_ID_MAX]);
void ssa_db_diff_destroy(struct ssa_db_diff * p_ssa_db_diff);
struct ssa_db_diff *ssa_db_compare(struct ssa_database * ssa_db,
				   uint64_t epoch_prev, int first);

END_C_DECLS
#endif				/* _SSA_COMPARISON_H_ */
