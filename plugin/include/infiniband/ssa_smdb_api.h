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

#ifndef _SSA_SMDB_API_H_
#define _SSA_SMDB_API_H_

#include <infiniband/ssa_smdb.h>
#include <infiniband/osm_headers.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

void ep_subnet_opts_tbl_rec_init(osm_subn_t *p_subn,
				 struct ep_subnet_opts_tbl_rec * p_rec);
void ep_guid_to_lid_tbl_rec_init(osm_port_t *p_port,
				 struct ep_guid_to_lid_tbl_rec * p_rec);
void ep_node_tbl_rec_init(osm_node_t *p_node, struct ep_node_tbl_rec * p_rec);
void ep_link_tbl_rec_init(osm_physp_t *p_physp, struct ep_link_tbl_rec * p_rec);
void ep_port_tbl_rec_init(osm_physp_t *p_physp, struct ep_port_tbl_rec * p_rec);
void ep_lft_block_tbl_rec_init(osm_switch_t *p_sw, uint16_t lid, uint16_t block,
			       struct ep_lft_block_tbl_rec * p_rec);
void ep_lft_top_tbl_rec_init(uint16_t lid, uint16_t lft_top,
			     struct ep_lft_top_tbl_rec *p_rec);
END_C_DECLS
#endif				/* _SSA_SMDB_API_H_ */
