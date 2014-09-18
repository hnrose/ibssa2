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

#ifndef _SSA_EXTRACT_H_
#define _SSA_EXTRACT_H_

#include <infiniband/osm_headers.h>
#include <infiniband/ssa_database.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else				/* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif				/* __cplusplus */

BEGIN_C_DECLS

enum ssa_db_ctrl_msg_type {
	SSA_DB_START_EXTRACT = 1,
	SSA_DB_LFT_CHANGE,
	SSA_DB_EXIT
};

struct ssa_db_ctrl_msg {
	int				len;
	enum ssa_db_ctrl_msg_type	type;
	uint8_t				data[0];
};

struct ssa_db_lft_change_rec {
       cl_list_item_t                  list_item;
       osm_epi_lft_change_event_t      lft_change;
       be16_t                          lid;
       uint8_t                         block[0];
};

struct ssa_db_extract *ssa_db_extract(osm_opensm_t *p_osm);
void ssa_db_validate(struct ssa_db_extract *p_ssa_db);
void ssa_db_validate_lft(int first);
void ssa_db_update(struct ssa_database *ssa_db);
void ssa_db_lft_handle(void);
END_C_DECLS
#endif				/* _SSA_EXTRACT_H_ */
