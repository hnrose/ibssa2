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

#ifndef _SSA_PR_DB_H_
#define _SSA_PR_DB_H_

#include <infiniband/ssa_db.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

enum ssa_prdb_table_id {
	SSA_PR_TABLE_ID = 0,
	SSA_PR_TABLE_ID_MAX
};

enum ssa_prdb_field_table_id {
	SSA_PR_TABLE_ID_FIELD_DEF = SSA_PR_TABLE_ID_MAX,
	SSA_PR_TABLE_ID_FIELD_DEF_MAX
};
enum ssa_prdb_ids {
	SSA_PR_FIELD_ID_PR_DGUID,
	SSA_PR_FIELD_ID_PR_DLID,
	SSA_PR_FIELD_ID_PR_MTU,
	SSA_PR_FIELD_ID_PR_RATE,
	SSA_PR_FIELD_ID_PR_SL,
	SSA_PR_FIELD_ID_PR_PK,
	SSA_PR_FIELD_ID_PR_REVERSIBLE,
	SSA_PR_FIELDS_ID_MAX
};

struct ep_pr_tbl_rec {
	be64_t		guid;
	be16_t		lid;
	be16_t		pk;
	uint8_t		mtu;
	uint8_t		rate;
	uint8_t		sl;
	uint8_t		is_reversible;
};

END_C_DECLS
#endif				/* _SSA_PR_DB_H_ */
