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

#ifndef _SSA_PR_DB_H_
#define _SSA_PR_DB_H_

#include <infiniband/ssa_db.h>
#include <infiniband/ssa_ipdb.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

#define PRDB_PR_TBL_NAME "PR"

enum prdb_tbl_id {
	PRDB_TBL_ID_PR = 0,
	PRDB_TBL_ID_IPv4,
	PRDB_TBL_ID_IPv6,
	PRDB_TBL_ID_NAME,
	PRDB_TBL_ID_MAX
};

enum prdb_pr_fields {
	PRDB_FIELD_ID_PR_DGUID,
	PRDB_FIELD_ID_PR_DLID,
	PRDB_FIELD_ID_PR_PK,
	PRDB_FIELD_ID_PR_MTU,
	PRDB_FIELD_ID_PR_RATE,
	PRDB_FIELD_ID_PR_SL,
	PRDB_FIELD_ID_PR_REVERSIBLE,
	PRDB_FIELD_ID_PR_MAX
};

struct prdb_pr {
	be64_t		guid;
	be16_t		lid;
	be16_t		pk;
	uint8_t		mtu;
	uint8_t		rate;
	uint8_t		sl;
	uint8_t		is_reversible;
};

#define DBT_TABLE_DEF_PR(id) DBT_TABLE_DEF(id, PRDB_PR_TBL_NAME, sizeof(struct prdb_pr))

#define DBF_TABLE_DEF_PR(id, offset) DBF_TABLE_DEF(id, offset, PRDB_PR_TBL_NAME)

#define DB_FIELD_DEF_PR_DGUID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET64, tbl_id, PRDB_FIELD_ID_PR_DGUID, "guid", 64, 0)
#define DB_FIELD_DEF_PR_DLID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, PRDB_FIELD_ID_PR_DLID, "guid", 16, 64)
#define DB_FIELD_DEF_PR_PK(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, PRDB_FIELD_ID_PR_PK, "pkey", 16, 80)
#define DB_FIELD_DEF_PR_MTU(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, PRDB_FIELD_ID_PR_MTU, "mtu", 8, 96)
#define DB_FIELD_DEF_PR_RATE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, PRDB_FIELD_ID_PR_RATE, "rate", 8, 104)
#define DB_FIELD_DEF_PR_SL(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, PRDB_FIELD_ID_PR_SL, "sl", 8, 112)
#define DB_FIELD_DEF_PR_REVERSIBLE(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, PRDB_FIELD_ID_PR_REVERSIBLE, "reversible", 8, 120)

extern struct ssa_db  *ssa_prdb_create(uint64_t epoch, uint64_t num_recs[PRDB_TBL_ID_MAX]);

END_C_DECLS
#endif				/* _SSA_PR_DB_H_ */
