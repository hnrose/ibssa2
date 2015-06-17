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
	SSA_IPv4_TABLE_ID,
	SSA_IPv6_TABLE_ID,
	SSA_NAME_TABLE_ID,
	SSA_PR_TABLE_ID_MAX
};

enum ssa_prdb_field_table_id {
	SSA_PR_TABLE_ID_FIELD_DEF = SSA_PR_TABLE_ID_MAX,
	SSA_IPv4_TABLE_ID_FIELD_DEF,
	SSA_IPv6_TABLE_ID_FIELD_DEF,
	SSA_NAME_TABLE_ID_FIELD_DEF,
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

enum ssa_prdb_ipv4_fields {
	SSA_PR_FIELD_ID_IPv4_QPN,
	SSA_PR_FIELD_ID_IPv4_PKEY,
	SSA_PR_FIELD_ID_IPv4_FLAGS,
	SSA_PR_FIELD_ID_IPv4_GID,
	SSA_PR_FIELD_ID_IPv4_ADDR,
	SSA_PR_FIELDS_ID_IPv4_MAX
};

enum ssa_prdb_ipv6_fields {
	SSA_PR_FIELD_ID_IPv6_QPN,
	SSA_PR_FIELD_ID_IPv6_PKEY,
	SSA_PR_FIELD_ID_IPv6_FLAGS,
	SSA_PR_FIELD_ID_IPv6_GID,
	SSA_PR_FIELD_ID_IPv6_ADDR,
	SSA_PR_FIELDS_ID_IPv6_MAX
};

enum ssa_prdb_name_fields {
	SSA_PR_FIELD_ID_NAME_QPN,
	SSA_PR_FIELD_ID_NAME_PKEY,
	SSA_PR_FIELD_ID_NAME_FLAGS,
	SSA_PR_FIELD_ID_NAME_GID,
	SSA_PR_FIELD_ID_NAME_ADDR,
	SSA_PR_FIELDS_ID_NAME_MAX
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

struct ep_ipv4_tbl_rec {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[4];
	uint8_t		pad[5];
};

struct ep_ipv6_tbl_rec {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[16];
	uint8_t		reserved;
};

struct ep_name_tbl_rec {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[64];
	uint8_t		reserved;
};

extern struct ssa_db  *ssa_prdb_create(uint64_t epoch, uint64_t num_recs[SSA_PR_TABLE_ID_MAX]);

END_C_DECLS
#endif				/* _SSA_PR_DB_H_ */
