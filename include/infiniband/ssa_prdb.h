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

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

enum prdb_tbl_id {
	PRDB_TBL_ID_PR = 0,
	PRDB_TBL_ID_IPv4,
	PRDB_TBL_ID_IPv6,
	PRDB_TBL_ID_NAME,
	PRDB_TBL_ID_MAX
};

enum prdb_field_tbl_id {
	PRDB_FIELD_TBL_ID_PR = PRDB_TBL_ID_MAX,
	PRDB_FIELD_TBL_ID_IPv4,
	PRDB_FIELD_TBL_ID_IPv6,
	PRDB_FIELD_TBL_ID_NAME,
	PRDB_FIELD_TBL_ID_MAX
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

enum prdb_ipv4_fields {
	PRDB_FIELD_ID_IPv4_QPN,
	PRDB_FIELD_ID_IPv4_PKEY,
	PRDB_FIELD_ID_IPv4_FLAGS,
	PRDB_FIELD_ID_IPv4_GID,
	PRDB_FIELD_ID_IPv4_ADDR,
	PRDB_FIELD_ID_IPv4_MAX
};

enum prdb_ipv6_fields {
	PRDB_FIELD_ID_IPv6_QPN,
	PRDB_FIELD_ID_IPv6_PKEY,
	PRDB_FIELD_ID_IPv6_FLAGS,
	PRDB_FIELD_ID_IPv6_GID,
	PRDB_FIELD_ID_IPv6_ADDR,
	PRDB_FIELD_ID_IPv6_MAX
};

enum prdb_name_fields {
	PRDB_FIELD_ID_NAME_QPN,
	PRDB_FIELD_ID_NAME_PKEY,
	PRDB_FIELD_ID_NAME_FLAGS,
	PRDB_FIELD_ID_NAME_GID,
	PRDB_FIELD_ID_NAME_ADDR,
	PRDB_FIELD_ID_NAME_MAX
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

struct prdb_ipv4 {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[4];
	uint8_t		pad[5];
};

struct prdb_ipv6 {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[16];
	uint8_t		reserved;
};

struct prdb_name {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		gid[16];
	uint8_t		addr[64];
	uint8_t		reserved;
};

extern struct ssa_db  *ssa_prdb_create(uint64_t epoch, uint64_t num_recs[PRDB_TBL_ID_MAX]);

END_C_DECLS
#endif				/* _SSA_PR_DB_H_ */
