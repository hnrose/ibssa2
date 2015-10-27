/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

#ifndef _SSA_IPDB_H_
#define _SSA_IPDB_H_

#include <infiniband/ssa_db.h>

#define IPDB_IPV4_TBL_NAME "IPv4"
#define IPDB_IPV6_TBL_NAME "IPv6"
#define IPDB_NAME_TBL_NAME "NAME"

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

enum ipdb_tbl_id {
	IPDB_TBL_ID_IPv4 = 0,
	IPDB_TBL_ID_IPv6,
	IPDB_TBL_ID_NAME,
	IPDB_TBL_ID_MAX
};

enum  ipdb_ipv4_fields {
	IPDB_FIELD_ID_IPv4_QPN,
	IPDB_FIELD_ID_IPv4_PKEY,
	IPDB_FIELD_ID_IPv4_FLAGS,
	IPDB_FIELD_ID_IPv4_RESERVED,
	IPDB_FIELD_ID_IPv4_GID,
	IPDB_FIELD_ID_IPv4_ADDR,
	IPDB_FIELD_ID_IPv4_MAX
};

enum ipdb_ipv6_fields {
	IPDB_FIELD_ID_IPv6_QPN,
	IPDB_FIELD_ID_IPv6_PKEY,
	IPDB_FIELD_ID_IPv6_FLAGS,
	IPDB_FIELD_ID_IPv6_RESERVED,
	IPDB_FIELD_ID_IPv6_GID,
	IPDB_FIELD_ID_IPv6_ADDR,
	IPDB_FIELD_ID_IPv6_MAX
};

enum ipdb_name_fields {
	IPDB_FIELD_ID_NAME_QPN,
	IPDB_FIELD_ID_NAME_PKEY,
	IPDB_FIELD_ID_NAME_FLAGS,
	IPDB_FIELD_ID_NAME_RESERVED,
	IPDB_FIELD_ID_NAME_GID,
	IPDB_FIELD_ID_NAME_ADDR,
	IPDB_FIELD_ID_NAME_MAX
};

struct ipdb_ipv4 {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		reserved;
	uint8_t		gid[16];
	uint8_t		addr[4];
	uint8_t		pad[4];
};

struct ipdb_ipv6 {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		reserved;
	uint8_t		gid[16];
	uint8_t		addr[16];
};

struct ipdb_name {
	be32_t		qpn;
	be16_t		pkey;
	uint8_t		flags;
	uint8_t		reserved;
	uint8_t		gid[16];
	uint8_t		addr[64];
};

#define IPDB_FIELDS	(IPDB_FIELD_ID_IPv4_MAX + \
			 IPDB_FIELD_ID_IPv6_MAX + \
			 IPDB_FIELD_ID_NAME_MAX)

#define DBT_TABLE_DEF_IPV4(id) DBT_TABLE_DEF(id, IPDB_IPV4_TBL_NAME, sizeof(struct ipdb_ipv4))
#define DBT_TABLE_DEF_IPV6(id) DBT_TABLE_DEF(id, IPDB_IPV6_TBL_NAME, sizeof(struct ipdb_ipv6))
#define DBT_TABLE_DEF_NAME(id) DBT_TABLE_DEF(id, IPDB_NAME_TBL_NAME, sizeof(struct ipdb_name))

#define DBF_TABLE_DEF_IPV4(id, offset) DBF_TABLE_DEF(id, offset, IPDB_IPV4_TBL_NAME)
#define DBF_TABLE_DEF_IPV6(id, offset) DBF_TABLE_DEF(id, offset, IPDB_IPV6_TBL_NAME)
#define DBF_TABLE_DEF_NAME(id, offset) DBF_TABLE_DEF(id, offset, IPDB_NAME_TBL_NAME)

#define DB_FIELD_DEF_IPV4_QPN(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET32, tbl_id, IPDB_FIELD_ID_IPv4_QPN, "qpn", 32, 0)
#define DB_FIELD_DEF_IPV4_PKEY(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, IPDB_FIELD_ID_IPv4_PKEY, "pkey", 16, 32)
#define DB_FIELD_DEF_IPV4_FLAGS(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv4_FLAGS, "flags", 8, 48)
#define DB_FIELD_DEF_IPV4_RESERVED(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv4_RESERVED, "reserved", 8, 56)
#define DB_FIELD_DEF_IPV4_GID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv4_GID, "gid", 8 * 16, 64)
#define DB_FIELD_DEF_IPV4_ADDR(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv4_ADDR, "ipv4_address", 8 * 4, 192)

#define DB_FIELD_DEF_IPV6_QPN(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET32, tbl_id, IPDB_FIELD_ID_IPv6_QPN, "qpn", 32, 0)
#define DB_FIELD_DEF_IPV6_PKEY(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, IPDB_FIELD_ID_IPv6_PKEY, "pkey", 16, 32)
#define DB_FIELD_DEF_IPV6_FLAGS(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv6_FLAGS, "flags", 8, 48)
#define DB_FIELD_DEF_IPV6_RESERVED(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv6_RESERVED, "reserved", 8, 56)
#define DB_FIELD_DEF_IPV6_GID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv6_GID, "gid", 8 * 16, 64)
#define DB_FIELD_DEF_IPV6_ADDR(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_IPv6_ADDR, "ipv6_address", 8 * 16, 192)

#define DB_FIELD_DEF_NAME_QPN(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET32, tbl_id, IPDB_FIELD_ID_NAME_QPN, "qpn", 32, 0)
#define DB_FIELD_DEF_NAME_PKEY(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_NET16, tbl_id, IPDB_FIELD_ID_NAME_PKEY, "pkey", 16, 32)
#define DB_FIELD_DEF_NAME_FLAGS(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_NAME_FLAGS, "flags", 8, 48)
#define DB_FIELD_DEF_NAME_RESERVED(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_NAME_RESERVED, "reserved", 8, 56)
#define DB_FIELD_DEF_NAME_GID(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_NAME_GID, "gid", 8 * 16, 64)
#define DB_FIELD_DEF_NAME_ADDR(tbl_id) \
	DB_FIELD_DEF(DBF_TYPE_U8, tbl_id, IPDB_FIELD_ID_NAME_ADDR, "name_address", 8 * 64, 192)

struct ssa_db *ssa_ipdb_create(uint64_t epoch, uint64_t num_recs[IPDB_TBL_ID_MAX]);
void ssa_ipdb_attach(struct ssa_db *ssa_db, struct ssa_db *ipdb);
void ssa_ipdb_detach(struct ssa_db *ssa_db);

END_C_DECLS
#endif				/* _SSA_IPDB_H_ */
