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

struct ssa_db *ssa_ipdb_create(uint64_t epoch, uint64_t num_recs[IPDB_TBL_ID_MAX]);

END_C_DECLS
#endif				/* _SSA_IPDB_H_ */
