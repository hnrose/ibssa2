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

#include <ssa_log.h>
#include <infiniband/ssa_db.h>
#include <infiniband/ssa_ipdb.h>
#include <inttypes.h>
#include <asm/byteorder.h>

const char *addr_data_tbl_name[] =
		{ [IPDB_TBL_ID_IPv4] = IPDB_IPV4_TBL_NAME,
		  [IPDB_TBL_ID_IPv6] = IPDB_IPV6_TBL_NAME,
		  [IPDB_TBL_ID_NAME] = IPDB_NAME_TBL_NAME };

const struct db_table_def ip_def_tbl[] = {
	DBT_TABLE_DEF_IPV4(IPDB_TBL_ID_IPv4),
	DBF_TABLE_DEF_IPV4(IPDB_TBL_ID_IPv4, IPDB_TBL_ID_MAX),
	DBT_TABLE_DEF_IPV6(IPDB_TBL_ID_IPv6),
	DBF_TABLE_DEF_IPV6(IPDB_TBL_ID_IPv6, IPDB_TBL_ID_MAX),
	DBT_TABLE_DEF_NAME(IPDB_TBL_ID_NAME),
	DBF_TABLE_DEF_NAME(IPDB_TBL_ID_NAME, IPDB_TBL_ID_MAX),
	{ DB_VERSION_INVALID }
};

const struct db_dataset ip_dataset_tbl[] = {
	DB_DATASET(IPDB_TBL_ID_IPv4),
	DB_DATASET(IPDB_TBL_ID_IPv6),
	DB_DATASET(IPDB_TBL_ID_NAME),
	{ DB_VERSION_INVALID }
};

const struct db_dataset ip_field_dataset_tbl[] = {
	DB_DATASET(IPDB_TBL_ID_IPv4 + IPDB_TBL_ID_MAX),
	DB_DATASET(IPDB_TBL_ID_IPv6 + IPDB_TBL_ID_MAX),
	DB_DATASET(IPDB_TBL_ID_NAME + IPDB_TBL_ID_MAX),
	{ DB_VERSION_INVALID }
};

const struct db_field_def ip_field_tbl[] = {
	DB_FIELD_DEF_IPV4_QPN(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_PKEY(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_FLAGS(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_RESERVED(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_GID(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_ADDR(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV6_QPN(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_PKEY(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_FLAGS(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_RESERVED(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_GID(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_ADDR(IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6),
	DB_FIELD_DEF_NAME_QPN(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_PKEY(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_FLAGS(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_RESERVED(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_GID(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_ADDR(IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME),
	{ DB_VERSION_INVALID }
};

struct ssa_db *ssa_ipdb_create(uint64_t epoch, uint64_t num_recs[IPDB_TBL_ID_MAX])
{
	struct ssa_db *ipdb = NULL;
	uint64_t num_field_recs_arr[IPDB_TBL_ID_MAX] = {};
	size_t recs_size_arr[IPDB_TBL_ID_MAX] = {};

	recs_size_arr[IPDB_TBL_ID_IPv4]	= sizeof(struct ipdb_ipv4);
	recs_size_arr[IPDB_TBL_ID_IPv6]	= sizeof(struct ipdb_ipv6);
	recs_size_arr[IPDB_TBL_ID_NAME]	= sizeof(struct ipdb_name);

	num_field_recs_arr[IPDB_TBL_ID_IPv4] = IPDB_FIELD_ID_IPv4_MAX;
	num_field_recs_arr[IPDB_TBL_ID_IPv6] = IPDB_FIELD_ID_IPv6_MAX;
	num_field_recs_arr[IPDB_TBL_ID_NAME] = IPDB_FIELD_ID_NAME_MAX;

	ipdb = ssa_db_alloc(num_recs, recs_size_arr,
			    num_field_recs_arr, IPDB_TBL_ID_MAX);

	ssa_db_init(ipdb, "IPDB", 11 /*just some db_id */, epoch, ip_def_tbl,
		    ip_dataset_tbl, ip_field_dataset_tbl, ip_field_tbl);

	return ipdb;
}

void ssa_ipdb_attach(struct ssa_db *ssa_db, struct ssa_db *ipdb)
{
	int i, ret = 0;

	for (i = 0; i < IPDB_TBL_ID_MAX; i++) {
		ret = ssa_db_attach(ssa_db, ipdb, addr_data_tbl_name[i]);
		if (ret < 0)
			ssa_log_err(SSA_LOG_DEFAULT,
				    "unable to attach %s table from %s %p "
				    "epoch 0x%" PRIx64 " to %s %p epoch "
				    "0x%" PRIx64 "\n", addr_data_tbl_name[i],
				    ipdb->db_def.name, ipdb,
				    ssa_db_get_epoch(ipdb, DB_DEF_TBL_ID),
				    ssa_db->db_def.name, ssa_db,
				    ssa_db_get_epoch(ssa_db, DB_DEF_TBL_ID));
	}
}

void ssa_ipdb_detach(struct ssa_db *ssa_db)
{
	int i;

	for (i = 0; i < IPDB_TBL_ID_MAX; i++)
		ssa_db_detach(ssa_db, addr_data_tbl_name[i]);
}
