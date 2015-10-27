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

#include <infiniband/ssa_db.h>
#include <infiniband/ssa_prdb.h>
#include <asm/byteorder.h>

static struct db_table_def def_tbl[] = {
	DBT_TABLE_DEF_PR(PRDB_TBL_ID_PR),
	DBF_TABLE_DEF_PR(PRDB_TBL_ID_PR, PRDB_TBL_ID_MAX),
	DBT_TABLE_DEF_IPV4(PRDB_TBL_ID_IPv4),
	DBF_TABLE_DEF_IPV4(PRDB_TBL_ID_IPv4, PRDB_TBL_ID_MAX),
	DBT_TABLE_DEF_IPV6(PRDB_TBL_ID_IPv6),
	DBF_TABLE_DEF_IPV6(PRDB_TBL_ID_IPv6, PRDB_TBL_ID_MAX),
	DBT_TABLE_DEF_NAME(PRDB_TBL_ID_NAME),
	DBF_TABLE_DEF_NAME(PRDB_TBL_ID_NAME, PRDB_TBL_ID_MAX),
	{ DB_VERSION_INVALID }
};

static struct db_dataset dataset_tbl[] = {
	DB_DATASET(PRDB_TBL_ID_PR),
	DB_DATASET(PRDB_TBL_ID_IPv4),
	DB_DATASET(PRDB_TBL_ID_IPv6),
	DB_DATASET(PRDB_TBL_ID_NAME),
	{ DB_VERSION_INVALID }
};

static struct db_dataset field_dataset_tbl[] = {
	DB_DATASET(PRDB_TBL_ID_PR + PRDB_TBL_ID_MAX),
	DB_DATASET(PRDB_TBL_ID_IPv4 + PRDB_TBL_ID_MAX),
	DB_DATASET(PRDB_TBL_ID_IPv6 + PRDB_TBL_ID_MAX),
	DB_DATASET(PRDB_TBL_ID_NAME + PRDB_TBL_ID_MAX),
	{ DB_VERSION_INVALID }
};

static struct db_field_def field_tbl[] = {
	DB_FIELD_DEF_PR_DGUID(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_DLID(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_PK(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_MTU(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_RATE(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_SL(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_PR_REVERSIBLE(PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR),
	DB_FIELD_DEF_IPV4_QPN(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_PKEY(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_FLAGS(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_RESERVED(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_GID(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV4_ADDR(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv4),
	DB_FIELD_DEF_IPV6_QPN(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_PKEY(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_FLAGS(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_RESERVED(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_GID(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_IPV6_ADDR(PRDB_TBL_ID_MAX + PRDB_TBL_ID_IPv6),
	DB_FIELD_DEF_NAME_QPN(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_PKEY(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_FLAGS(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_RESERVED(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_GID(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	DB_FIELD_DEF_NAME_ADDR(PRDB_TBL_ID_MAX + PRDB_TBL_ID_NAME),
	{ DB_VERSION_INVALID }
};

/** =========================================================================
 */
struct ssa_db  *ssa_prdb_create(uint64_t epoch, uint64_t num_recs[PRDB_TBL_ID_MAX])
{
	struct ssa_db *p_ssa_db = NULL;
	uint64_t num_field_recs_arr[PRDB_TBL_ID_MAX] = {};
	size_t recs_size_arr[PRDB_TBL_ID_MAX] = {};

	recs_size_arr[PRDB_TBL_ID_PR]	= sizeof(struct prdb_pr);
	recs_size_arr[PRDB_TBL_ID_IPv4]	= sizeof(struct ipdb_ipv4);
	recs_size_arr[PRDB_TBL_ID_IPv6]	= sizeof(struct ipdb_ipv6);
	recs_size_arr[PRDB_TBL_ID_NAME]	= sizeof(struct ipdb_name);

	num_field_recs_arr[PRDB_TBL_ID_PR]	= PRDB_FIELD_ID_PR_MAX;
	num_field_recs_arr[PRDB_TBL_ID_IPv4]	= IPDB_FIELD_ID_IPv4_MAX;
	num_field_recs_arr[PRDB_TBL_ID_IPv6]	= IPDB_FIELD_ID_IPv6_MAX;
	num_field_recs_arr[PRDB_TBL_ID_NAME]	= IPDB_FIELD_ID_NAME_MAX;

	p_ssa_db = ssa_db_alloc(num_recs, recs_size_arr,
				num_field_recs_arr, PRDB_TBL_ID_MAX);

	ssa_db_init(p_ssa_db, "PRDB", 10 /*just some db_id */, epoch, def_tbl,
		    dataset_tbl, field_dataset_tbl, field_tbl);

	return p_ssa_db;
}
