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

extern struct db_table_def	ip_def_tbl[];
extern struct db_dataset	ip_dataset_tbl[];
extern struct db_dataset	ip_field_dataset_tbl[];
extern struct db_field_def	ip_field_tbl[];

static struct db_table_def def_tbl[] = {
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DATA, 0, { 0, PRDB_TBL_ID_PR, 0 },
		"PR", __constant_htonl(sizeof(struct prdb_pr)), 0 },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DEF, 0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, 0 },
		"PR fields", __constant_htonl(sizeof(struct db_field_def)), __constant_htonl(PRDB_TBL_ID_PR) },
	[PRDB_TBLS] = { DB_VERSION_INVALID }
};

static struct db_dataset dataset_tbl[] = {
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, PRDB_TBL_ID_PR, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	[PRDB_DATA_TBLS] = { DB_VERSION_INVALID }
};

static struct db_dataset field_dataset_tbl[] = {
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	[PRDB_DATA_TBLS] = { DB_VERSION_INVALID }
};

static struct db_field_def field_tbl[] = {
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET64, 0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_DGUID      }, "guid",       __constant_htonl(64),                  0    },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET16, 0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_DLID       }, "dlid",       __constant_htonl(16), __constant_htonl(64)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET16, 0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_PK         }, "pkey",       __constant_htonl(16), __constant_htonl(80)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_MTU        }, "mtu",        __constant_htonl(8),  __constant_htonl(96)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_RATE       }, "rate",       __constant_htonl(8),  __constant_htonl(104) },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_SL         }, "sl",         __constant_htonl(8),  __constant_htonl(112) },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, PRDB_TBL_ID_MAX + PRDB_TBL_ID_PR, PRDB_FIELD_ID_PR_REVERSIBLE }, "reversible", __constant_htonl(8),  __constant_htonl(120) },
	[PRDB_FIELDS] = { DB_VERSION_INVALID }
};

static void prdb_attach_ipdb()
{
	int i = 0;
	uint8_t offset;

	offset = PRDB_TBL_OFFSET * 2;
	for (i = offset; i < PRDB_TBLS; i++) {
		def_tbl[i] = ip_def_tbl[i - offset];
		if (def_tbl[i].type == DBT_TYPE_DATA) {
			def_tbl[i].id.table += PRDB_TBL_OFFSET;
		} else if (def_tbl[i].type == DBT_TYPE_DEF) {
			def_tbl[i].id.table +=
				PRDB_DATA_TBLS + PRDB_TBL_OFFSET - IPDB_TBL_ID_MAX;
			def_tbl[i].ref_table_id =
				htonl(ntohl(def_tbl[i].ref_table_id) +
					    PRDB_TBL_OFFSET);
		}
	}

	offset = PRDB_TBL_OFFSET;
	for (i = offset; i < PRDB_DATA_TBLS; i++) {
		dataset_tbl[i] = ip_dataset_tbl[i - offset];
		dataset_tbl[i].id.table += offset;
	}

	offset = PRDB_TBL_OFFSET;
	for (i = offset; i < PRDB_DATA_TBLS; i++) {
		field_dataset_tbl[i] = ip_field_dataset_tbl[i - offset];
		field_dataset_tbl[i].id.table +=
			PRDB_DATA_TBLS + PRDB_TBL_OFFSET - IPDB_TBL_ID_MAX;
	}

	offset = PRDB_FIELDS - IPDB_FIELDS;
	for (i = offset; i < PRDB_FIELDS; i++) {
		field_tbl[i] = ip_field_tbl[i - offset];
		field_tbl[i].id.table +=
			PRDB_DATA_TBLS + PRDB_TBL_OFFSET - IPDB_TBL_ID_MAX;
	}
}

/** =========================================================================
 */
struct ssa_db  *ssa_prdb_create(uint64_t epoch, uint64_t num_recs[PRDB_DATA_TBLS])
{
	struct ssa_db *p_ssa_db = NULL;
	uint64_t num_field_recs_arr[PRDB_DATA_TBLS] = {};
	size_t recs_size_arr[PRDB_DATA_TBLS] = {};

	recs_size_arr[PRDB_TBL_ID_PR]	= sizeof(struct prdb_pr);
	recs_size_arr[PRDB_TBL_ID_IPv4]	= sizeof(struct ipdb_ipv4);
	recs_size_arr[PRDB_TBL_ID_IPv6]	= sizeof(struct ipdb_ipv6);
	recs_size_arr[PRDB_TBL_ID_NAME]	= sizeof(struct ipdb_name);

	num_field_recs_arr[PRDB_TBL_ID_PR]	= PRDB_FIELD_ID_PR_MAX;
	num_field_recs_arr[PRDB_TBL_ID_IPv4]	= IPDB_FIELD_ID_IPv4_MAX;
	num_field_recs_arr[PRDB_TBL_ID_IPv6]	= IPDB_FIELD_ID_IPv6_MAX;
	num_field_recs_arr[PRDB_TBL_ID_NAME]	= IPDB_FIELD_ID_NAME_MAX;

	p_ssa_db = ssa_db_alloc(num_recs, recs_size_arr,
				num_field_recs_arr, PRDB_DATA_TBLS);

	prdb_attach_ipdb();

	ssa_db_init(p_ssa_db, "PRDB", 10 /*just some db_id */, epoch, def_tbl,
		    dataset_tbl, field_dataset_tbl, field_tbl);

	return p_ssa_db;
}
