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
		{ [IPDB_TBL_ID_IPv4] = "IPv4",
		  [IPDB_TBL_ID_IPv6] = "IPv6",
		  [IPDB_TBL_ID_NAME] = "NAME" };

const struct db_table_def ip_def_tbl[] = {
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DATA, 0, { 0, IPDB_TBL_ID_IPv4, 0 },
		"IPv4", __constant_htonl(sizeof(struct ipdb_ipv4)), 0 },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DEF, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, 0 },
		"IPv4 fields", __constant_htonl(sizeof(struct db_field_def)), __constant_htonl(IPDB_TBL_ID_IPv4) },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DATA, 0, { 0, IPDB_TBL_ID_IPv6, 0 },
		"IPv6", __constant_htonl(sizeof(struct ipdb_ipv6)), 0 },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DEF, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, 0 },
		"IPv6 fields", __constant_htonl(sizeof(struct db_field_def)), __constant_htonl(IPDB_TBL_ID_IPv6) },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DATA, 0, { 0, IPDB_TBL_ID_NAME, 0 },
		"NAME", __constant_htonl(sizeof(struct ipdb_name)), 0 },
	{ DBT_DEF_VERSION, sizeof(struct db_table_def), DBT_TYPE_DEF, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, 0 },
		"NAME fields", __constant_htonl(sizeof(struct db_field_def)), __constant_htonl(IPDB_TBL_ID_NAME) },
	{ DB_VERSION_INVALID }
};

const struct db_dataset ip_dataset_tbl[] = {
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_IPv4, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_IPv6, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_NAME, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_VERSION_INVALID }
};

const struct db_dataset ip_field_dataset_tbl[] = {
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_DS_VERSION, sizeof(struct db_dataset), 0, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, 0 }, DB_EPOCH_INVALID, 0, 0, 0 },
	{ DB_VERSION_INVALID }
};

const struct db_field_def ip_field_tbl[] = {
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET32, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_QPN      }, "qpn",          __constant_htonl(32),                      0    },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET16, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_PKEY     }, "pkey",         __constant_htonl(16),     __constant_htonl(32)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_FLAGS    }, "flags",        __constant_htonl(8),      __constant_htonl(48)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_RESERVED }, "reserved",     __constant_htonl(8),      __constant_htonl(56)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_GID      }, "gid",          __constant_htonl(8 * 16), __constant_htonl(64)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv4, IPDB_FIELD_ID_IPv4_ADDR     }, "ipv4_address", __constant_htonl(8 * 4),  __constant_htonl(192) },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET32, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_QPN      }, "qpn",          __constant_htonl(32),                      0    },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET16, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_PKEY     }, "pkey",         __constant_htonl(16),     __constant_htonl(32)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_FLAGS    }, "flags",        __constant_htonl(8),      __constant_htonl(48)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_RESERVED }, "reserved",     __constant_htonl(8),      __constant_htonl(56)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_GID      }, "gid",          __constant_htonl(8 * 16), __constant_htonl(64)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_IPv6, IPDB_FIELD_ID_IPv6_ADDR     }, "ipv6_address", __constant_htonl(8 * 16), __constant_htonl(192) },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET32, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_QPN      }, "qpn",          __constant_htonl(32),                      0    },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_NET16, 0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_PKEY     }, "pkey",         __constant_htonl(16),     __constant_htonl(32)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_FLAGS    }, "flags",        __constant_htonl(8),      __constant_htonl(48)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_RESERVED }, "reserved",     __constant_htonl(8),      __constant_htonl(56)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_GID      }, "gid",          __constant_htonl(8 * 16), __constant_htonl(64)  },
	{ DBF_DEF_VERSION, 0, DBF_TYPE_U8,    0, { 0, IPDB_TBL_ID_MAX + IPDB_TBL_ID_NAME, IPDB_FIELD_ID_NAME_ADDR     }, "name_address", __constant_htonl(8 * 64), __constant_htonl(192) },
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
				    "epoch 0x" PRIx64 " to %s %p epoch "
				    "0x" PRIx64 "\n", addr_data_tbl_name[i],
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
