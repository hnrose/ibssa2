/*
 * Copyright (c) 2012 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012 Intel Corporation. All rights reserved.
 * Copyright (c) 2012 Lawrence Livermore National Securities.  All rights reserved.
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


#ifndef __IBSSA_DB_H__
#define __IBSSA_DB_H__

#define IBSSA_DB_NAME_LEN 64

/*
 * Definitions to allow for generic processing of any data
 * E.g. useful for dumping table data to a log
 */
enum field_type {
	field_uint8,
	field_uint16,
	field_uint32,
	field_uint64,
	field_guid = field_uint64
	field_uint128,
	field_gid = field_uint128
	/* ... */
};

/* All fields defs belonging to the same table are assigned a unique identifier */
struct field_def {
	char     name[IBSSA_DB_NAME_LEN];
	be32_t   type;
	be32_t   guid;
};

/* Primary key is always a be64_t   stored in fields[0] */
/* All tables are assigned a unique identifier */
/* If we change a table definition, we assign it a new guid */
struct table_def {
	char             name[IBSSA_DB_NAME_LEN];
	be32_t           guid;
	be32_t           field_cnt;
	be32_t           record_size;
	be32_t           reserved;
	struct field_def fields[0];
};

struct table {
	be64_t           epoch;
	be64_t           table_size;
	be64_t           record_cnt;
	struct table_def def;
	uint8_t          data[0];
};

/**
 * Transaction logs provide information to query incrimental updates
 */
enum ib_ssa_trans_op {
	IB_SSA_OP_INSERT,
	IB_SSA_OP_DELETE,
	IB_SSA_OP_UPDATE,
	IB_SSA_OP_RELOAD,
};
struct ib_ssa_trans_log_entry {
	be64_t   epoch;
	be64_t   record_id;
	be32_t   table_guid;
	be32_t   record_size;
	uint8_t  operation; /* enum ib_ssa_trans_op */
	uint8_t  reserved[15];
	uint8_t  data[0];   /* stores both old and new value */
};


/**
 * Specific table definitions
 */
struct ib_ssa_path_record {
	be64_t   path_id;
	struct ibv_path_record path;
};

struct table_def ib_ssa_pr_table_def;
ib_ssa_pr_table_def.table_guid = SSA_PATH_RECORD_GUID;
ib_ssa_pr_table_def.field_cnt = 1 + however many combined fields are in a path record;
ib_ssa_pr_table_def.record_size = sizeof(struct ib_ssa_path_record);

#endif /* __IBSSA_DB_H__ */

