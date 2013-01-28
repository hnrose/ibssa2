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

#include <stdint.h>
#include <byteswap.h>
#include <infiniband/umad.h>
#include "ibssa_control.h"

/*
 * The format of the data contained in a database is described by the
 * database definition structures (db_def, db_table_def, and db_field_def).
 * The actual data contained in a database is identified by the dataset
 * structure (db_dataset).  The dataset is also used to exchange the
 * definitions, as indicated below.
 */

#define DB_NAME_LEN		64
#define DB_VARIABLE_SIZE	0xFFFFFFFF

/**
 * db_def:
 * @version - version of this structure
 * @size - size of this structure
 * @reserved - set to 0
 * @id - unique identifier for a specific database
 * @name - user-friendly name for a specific database
 * @table_def_size - size of each table definition (db_table_def)
 *
 * A database is comprised of:
 *    - a single db_def, which includes a unique ID for the database
 *    - a collection of data tables and their corresponding definitions
 * Once a user has obtained a db_def, they can obtain a list of
 * db_table_def's by querying for the db_dataset with a def_id matching
 * that of the database.  This provides the definitions of the tables
 * contained within a database.
 */
#define DB_DEF_VERSION 0
struct db_def {
	uint8_t		version;
	uint8_t		size;
	uint8_t		reserved[2];
	be32_t		id;
	char		name[DB_NAME_LEN];
	be32_t		table_def_size;
};

enum {
	DBT_TYPE_DEF,
	DBT_TYPE_DATA,
	DBT_TYPE_LOG
};

enum {
	DBT_ACCESS_SEQUENTIAL	= (1 << 0),
	DBT_ACCESS_NET_ORDER	= (1 << 1)
};

/**
 * db_table_def:
 * @version - version of this structure
 * @size - size of this structure
 * @type - identifies the contents of the corresponding data set
 * @access - flags that indicate how to access the data correctly
 * @id - unique identifier for a specific table
 * @name - user-friendly name for a specific table
 * @record_size - size of each dataset entry
 * @ref_table_id - the id of a related table, if any
 *
 * This structure defines the basic format for the data tables found in
 * a database, along with information on how to process that data.  The
 * access flags indicate if the dataset should be accessed randomly
 * (true for most tables) or sequentially (true for transaction log files).
 *
 * The record_size field gives the size of each record in the dataset,
 * or DB_VARIABLE_SIZE if the size is variable.  Datasets containing
 * variable sized data should be paired with a dataset of fixed-sized
 * records, with the fixed-sized records marking the start of
 * each variable sized record.  (See db_trans_log_entry for an example.)
 *
 * The ref_table_id field is used to identify such associations between
 * tables.  A variable sized dataset would reference the fixed sized dataset.
 * A dataset containing field definitions for a table would reference
 * the corresponding table.
 */
#define DBT_DEF_VERSION 0
struct db_table_def {
	uint8_t		version;
	uint8_t		size;
	uint8_t		type;
	uint8_t		access;
	be32_t		id;
	char		name[DB_NAME_LEN];
	be32_t		record_size;
	be32_t		ref_table_id;
};

enum {
	DBF_TYPE_U8,
	DBF_TYPE_U16,
	DBF_TYPE_U32,
	DBF_TYPE_U64,
	DBF_TYPE_NET16,
	DBF_TYPE_NET32,
	DBF_TYPE_NET64,
	DBF_TYPE_NET128,
	DBF_TYPE_STRING
};

/**
 * db_field_def:
 * @version - version of this structure
 * @reserved - set to 0
 * @type - identifies the data type for the field
 * @reserved2 - set to 0
 * @id - unique identifier for a field
 * @name - user-friendly name for a field
 * @field_size - size of the field, in bits
 * @field_offset - offset of field from start of record, in bits
 *
 * Field definitions allow for generic processing of data records.  The
 * definitions for table's fields are maintained in a separate dataset.
 * That dataset should be identified as having a DBT_TYPE_DEF type, with
 * a ref_table_id that references the table being described.
 */
#define DBF_DEF_VERSION 0
struct db_field_def {
	uint8_t		version;
	uint8_t		reserved;
	uint8_t		type;
	uint8_t		reserved2;
	be32_t		id;
	char		name[DB_NAME_LEN];
	be32_t		field_size;
	be32_t		field_offset;
};

/**
 * db_dataset:
 * @version - version of this structure
 * @size - size of this structure
 * @reserved - set to 0
 * @access - flags that indicate how to access the data correctly
 * @def_id - id of table that defines record format
 * @epoch - static or dynamic version of data
 * @set_size - size of current dataset, in bytes
 * @set_offset - offset of first record in current dataset, in bytes
 * @set_count - number of records in current dataset
 *
 * All data exchanges relating to a specific database are done using
 * datasets.  A dataset is a table of records.  A description of the
 * records, including the record size and access mode, is given by a
 * table definition.  A table definition may be expanded to include field
 * sizes and locations.  Field definitions are themselves stored in a
 * separate dataset.
 *
 * The access flags indicate if the data are stored in network-byte order.
 * Clients may use this to determine if byte-swapping is necessary on
 * fields where byte order is not specified (DBF_TYPE_U16, DBF_TYPE_U32,
 * DBF_TYPE_U64).
 *
 * The epoch value is used to track changes to the dataset.  The epoch
 * value is incremented anytime a transaction has modified, added, or
 * removed data from a dataset.  The epoch value may be treated as a
 * static version number if the dataset is not expected to change during
 * execution.  This is the case when the dataset contains a listing of
 * table or field definitions.
 *
 * The dataset structure may be used to reference a subset of a larger
 * dataset.  All fields of db_dataset are relative to the current set of
 * records being referenced.  The set_size field indicates the size of
 * the dataset, in bytes.  The set_offset field is used to identify the
 * location of the dataset's first record of relative to a larger dataset.
 * The set_offset is 0 if the dataset is not a subset.  The set_count is
 * only valid if the records are of fixed sized and lists the number of
 * records in the dataset.
 */
#define DB_DS_VERSION 0
struct db_dataset {
	uint8_t		version;
	uint8_t		size;
	uint8_t		reserved;
	uint8_t		access;
	be32_t		def_id;
	be64_t		epoch;
	be64_t		set_size;
	be64_t		set_offset;
	be64_t		set_count;
	/* data */
};

/**
 * Transaction logs provide information to query incremental updates
 */
enum db_trans_op {
	DB_OP_INSERT,
	DB_OP_DELETE,
	DB_OP_UPDATE,
	DB_OP_RELOAD,
	DB_OP_START,
	DB_OP_END,
};

struct db_trans_log_entry {
	be64_t		epoch;
	be32_t		table_id;
	uint8_t		operation;
	uint8_t		reserved;
	be16_t		entry_size;
	be64_t		entry_offset;
	be64_t		record_offset;
};


/** =========================================================================
 * Core database transfer operations
 */

enum {
	IBSSA_MSG_ID_QUERY_DB_DEF = IBSSA_MSG_ID_DB_START,
	IBSSA_MSG_ID_QUERY_DATASET,
	IBSSA_MSG_ID_PUBLISH_EPOCH_BUF,
};

struct ib_ssa_db_msg {
	struct ib_ssa_msg_hdr	hdr;
	struct db_dataset	info;
};

#endif /* __IBSSA_DB_H__ */
