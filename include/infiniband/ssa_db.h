/*
 * Copyright (c) 2012-2015 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012-2013 Intel Corporation. All rights reserved.
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

#ifndef __SSA_DB_H__
#define __SSA_DB_H__

#include <stdint.h>
#include <byteswap.h>
#include <infiniband/umad.h>
#include <infiniband/ssa.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The format of the data contained in a database is described by the
 * database definition structures (db_def, db_table_def, and db_field_def).
 * The actual data contained in a database is identified by the dataset
 * structure (db_dataset).  The dataset is also used to exchange the
 * definitions, as indicated below.
 */

#define DB_NAME_LEN		64
#define DB_VARIABLE_SIZE	0xFFFFFFFF
#define DB_ID_DEFS		0xFF
#define DB_VERSION_INVALID	0xFF
#define DB_EPOCH_INVALID	0
#define DB_EPOCH_INITIAL	(DB_EPOCH_INVALID + 1)

struct db_id {
	uint8_t		db;
	uint8_t		table;
	uint8_t		field;
	uint8_t		reserved;
};

/**
 * db_def:
 * @version - version of this structure
 * @size - size of this structure
 * @reserved - set to 0
 * @id - unique identifier for a specific database
 * @name - user-friendly name for a specific database
 * @epoch - static or dynamic version of DB (is equal to maximum table epoch)
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
#define DB_DEF_TBL_ID  0xFF
struct db_def {
	uint8_t		version;
	uint8_t		size;
	uint8_t		reserved[2];
	struct db_id	id;
	char		name[DB_NAME_LEN];
	be64_t		epoch;
	be32_t		table_def_size;
	uint8_t		reserved2[4];
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
#define DBT_DEF_NO_RELATED_TBL 0xFFFFFFFF
#define DBT_DEF_DS_ID 0xFE
struct db_table_def {
	uint8_t		version;
	uint8_t		size;
	uint8_t		type;
	uint8_t		access;
	struct db_id	id;
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
	struct db_id	id;
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
 * @id - id of requested data
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
 * The id field specifies the data to return in response to a query.  In
 * most cases, the id field will specify the id of a database or table,
 * indicating that the query should return all data in the database or
 * table, respectively.  If an id field contains DB_ID_DEFS, the response
 * should return definitions, such as the table definitions for a database,
 * or field definitions for a table.
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
	struct db_id	id;
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
	SSA_MSG_DB_QUERY_DEF,
	SSA_MSG_DB_QUERY_TBL_DEF,
	SSA_MSG_DB_QUERY_TBL_DEF_DATASET,
	SSA_MSG_DB_QUERY_FIELD_DEF_DATASET,	/* issued multiple times */
	SSA_MSG_DB_QUERY_DATA_DATASET,		/* issued multiple times */
	SSA_MSG_DB_PUBLISH_EPOCH_BUF,
	SSA_MSG_DB_UPDATE,
};

struct ssa_db_msg {
	struct ssa_msg_hdr	hdr;
	struct db_dataset	info;
};

void ssa_db_def_init(struct db_def * p_db_def, uint8_t version,
		     uint8_t size, uint8_t db_id, uint8_t table_id,
		     uint8_t field_id, const char * name,
		     uint64_t epoch, uint32_t table_def_size);

void ssa_db_dataset_init(struct db_dataset * p_dataset,
			 uint8_t version, uint8_t size,
			 uint8_t access, uint8_t db_id,
			 uint8_t table_id, uint8_t field_id,
			 uint64_t epoch, uint64_t set_size,
			 uint64_t set_offset, uint64_t set_count);

void ssa_db_table_def_insert(struct db_table_def * p_tbl,
			     struct db_dataset * p_dataset,
			     uint8_t version, uint8_t size,
			     uint8_t type, uint8_t access,
			     uint8_t db_id, uint8_t table_id,
			     uint8_t field_id, const char * name,
			     uint32_t record_size, uint32_t ref_table_id);

void ssa_db_field_def_insert(struct db_field_def * p_tbl,
			     struct db_dataset * p_dataset,
			     uint8_t version, uint8_t type,
			     uint8_t db_id, uint8_t table_id,
			     uint8_t field_id, const char * name,
			     uint32_t field_size, uint32_t field_offset);

/**
 * ssa_db:
 * @db_def - general database definitions
 * @db_table_def - dataset of database table definitions
 * @p_def_tbl - database table definitions
 * @p_db_field_tables - datasets of field tables
 * @pp_field_tables - database tables fields definitions
 * @p_db_tables - datasets of database data tables
 * @pp_tables - database data tables
 *
 * All data that belongs to a certain database is unified under
 * a single "ssa_db" structure. It includes:
 *    - database definitions
 *    - dataset of table definitions
 *    - datasets of field definitions
 *    - datasets of data
 *
 * Creating new database should be done through the following steps:
 *
 * [1] The following structures have to be defined:
 *
 *        - struct db_table_def []	containing all database tables defs.
 *          example:
 *             static const struct db_table_def def_arr[] = {
 *                 { table_1 definitions },
 *                 { table_1 field definitions },
 *                 ...
 *                 { DB_VERSION_INVALID }
 *             };
 *
 *        - struct db_dataset []	containing all datasets, 1 for data
 *                                      tables and 1 for field definition
 *                                      tables.
 *          example:
 *             static const struct db_dataset dataset_arr[] = {
 *                 { dataset_1 definitions },
 *                 { dataset_2 definitions },
 *                 ...
 *                 { DB_VERSION_INVALID }
 *             };
 *
 *             static const struct db_dataset field_dataset_arr[] = {
 *                 { dataset_1 field definitions },
 *                 { dataset_2 field definitions },
 *                 ...
 *                 { DB_VERSION_INVALID }
 *             };
 *
 *        - struct db_field_def []	containing data tables field defs.
 *          example:
 *             static const struct db_field_def field_arr[] = {
 *                { table_1 field_1 definitions },
 *                { table_1 field_2 definitions },
 *                ...
 *                { table_2 field_1 definitions },
 *                { table_2 field_2 definitions },
 *                ...
 *                { DB_VERSION_INVALID }
 *             };
 *
 * [2] ssa_db_alloc() has to be called with the following arguments:
 *
 *         - p_num_recs_arr		an array containing number of records
 *					for each table in database.
 *
 *         - p_recs_size_arr		an array containing record sizes
 *					for each table in database.
 *
 *         - p_num_field_recs_arr	an array containing the number of
 *					fields contained in table records.
 *
 *         - tbl_cnt			the number of data tables.
 *
 * [3] ssa_db_init() method has to be called with the arguments that
 *     were defined at stage 1.
 *
 */
struct ssa_db {
	struct db_def		db_def;

	struct db_dataset	db_table_def;
	struct db_table_def	*p_def_tbl;

	struct db_dataset	*p_db_field_tables;
	struct db_field_def	**pp_field_tables;

	struct db_dataset	*p_db_tables;
	void			**pp_tables;
	uint64_t		data_tbl_cnt;
};

struct ssa_db *ssa_db_alloc(uint64_t * p_num_recs_arr,
			    size_t * p_recs_size_arr,
			    uint64_t * p_num_field_recs_arr,
			    uint64_t tbl_cnt);

void ssa_db_init(struct ssa_db * p_ssa_db, char * name,
		 uint8_t db_id, uint64_t epoch,
		 const struct db_table_def *def_tbl,
		 const struct db_dataset *dataset_tbl,
		 const struct db_dataset *field_dataset_tbl,
		 const struct db_field_def *field_tbl);

void ssa_db_destroy(struct ssa_db * p_ssa_db);
int ssa_db_tbl_cmp(struct ssa_db *ssa_db1, struct ssa_db *ssa_db2, const char *name);
int ssa_db_cmp(struct ssa_db const * const ssa_db1, struct ssa_db const * const ssa_db2);
struct ssa_db *ssa_db_copy(struct ssa_db const * const ssa_db);
uint64_t ssa_db_calculate_data_tbl_num(const struct ssa_db *p_ssa_db);
uint64_t ssa_db_get_epoch(const struct ssa_db *p_ssa_db, uint8_t tbl_id);
uint64_t ssa_db_set_epoch(struct ssa_db *p_ssa_db, uint8_t tbl_id, uint64_t epoch);
uint64_t ssa_db_increment_epoch(struct ssa_db *p_ssa_db, uint8_t tbl_id);

/**
 * ssa_db_attach():
 * @dest        - destination SSA DB for attached table
 * @src         - source SSA DB of the attached table
 * @tbl_name    - attached table name
 *
 * This routine is being used in order to attach an existing table
 * destination SSA DB already includes the attached table definitions
 * and also have reserved indexes for storing the table. The attach
 * procedure involves deep copy of specified table, therefore new
 * memory buffer is allocated and on ssa_db_detach() call it is
 * being free'd.
 */
int ssa_db_attach(struct ssa_db *dest, struct ssa_db *src, const char *tbl_name);
void ssa_db_detach(struct ssa_db *ssa_db, const char *tbl_name);
#ifdef __cplusplus
}
#endif

#endif /* __SSA_DB_H__ */
