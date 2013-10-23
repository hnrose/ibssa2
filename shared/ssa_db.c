/*
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013 Lawrence Livermore National Securities.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <infiniband/ssa_db.h>

/** =========================================================================
 */
void ssa_db_def_init(struct db_def * p_db_def, uint8_t version,
		     uint8_t size, uint8_t db_id, uint8_t table_id,
		     uint8_t field_id, const char * name,
		     uint32_t table_def_size)
{
	p_db_def->version		= version;
	p_db_def->size			= size;
	p_db_def->id.db			= db_id;
	p_db_def->id.table		= table_id;
	p_db_def->id.field		= field_id;
	strncpy(p_db_def->name, name, sizeof(p_db_def->name));
	p_db_def->table_def_size	= htonl(table_def_size);
}

/** =========================================================================
 */
void ssa_db_dataset_init(struct db_dataset * p_dataset,
			 uint8_t version, uint8_t size,
			 uint8_t access, uint8_t db_id,
			 uint8_t table_id, uint8_t field_id,
			 uint64_t epoch, uint64_t set_size,
			 uint64_t set_offset, uint64_t set_count)
{
	p_dataset->version	= version;
	p_dataset->size		= size;
	p_dataset->access	= access;
	p_dataset->id.db	= db_id;
	p_dataset->id.table	= table_id;
	p_dataset->id.field	= field_id;
	p_dataset->epoch	= htonll(epoch);
	p_dataset->set_size	= htonll(set_size);
	p_dataset->set_offset	= htonll(set_offset);
	p_dataset->set_count	= htonll(set_count);
}

/** =========================================================================
 */
void ssa_db_table_def_insert(struct db_table_def * p_tbl,
			     struct db_dataset * p_dataset,
			     uint8_t version, uint8_t size,
			     uint8_t type, uint8_t access,
			     uint8_t db_id, uint8_t table_id,
			     uint8_t field_id, const char * name,
			     uint32_t record_size, uint32_t ref_table_id)
{
	struct db_table_def db_table_def_rec;

	memset(&db_table_def_rec, 0, sizeof(db_table_def_rec));

	db_table_def_rec.version	= version;
	db_table_def_rec.size		= size;
	db_table_def_rec.type		= type;
	db_table_def_rec.access		= access;
	db_table_def_rec.id.db		= db_id;
	db_table_def_rec.id.table	= table_id;
	db_table_def_rec.id.field	= field_id;
	strncpy(db_table_def_rec.name, name, sizeof(db_table_def_rec.name));
	db_table_def_rec.record_size	= htonl(record_size);
	db_table_def_rec.ref_table_id	= htonl(ref_table_id);

	memcpy(&p_tbl[ntohll(p_dataset->set_count)], &db_table_def_rec,
	       sizeof(*p_tbl));
	p_dataset->set_count = htonll(ntohll(p_dataset->set_count) + 1);
	p_dataset->set_size = htonll(ntohll(p_dataset->set_size) + sizeof(*p_tbl));
}

/** =========================================================================
 */
void ssa_db_field_def_insert(struct db_field_def * p_tbl,
			     struct db_dataset * p_dataset,
			     uint8_t version, uint8_t type,
			     uint8_t db_id, uint8_t table_id,
			     uint8_t field_id, const char * name,
			     uint32_t field_size, uint32_t field_offset)
{
	struct db_field_def db_field_def_rec;

	memset(&db_field_def_rec, 0, sizeof(db_field_def_rec));

	db_field_def_rec.version	= version;
	db_field_def_rec.type		= type;
	db_field_def_rec.id.db		= db_id;
	db_field_def_rec.id.table	= table_id;
	db_field_def_rec.id.field	= field_id;
	strncpy(db_field_def_rec.name, name, sizeof(db_field_def_rec.name));
	db_field_def_rec.field_size	= htonl(field_size);
	db_field_def_rec.field_offset	= htonl(field_offset);

	memcpy(&p_tbl[ntohll(p_dataset->set_count)], &db_field_def_rec,
	       sizeof(*p_tbl));
	p_dataset->set_count = htonll(ntohll(p_dataset->set_count) + 1);
	p_dataset->set_size = htonll(ntohll(p_dataset->set_size) + sizeof(*p_tbl));
}
