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

/** =========================================================================
 */
struct ssa_db *ssa_db_create(uint64_t * p_num_recs_arr,
			     size_t * p_data_recs_size_arr,
			     uint64_t * p_num_field_recs_arr,
			     uint64_t tbl_cnt)
{
	struct ssa_db *p_db;
	int i, k;

	p_db = (struct ssa_db *) calloc(1, sizeof(*p_db));
	if (!p_db)
		goto err1;

	/* number of data & field tables = tbl_cnt * 2 */
	p_db->p_def_tbl = (struct db_table_def *)
				calloc(tbl_cnt * 2, sizeof(*p_db->p_def_tbl));
	if (!p_db->p_def_tbl)
		goto err2;

	p_db->p_db_tables = (struct db_dataset *)
				calloc(tbl_cnt, sizeof(*p_db->p_db_tables));
	if (!p_db->p_db_tables)
		goto err3;

	p_db->p_db_field_tables = (struct db_dataset *)
				calloc(tbl_cnt, sizeof(*p_db->p_db_field_tables));
	if (!p_db->p_db_field_tables)
		goto err4;

	p_db->pp_tables = (void **) calloc(tbl_cnt, sizeof(*p_db->pp_tables));
	if (!p_db->pp_tables)
		goto err5;

	for (i = 0; i < tbl_cnt; i++) {
		p_db->pp_tables[i] =
			(void *) malloc(p_data_recs_size_arr[i] * p_num_recs_arr[i]);
		if (!p_db->pp_tables[i]) {
			for (k = i - 1; k >= 0; k--)
				free(p_db->pp_tables[k]);
			goto err6;
		}
	}

	p_db->pp_field_tables = (struct db_field_def **)
				calloc(tbl_cnt, sizeof(*p_db->pp_field_tables));
	if (!p_db->pp_field_tables)
		goto err7;

	for (i = 0; i < tbl_cnt; i++) {
		if (p_num_field_recs_arr[i] == DB_VARIABLE_SIZE)
			continue;

		p_db->pp_field_tables[i] = (struct db_field_def *)
				calloc(p_num_field_recs_arr[i], sizeof(**(p_db->pp_field_tables)));
		if (!p_db->pp_field_tables[i]) {
			for (k = i - 1; k >= 0; k--)
				free(p_db->pp_field_tables[k]);
			goto err8;
		}
	}

	p_db->data_tbl_cnt = tbl_cnt;

	return p_db;
err8:
	free(p_db->pp_field_tables);
err7:
	for (k = tbl_cnt - 1; k >= 0; k--)
		free(p_db->pp_tables[k]);
err6:
	free(p_db->pp_tables);
err5:
	free(p_db->p_db_field_tables);
err4:
	free(p_db->p_db_tables);
err3:
	free(p_db->p_def_tbl);
err2:
	free(p_db);
err1:
	return NULL;
}

/** =========================================================================
 */
void ssa_db_init(struct ssa_db * p_ssa_db, char * name, uint8_t db_id,
		 const struct db_table_def *def_tbl,
		 const struct db_dataset *dataset_tbl,
		 const struct db_dataset *field_dataset_tbl,
		 const struct db_field_def *field_tbl)
{
	const struct db_table_def *p_tbl_def = NULL;
	const struct db_dataset *p_dataset = NULL;
	const struct db_field_def *p_field_def = NULL;

	if (!p_ssa_db)
		return;

	/*
	 * Database definition initialization
	 */
	ssa_db_def_init(&p_ssa_db->db_def, DB_DEF_VERSION,
			sizeof(p_ssa_db->db_def), db_id,
			0, 0, name, sizeof(*p_ssa_db->p_def_tbl));

	/*
	 * Definition tables dataset initialization
	 */
	ssa_db_dataset_init(&p_ssa_db->db_table_def, DB_DS_VERSION,
			    sizeof(p_ssa_db->db_table_def),
			    DBT_ACCESS_NET_ORDER, db_id, DBT_DEF_DS_ID,
			    0, 0 /* epoch */, 0 /* set_size */,
			    0 /* set_offset */, 0 /* set_count */);

	/* adding table definitions */
	for (p_tbl_def = def_tbl; p_tbl_def->version != DB_VERSION_INVALID; p_tbl_def++)
		ssa_db_table_def_insert(p_ssa_db->p_def_tbl,
					&p_ssa_db->db_table_def,
					p_tbl_def->version, p_tbl_def->size,
					p_tbl_def->type, p_tbl_def->access,
					p_tbl_def->id.db, p_tbl_def->id.table,
					p_tbl_def->id.field, p_tbl_def->name,
					ntohl(p_tbl_def->record_size),
					ntohl(p_tbl_def->ref_table_id));

	/* data tables datasets initialization */
	for (p_dataset = dataset_tbl; p_dataset->version != DB_VERSION_INVALID; p_dataset++)
		ssa_db_dataset_init(&p_ssa_db->p_db_tables[p_dataset->id.table],
				    p_dataset->version, p_dataset->size,
				    p_dataset->access, p_dataset->id.db,
				    p_dataset->id.table, p_dataset->id.field,
				    p_dataset->epoch, p_dataset->set_size,
				    p_dataset->set_offset,
				    p_dataset->set_count);

	/* field tables datasets initialization */
	for (p_dataset = dataset_tbl; p_dataset->version != DB_VERSION_INVALID; p_dataset++)
		ssa_db_dataset_init(&p_ssa_db->p_db_field_tables[p_dataset->id.table],
				    p_dataset->version, p_dataset->size,
				    p_dataset->access, p_dataset->id.db,
				    p_dataset->id.table, p_dataset->id.field,
				    p_dataset->epoch, p_dataset->set_size,
				    p_dataset->set_offset,
				    p_dataset->set_count);

	/* field tables initialization */
	for (p_tbl_def = def_tbl; p_tbl_def->version != DB_VERSION_INVALID; p_tbl_def++) {
		uint8_t tbl_id = ntohl(p_tbl_def->ref_table_id);
		if (p_tbl_def->type != DBT_TYPE_DEF)
			continue;
		for (p_field_def = field_tbl; p_field_def->version != DB_VERSION_INVALID; p_field_def++) {
                        if (p_field_def->id.table == p_tbl_def->id.table) {
                                ssa_db_field_def_insert(p_ssa_db->pp_field_tables[tbl_id],
                                                        &p_ssa_db->p_db_field_tables[tbl_id],
                                                        p_field_def->version, p_field_def->type,
                                                        p_field_def->id.db, p_field_def->id.table,
                                                        p_field_def->id.field, p_field_def->name,
                                                        ntohl(p_field_def->field_size),
                                                        ntohl(p_field_def->field_offset));
			}
                }
        }
}

/** =========================================================================
 */
void ssa_db_destroy(struct ssa_db * p_ssa_db)
{
	uint64_t tbl_cnt;
	int i;

	if (!p_ssa_db)
		return;

	tbl_cnt = p_ssa_db->data_tbl_cnt;

	for (i = tbl_cnt - 1; i >= 0; i--) {
		if (!p_ssa_db->pp_field_tables[i])
			continue;
		free(p_ssa_db->pp_field_tables[i]);
		p_ssa_db->pp_field_tables[i] = NULL;
	}
	free(p_ssa_db->pp_field_tables);

	for (i = tbl_cnt - 1; i >= 0; i--) {
		free(p_ssa_db->pp_tables[i]);
		p_ssa_db->pp_tables[i] = NULL;
	}
	free(p_ssa_db->pp_tables);
	p_ssa_db->pp_tables = NULL;

	free(p_ssa_db->p_db_field_tables);
	free(p_ssa_db->p_db_tables);
	p_ssa_db->p_db_tables = NULL;

	free(p_ssa_db->p_def_tbl);
	p_ssa_db->p_def_tbl = NULL;

	free(p_ssa_db);
	p_ssa_db = NULL;
}

/** =========================================================================
 */
uint64_t ssa_db_calculate_data_tbl_num(const struct ssa_db *p_ssa_db)
{
	uint64_t i, data_tbl_cnt = 0;

	if (!p_ssa_db || !p_ssa_db->p_def_tbl)
		goto out;

	for (i = 0; i < ntohll(p_ssa_db->db_table_def.set_count); i++)
		if (p_ssa_db->p_def_tbl[i].type == DBT_TYPE_DATA)
			data_tbl_cnt++;

out:
	return data_tbl_cnt;
}
