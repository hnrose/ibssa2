/*
 * Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
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

static int get_table_id(const char *name, struct db_dataset *dataset,
			struct db_table_def *tbl_def)
{
	int table_id = -1;
	uint64_t i;

	for (i = 0; i < ntohll(dataset->set_count); i++) {
		if (tbl_def[i].type != DBT_TYPE_DATA)
			continue;

		if (strncmp(name, tbl_def[i].name, DB_NAME_LEN))
			continue;

		table_id = tbl_def[i].id.table;
		break;
	}

	return table_id;
}

/** =========================================================================
 */
void ssa_db_def_init(struct db_def * p_db_def, uint8_t version,
		     uint8_t size, uint8_t db_id, uint8_t table_id,
		     uint8_t field_id, const char * name,
		     uint64_t epoch, uint32_t table_def_size)
{
	p_db_def->version		= version;
	p_db_def->size			= size;
	p_db_def->id.db			= db_id;
	p_db_def->id.table		= table_id;
	p_db_def->id.field		= field_id;
	strncpy(p_db_def->name, name, sizeof(p_db_def->name));
	p_db_def->epoch			= htonll(epoch);
	p_db_def->table_def_size	= htonl(table_def_size);
}

static int ssa_db_def_cmp(struct db_def const *db_def1,
			  struct db_def const *db_def2) {
	if ((db_def1->size		!= db_def2->size) ||
	    (db_def1->id.db		!= db_def2->id.db) ||
	    (db_def1->id.table		!= db_def2->id.table) ||
	    (db_def1->id.field		!= db_def2->id.field) ||
	    (db_def1->version		!= db_def2->version) ||
	    (db_def1->table_def_size	!= db_def2->table_def_size))
		return 1;

	return 0;
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

static int ssa_db_dataset_cmp(struct db_dataset const *dataset1,
			      struct db_dataset const *dataset2)
{
	if ((dataset1->size		!= dataset2->size) ||
	    (dataset1->version		!= dataset2->version) ||
	    (dataset1->access		!= dataset2->access) ||
	    (dataset1->id.db		!= dataset2->id.db) ||
	    (dataset1->id.table		!= dataset2->id.table) ||
	    (dataset1->id.field		!= dataset2->id.field) ||
	    (dataset1->set_size		!= dataset2->set_size) ||
	    (dataset1->set_count	!= dataset2->set_count))
	    /* 'set_offset' field comparison is omitted, because currently it is not used */
		return 1;

	return 0;
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

static int ssa_db_tbl_def_cmp(struct db_table_def const *tbl_def1,
			      struct db_table_def const *tbl_def2)
{
	if ((tbl_def1->version		!= tbl_def2->version) ||
	    (tbl_def1->size		!= tbl_def2->size) ||
	    (tbl_def1->type		!= tbl_def2->type) ||
	    (tbl_def1->access		!= tbl_def2->access) ||
	    (tbl_def1->id.db		!= tbl_def2->id.db) ||
	    (tbl_def1->id.table		!= tbl_def2->id.table) ||
	    (tbl_def1->id.field		!= tbl_def2->id.field) ||
	    (tbl_def1->record_size	!= tbl_def2->record_size) ||
	    (tbl_def1->ref_table_id	!= tbl_def2->ref_table_id))
		return 1;

	return 0;
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

static int ssa_db_field_def_cmp(struct db_field_def *field_def1,
				struct db_field_def *field_def2)
{
	if ((field_def1->version	!= field_def2->version) ||
	    (field_def1->type		!= field_def2->type) ||
	    (field_def1->id.db		!= field_def2->id.db) ||
	    (field_def1->id.table	!= field_def2->id.table) ||
	    (field_def1->id.field	!= field_def2->id.field) ||
	    (field_def1->field_size	!= field_def2->field_size) ||
	    (field_def1->field_offset	!= field_def2->field_offset))
		return 1;

	return 0;
}

/** =========================================================================
 */
uint64_t ssa_db_get_epoch(const struct ssa_db *p_ssa_db, uint8_t tbl_id)
{
	uint8_t tbl_cnt;

	if (!p_ssa_db)
		return DB_EPOCH_INVALID;

	if (tbl_id == DB_DEF_TBL_ID)
		return ntohll(p_ssa_db->db_def.epoch);

	tbl_cnt = p_ssa_db->data_tbl_cnt ? p_ssa_db->data_tbl_cnt:
		  ssa_db_calculate_data_tbl_num(p_ssa_db);
	if (tbl_id < tbl_cnt)
		return ntohll(p_ssa_db->p_db_tables[tbl_id].epoch);
	else
		return DB_EPOCH_INVALID;
}

/** =========================================================================
 */
uint64_t ssa_db_set_epoch(struct ssa_db *p_ssa_db, uint8_t tbl_id, uint64_t epoch)
{
	if (!p_ssa_db)
		return DB_EPOCH_INVALID;

	if (tbl_id == DB_DEF_TBL_ID) {
		p_ssa_db->db_def.epoch = htonll(epoch);
		return epoch;
	} else if (tbl_id < p_ssa_db->data_tbl_cnt) {
		p_ssa_db->p_db_tables[tbl_id].epoch = htonll(epoch);
		return epoch;
	} else
		return DB_EPOCH_INVALID;
}

/** =========================================================================
 */
uint64_t ssa_db_increment_epoch(struct ssa_db *p_ssa_db, uint8_t tbl_id)
{
	uint64_t epoch;

	if (!p_ssa_db)
		return DB_EPOCH_INVALID;

	if (tbl_id == DB_DEF_TBL_ID) {
		epoch = ntohll(p_ssa_db->db_def.epoch);
		if (++epoch == DB_EPOCH_INVALID)
			++epoch;
		p_ssa_db->db_def.epoch = htonll(epoch);
		return epoch;
	} else if (tbl_id < p_ssa_db->data_tbl_cnt) {
		epoch = ntohll(p_ssa_db->p_db_tables[tbl_id].epoch);
		if (++epoch == DB_EPOCH_INVALID)
			++epoch;
		p_ssa_db->p_db_tables[tbl_id].epoch = htonll(epoch);
		return epoch;
	} else {
		return DB_EPOCH_INVALID;
	}
}

/** =========================================================================
 */
struct ssa_db *ssa_db_alloc(uint64_t * p_num_recs_arr,
			    size_t * p_data_recs_size_arr,
			    uint64_t * p_num_field_recs_arr,
			    uint64_t tbl_cnt)
{
	struct ssa_db *p_db;
	int i, k, size;

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
		size = p_data_recs_size_arr[i] * p_num_recs_arr[i];
		if (!size)
			continue;
		p_db->pp_tables[i] = (void *) malloc(size);
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
void ssa_db_init(struct ssa_db * p_ssa_db, char * name,
		 uint8_t db_id, uint64_t epoch,
		 const struct db_table_def *def_tbl,
		 const struct db_dataset *dataset_tbl,
		 const struct db_dataset *field_dataset_tbl,
		 const struct db_field_def *field_tbl)
{
	const struct db_table_def *p_tbl_def = NULL;
	const struct db_dataset *p_dataset = NULL;
	const struct db_field_def *p_field_def = NULL;
	int i = 0;

	if (!p_ssa_db)
		return;

	/*
	 * Database definition initialization
	 */
	ssa_db_def_init(&p_ssa_db->db_def, DB_DEF_VERSION,
			sizeof(p_ssa_db->db_def), db_id,
			0, 0, name, epoch, sizeof(*p_ssa_db->p_def_tbl));

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
	for (p_dataset = dataset_tbl, i = 0;
	     p_dataset->version != DB_VERSION_INVALID; p_dataset++, i++)
		ssa_db_dataset_init(&p_ssa_db->p_db_tables[i],
				    p_dataset->version, p_dataset->size,
				    p_dataset->access, p_dataset->id.db,
				    p_dataset->id.table, p_dataset->id.field,
				    p_dataset->epoch, p_dataset->set_size,
				    p_dataset->set_offset,
				    p_dataset->set_count);

	/* field tables datasets initialization */
	for (p_dataset = field_dataset_tbl, i = 0;
	     p_dataset->version != DB_VERSION_INVALID; p_dataset++, i++)
		ssa_db_dataset_init(&p_ssa_db->p_db_field_tables[i],
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
	p_ssa_db->pp_field_tables = NULL;

	for (i = tbl_cnt - 1; i >= 0; i--) {
		free(p_ssa_db->pp_tables[i]);
		p_ssa_db->pp_tables[i] = NULL;
	}
	free(p_ssa_db->pp_tables);
	p_ssa_db->pp_tables = NULL;

	free(p_ssa_db->p_db_field_tables);
	p_ssa_db->p_db_field_tables = NULL;
	free(p_ssa_db->p_db_tables);
	p_ssa_db->p_db_tables = NULL;

	free(p_ssa_db->p_def_tbl);
	p_ssa_db->p_def_tbl = NULL;

	free(p_ssa_db);
}

/*
 *	Return values:
 *	 0 - equal ssa_db structures
 *	 1 - different ssa_db structures
 *	-1 - invalid input
 */
int ssa_db_tbl_cmp(struct ssa_db *ssa_db1, struct ssa_db *ssa_db2, const char *name)
{
	struct db_dataset *dataset1, *dataset2;
	void *tbl1, *tbl2;
	int id;

	if (!ssa_db1 || !ssa_db2 || !name)
		goto err;

	id = get_table_id(name, &ssa_db1->db_table_def, ssa_db1->p_def_tbl);
	if (id < 0)
		goto err;

	dataset1 = &ssa_db1->p_db_tables[id];
	tbl1 = ssa_db1->pp_tables[id];

	id = get_table_id(name, &ssa_db2->db_table_def, ssa_db2->p_def_tbl);
	if (id < 0)
		goto err;

	dataset2 = &ssa_db2->p_db_tables[id];
	tbl2 = ssa_db2->pp_tables[id];

	if ((dataset1->size		!= dataset2->size) ||
	    (dataset1->version		!= dataset2->version) ||
	    (dataset1->access		!= dataset2->access) ||
	    (dataset1->set_size		!= dataset2->set_size) ||
	    (dataset1->set_count	!= dataset2->set_count))
		return 1;

	if (!tbl1 && !tbl2)
		goto equal;

	if ((!tbl1 && tbl2) || (tbl1 && !tbl2))
		return 1;

	if (memcmp(tbl1, tbl2, ntohll(dataset1->set_size)))
		return 1;

equal:
	return 0;
err:
	return -1;
}

/*
 *	Return values:
 *	 0 - equal ssa_db structures
 *	 1 - different ssa_db structures
 *	-1 - invalid ssa_db structures
 */
int ssa_db_cmp(struct ssa_db const * const ssa_db1, struct ssa_db const * const ssa_db2)
{
	uint64_t i, j;
	int ret = 0;

	if (!ssa_db1 ||				!ssa_db2 ||
	    !ssa_db1->p_def_tbl ||		!ssa_db2->p_def_tbl ||
	    !ssa_db1->p_db_field_tables ||	!ssa_db2->p_db_field_tables ||
	    !ssa_db1->pp_field_tables ||	!ssa_db2->pp_field_tables ||
	    !ssa_db1->p_db_tables ||		!ssa_db2->p_db_tables ||
	    !ssa_db1->pp_tables ||		!ssa_db2->pp_tables) {
		ret = -1;
		goto out;
	}

	if (ssa_db_def_cmp(&ssa_db1->db_def, &ssa_db2->db_def) ||
	    ssa_db_dataset_cmp(&ssa_db1->db_table_def, &ssa_db2->db_table_def)) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < ntohll(ssa_db1->db_table_def.set_count); i++) {
		if (ssa_db_tbl_def_cmp(&ssa_db1->p_def_tbl[i],
				       &ssa_db2->p_def_tbl[i])) {
			ret = 1;
			goto out;
		}
	}

	if (ssa_db1->data_tbl_cnt != ssa_db2->data_tbl_cnt) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < ssa_db1->data_tbl_cnt; i++) {
		struct db_dataset *dataset1 = &ssa_db1->p_db_field_tables[i];
		struct db_dataset *dataset2 = &ssa_db2->p_db_field_tables[i];

		if (ssa_db_dataset_cmp(dataset1, dataset2)) {
			ret = 1;
			goto out;
		}

		for (j = 0; j < ntohll(dataset1->set_count); j++) {
			if (ssa_db_field_def_cmp(&ssa_db1->pp_field_tables[i][j],
						 &ssa_db2->pp_field_tables[i][j])) {
				ret = 1;
				goto out;
			}
		}
	}

	for (i = 0; i < ssa_db1->data_tbl_cnt; i ++) {
		struct db_dataset *dataset1 = &ssa_db1->p_db_tables[i];
		struct db_dataset *dataset2 = &ssa_db2->p_db_tables[i];

		if (ssa_db_dataset_cmp(dataset1, dataset2)) {
			ret = 1;
			goto out;
		}

		if (memcmp(ssa_db1->pp_tables[i], ssa_db2->pp_tables[i],
			   ntohll(dataset1->set_size))) {
			ret = 1;
			goto out;
		}
	}

out:
	return ret;
}

struct ssa_db *ssa_db_copy(struct ssa_db const * const ssa_db)
{
	uint64_t *field_cnt = NULL, *rec_cnt = NULL;
	struct ssa_db *ssa_db_copy = NULL;
	size_t *rec_size = NULL;
	uint64_t tbl_cnt, i, j;

	if (!ssa_db || !ssa_db->p_def_tbl ||
	    !ssa_db->p_db_field_tables || !ssa_db->pp_field_tables ||
	    !ssa_db->p_db_tables || !ssa_db->pp_tables)
		goto out;

	tbl_cnt = ssa_db->data_tbl_cnt;

	field_cnt = (uint64_t *) malloc(tbl_cnt * sizeof(*field_cnt));
	if (!field_cnt)
		goto out;

	rec_cnt = (uint64_t *) malloc(tbl_cnt * sizeof(*rec_cnt));
	if (!rec_cnt)
		goto err1;

	rec_size = (size_t *) malloc(tbl_cnt * sizeof(*rec_size));
	if (!rec_size)
		goto err2;

	for (i = 0; i < tbl_cnt; i++) {
		field_cnt[i] = ntohll(ssa_db->p_db_field_tables[i].set_count);
		rec_cnt[i] = ntohll(ssa_db->p_db_tables[i].set_count);

		for (j = 0; j < ntohll(ssa_db->db_table_def.set_count); j++) {
			if (ssa_db->p_def_tbl[j].id.table ==
			    ssa_db->p_db_tables[i].id.table) {
				rec_size[i] = ntohl(ssa_db->p_def_tbl[j].record_size);
				break;
			}
		}
	}

	ssa_db_copy = ssa_db_alloc(rec_cnt, rec_size, field_cnt, tbl_cnt);
	if (!ssa_db_copy)
		goto err3;

	ssa_db_copy->db_def = ssa_db->db_def;

	ssa_db_copy->db_table_def = ssa_db->db_table_def;
	memcpy(ssa_db_copy->p_def_tbl, ssa_db->p_def_tbl,
	       ntohll(ssa_db->db_table_def.set_size));

	ssa_db_copy->data_tbl_cnt = tbl_cnt;

	memcpy(ssa_db_copy->p_db_field_tables, ssa_db->p_db_field_tables,
	       tbl_cnt * sizeof(*ssa_db_copy->p_db_field_tables));

	memcpy(ssa_db_copy->p_db_tables, ssa_db->p_db_tables,
	       tbl_cnt * sizeof(*ssa_db_copy->p_db_tables));

	for (i = 0; i < tbl_cnt; i++) {
		if (ssa_db->pp_field_tables[i])
			memcpy(ssa_db_copy->pp_field_tables[i], ssa_db->pp_field_tables[i],
			       ntohll(ssa_db->p_db_field_tables[i].set_size));
		memcpy(ssa_db_copy->pp_tables[i], ssa_db->pp_tables[i],
		       ntohll(ssa_db->p_db_tables[i].set_size));
	}

err3:
	free(rec_size);
err2:
	free(rec_cnt);
err1:
	free(field_cnt);
out:
	return ssa_db_copy;
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

int
ssa_db_attach(struct ssa_db *dest, struct ssa_db *src, const char *tbl_name)
{
	struct db_dataset *dataset_src, *dataset_dest;
	int id_src, id_dest;

	if (!dest || !src || !tbl_name)
		goto err;

	id_src = get_table_id(tbl_name, &src->db_table_def, src->p_def_tbl);
	if (id_src < 0)
		goto err;

	dataset_src = &src->p_db_tables[id_src];
	if (!dataset_src->set_size || !src->pp_tables[id_src])
		goto skip_attach;

	id_dest = get_table_id(tbl_name, &dest->db_table_def, dest->p_def_tbl);
	if (id_dest < 0)
		goto err;

	dataset_dest = &dest->p_db_tables[id_dest];
	if (dataset_dest->set_size > 0 ||
	    dataset_dest->set_count > 0 || dest->pp_tables[id_dest])
		goto err;

	if (dataset_dest->version != dataset_src->version ||
	    dataset_dest->size    != dataset_src->size    ||
	    dataset_dest->access  != dataset_src->access)
		goto err;

	dest->pp_tables[id_dest] = malloc(ntohll(dataset_src->set_size));
	if (!dest->pp_tables[id_dest])
		goto err;

	memcpy(dest->pp_tables[id_dest], src->pp_tables[id_src],
	       ntohll(dataset_src->set_size));

	dataset_dest->epoch	= dataset_src->epoch;
	dataset_dest->set_size	= dataset_src->set_size;
	dataset_dest->set_count	= dataset_src->set_count;

skip_attach:
	return 0;

err:
	return -1;
}

void ssa_db_detach(struct ssa_db *ssa_db, const char *tbl_name)
{
	struct db_dataset *dataset;
	int id;

	if (!ssa_db || !tbl_name)
		goto out;

	id = get_table_id(tbl_name, &ssa_db->db_table_def, ssa_db->p_def_tbl);
	if (id < 0)
		goto out;

	dataset = &ssa_db->p_db_tables[id];
	dataset->set_size = 0;
	dataset->set_count = 0;

	if (!ssa_db->pp_tables[id])
		goto out;

	free(ssa_db->pp_tables[id]);
	ssa_db->pp_tables[id] = NULL;
out:
	return;
}
