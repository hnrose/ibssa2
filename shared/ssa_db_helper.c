/*
 * Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
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

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <infiniband/ssa_db_helper.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ssa_log.h>

#define SSA_DB_HELPER_PATH_MAX PATH_MAX

#ifndef DBT_DEF_NO_RELATED_TBL
#define DBT_DEF_NO_RELATED_TBL 0xFFFFFFFF
#endif

#define SSA_DB_HELPER_DB_DEF_NAME		"db_def"
#define SSA_DB_HELPER_TABLE_DEF_NAME		"table_def"
#define SSA_DB_HELPER_FIELD_DEF_NAME		"field_def"
#define SSA_DB_HELPER_DATA_NAME			"data"
#define SSA_DB_HELPER_FIELDS_NAME		"fields"
#define SSA_DB_HELPER_DATASET_NAME		"dataset"
#define SSA_DB_HELPER_FIELDS_DATASET_NAME	"fields_dataset"

#define SSA_DB_HELPER_FILE_WRITE_MODE_TXT	"w"
#define SSA_DB_HELPER_FILE_READ_MODE_TXT	"r"
#define SSA_DB_HELPER_FILE_WRITE_MODE_BIN	"wb"
#define SSA_DB_HELPER_FILE_READ_MODE_BIN	"rb"

#define SSA_DB_HELPER_DELIMITER		":"
#define SSA_DB_HELPER_ARRAY_DELIMITER	";"

#define DB_DEF_FORMAT_WRITE		"version %"SCNu8" size %"SCNu8" db_id %"SCNu8" tbl_id %"SCNu8" field_id %"SCNu8" table_def_size %u epoch %"SCNu64" name %s\n"
#define DB_DEF_FORMAT_READ		"version %"SCNu8" size %"SCNu8" db_id %"SCNu8" tbl_id %"SCNu8" field_id %"SCNu8" table_def_size %u epoch %"SCNu64" name %[^\n]s"
#define TABLE_DEF_FORMAT_WRITE		"version %"SCNu8" size %"SCNu8" type %"SCNu8" access %"SCNu8" id %"SCNu8"-%"SCNu8"-%"SCNu8 \
					" record_size %"SCNu32" ref_table_id %u name %s\n"
#define TABLE_DEF_FORMAT_READ		"version %"SCNu8" size %"SCNu8" type %"SCNu8" access %"SCNu8" id %"SCNu8"-%"SCNu8"-%"SCNu8 \
					" record_size %"SCNu32" ref_table_id %u name %[^\n]s"
#define DATASET_DEF_FORMAT		"version %"SCNu8" size %"SCNu8" access %"SCNu8" db_id %"SCNu8" table_id %"SCNu8" field_id %"SCNu8""\
					" epoch %lu set_size %lu ""set_offset %lu set_count %lu\n"
#define DB_FIELD_DEF_FORMAT_WRITE	"version %"SCNu8" type %"SCNu8" db_id %"SCNu8" table_id %"SCNu8" field_id %"SCNu8" field_size %u field_offset %u name %s\n"
#define DB_FIELD_DEF_FORMAT_READ	"version %"SCNu8" type %"SCNu8" db_id %"SCNu8" table_id %"SCNu8" field_id %"SCNu8" field_size %u field_offset %u name %[^\n]s"

static void ssa_db_db_def_dump(FILE *fd, const struct db_def *p_db_def)
{
	fprintf(fd, DB_DEF_FORMAT_WRITE, p_db_def->version, p_db_def->size,
		p_db_def->id.db, p_db_def->id.table, p_db_def->id.field,
		ntohl(p_db_def->table_def_size), ntohll(p_db_def->epoch),
		p_db_def->name);
}

static void ssa_db_table_def_dump(FILE *fd, struct db_table_def *p_def_tbl,
				  uint64_t offset)
{
	struct db_table_def db_table_def;

	memcpy(&db_table_def, &p_def_tbl[offset], sizeof(db_table_def));
	fprintf(fd, TABLE_DEF_FORMAT_WRITE,
		db_table_def.version, db_table_def.size,
		db_table_def.type, db_table_def.access,
		db_table_def.id.db, db_table_def.id.table,
		db_table_def.id.field, ntohl(db_table_def.record_size),
		ntohl(db_table_def.ref_table_id), db_table_def.name);
}

static void ssa_db_dataset_dump(FILE *fd, struct db_dataset *p_dataset)
{
	fprintf(fd, DATASET_DEF_FORMAT,
		p_dataset->version, p_dataset->size,
		p_dataset->access, p_dataset->id.db,
		p_dataset->id.table, p_dataset->id.field,
		ntohll(p_dataset->epoch), ntohll(p_dataset->set_size),
		ntohll(p_dataset->set_offset), ntohll(p_dataset->set_count));
}

static void ssa_db_field_tbl_dump(FILE *fd, struct db_dataset *p_dataset,
				  struct db_field_def *p_data_tbl)
{
	struct db_field_def field_rec;
	uint32_t i;

	for (i = 0; i < ntohll(p_dataset->set_count); i++) {
		memcpy(&field_rec, &p_data_tbl[i], sizeof(field_rec));
		fprintf(fd, DB_FIELD_DEF_FORMAT_WRITE,
			field_rec.version, field_rec.type, field_rec.id.db,
			field_rec.id.table, field_rec.id.field,
			ntohl(field_rec.field_size),
			ntohl(field_rec.field_offset), field_rec.name);
	}
}

static void ssa_db_db_def_load(FILE *fd, struct db_def *p_db_def)
{
	uint32_t table_def_size = 0;
	int res = 0;
	char line[1024] = {};

	if (NULL != fgets(line, 1024, fd)) {
		res = sscanf(line, DB_DEF_FORMAT_READ,
			     &p_db_def->version, &p_db_def->size,
			     &p_db_def->id.db, &p_db_def->id.table,
			     &p_db_def->id.field, &table_def_size,
			     &p_db_def->epoch, p_db_def->name);

		if (res != 8)
			ssa_log_warn(SSA_LOG_DEFAULT,
				    "%d fields out of 8 were loaded\n", res);

		p_db_def->epoch = htonll(p_db_def->epoch);
		p_db_def->table_def_size = htonl(table_def_size);
	}
}

static void ssa_db_table_def_load(FILE *fd, struct db_table_def *p_def_tbl)
{
	int res = 0;

	res = fscanf(fd, TABLE_DEF_FORMAT_READ,
		     &p_def_tbl->version, &p_def_tbl->size,
		     &p_def_tbl->type, &p_def_tbl->access,
		     &p_def_tbl->id.db, &p_def_tbl->id.table,
		     &p_def_tbl->id.field, &p_def_tbl->record_size,
		     &p_def_tbl->ref_table_id, p_def_tbl->name);
	if (res != 10)
		ssa_log_warn(SSA_LOG_DEFAULT,
			    "%d fields out of 10 were loaded\n", res);

	p_def_tbl->record_size = htonl(p_def_tbl->record_size);
	p_def_tbl->ref_table_id = htonl(p_def_tbl->ref_table_id);
}

static void ssa_db_dataset_load(FILE *fd, struct db_dataset *p_dataset)
{
	int res = 0;

	res = fscanf(fd, DATASET_DEF_FORMAT,
		     &p_dataset->version, &p_dataset->size,
		     &p_dataset->access, &p_dataset->id.db,
		     &p_dataset->id.table, &p_dataset->id.field,
		     &p_dataset->epoch, &p_dataset->set_size,
		     &p_dataset->set_offset, &p_dataset->set_count);
	if (res != 10)
		ssa_log_warn(SSA_LOG_DEFAULT,
			    "%d fields out of 10 were loaded\n", res);

	p_dataset->epoch = htonll(p_dataset->epoch);
	p_dataset->set_size = htonll(p_dataset->set_size);
	p_dataset->set_offset = htonll(p_dataset->set_offset);
	p_dataset->set_count = htonll(p_dataset->set_count);
}

static void ssa_db_field_tbl_load(FILE *fd, struct db_dataset *p_dataset,
				  struct db_field_def *p_data_tbl)
{
	struct db_field_def field_rec;
	uint32_t i = 0;
	int res = 0;
	char line[1024] = {};

	for (i = 0; i < ntohll(p_dataset->set_count); i++) {
		if (NULL != fgets(line, 1024, fd)) {
			res = sscanf(line, DB_FIELD_DEF_FORMAT_READ,
				     &field_rec.version, &field_rec.type,
				     &field_rec.id.db, &field_rec.id.table,
				     &field_rec.id.field, &field_rec.field_size,
				     &field_rec.field_offset, field_rec.name);
			if (res != 8)
				ssa_log_warn(SSA_LOG_DEFAULT,
					    "%d fields out of 8 were loaded\n", res);

			field_rec.field_size = htonl(field_rec.field_size);
			field_rec.field_offset = htonl(field_rec.field_offset);
		}

		memcpy(&p_data_tbl[i], &field_rec, sizeof(field_rec));
	}
}

static void ssa_db_rec_tbl_dump(FILE *fd, enum ssa_db_helper_mode mode,
				struct db_table_def *p_data_tbl_def,
				struct db_dataset *p_dataset, void *p_data_tbl,
				struct db_dataset *p_dataset_field,
				struct db_field_def *p_field_tbl)
{
	struct db_field_def *p_field_rec;
	uint8_t *p_data_rec, *p_data_field;
	uint64_t i, k, j;

	for (i = 0; i < ntohll(p_dataset->set_count); i++) {
		p_data_rec = (uint8_t *)((uint8_t *)p_data_tbl + i * ntohl(p_data_tbl_def->record_size));
		if (mode == SSA_DB_HELPER_STANDARD) {
			for (k = 0; k < ntohl(p_data_tbl_def->record_size); k++)
				fprintf(fd, "%c", *(char *)((char *)p_data_rec + k));
		} else {
			for (k = 0; k < ntohll(p_dataset_field->set_count); k++) {
				p_field_rec = &p_field_tbl[k];
				p_data_field = p_data_rec + ntohl(p_field_rec->field_offset) / 8;

				if (mode == SSA_DB_HELPER_HUMAN)
					fprintf(fd, "%s ", p_field_rec->name);

				switch (p_field_rec->type) {
				case DBF_TYPE_U8:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 8; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "%" SCNu8 "",
							*((uint8_t *)(p_data_field + j)));
					}
					break;
				case DBF_TYPE_U16:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 16; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "%" SCNu16 "",
							*((uint16_t *)(p_data_field + (j * 2))));
					}
					break;
				case DBF_TYPE_U32:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 32; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "%" PRIx32 "",
							*((uint32_t *)(p_data_field + (j * 4))));
					}
					break;
				case DBF_TYPE_U64:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 64; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "0x%" PRIx64 "",
							*((uint64_t *)(p_data_field + (j * 8))));
					}
					break;
				case DBF_TYPE_NET16:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 16; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "%" SCNu16 "",
							ntohs(*((uint16_t *)(p_data_field + (j * 2)))));
					}
					break;
				case DBF_TYPE_NET32:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 32; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "%" PRIx32 "",
							ntohl(*((uint32_t *)(p_data_field + (j * 4)))));
					}
					break;
				case DBF_TYPE_NET64:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 64; j++) {
						if (j > 0)
							fprintf(fd, SSA_DB_HELPER_ARRAY_DELIMITER);
						fprintf(fd, "0x%" PRIx64 "",
							ntohll(*((uint64_t *)(p_data_field + (j * 8)))));
					}
					break;
				case DBF_TYPE_NET128:
					/* TODO: add 128 bit handling */
					break;
				case DBF_TYPE_STRING:
					fprintf(fd, "%s",
						((char *)(p_data_field)));
					break;
				default:
					ssa_log_err(SSA_LOG_DEFAULT, "Unknown field type\n");
					break;
				}

				if (k < ntohll(p_dataset_field->set_count) &&
				    mode == SSA_DB_HELPER_DEBUG)
					fprintf(fd, SSA_DB_HELPER_DELIMITER);

				if (k < ntohll(p_dataset_field->set_count) - 1 &&
				    mode == SSA_DB_HELPER_HUMAN)
					fprintf(fd, " ");
			}
		}
		fprintf(fd, "\n");
	}
}

static void ssa_db_rec_tbl_load(FILE *fd, enum ssa_db_helper_mode mode,
				struct db_table_def *p_data_tbl_def,
				struct db_dataset *p_dataset, void *p_data_tbl,
				struct db_dataset *p_dataset_field,
				struct db_field_def *p_field_tbl)
{
	struct db_field_def *p_field_rec;
	uint64_t i, k, j;
	uint8_t *p_data_rec, *p_data_field;
	char c;

	if (mode != SSA_DB_HELPER_STANDARD && mode != SSA_DB_HELPER_DEBUG)
		return;

	for (i = 0; i < ntohll(p_dataset->set_count); i++) {
		p_data_rec = (uint8_t *)((uint8_t *)p_data_tbl + i * ntohl(p_data_tbl_def->record_size));
		if (mode == SSA_DB_HELPER_STANDARD) {
			for (k = 0; k < ntohl(p_data_tbl_def->record_size); k++) {
				fscanf(fd, "%c", &c);
				memcpy(p_data_rec + k, &c, sizeof(c));
			}
		} else {
			for (k = 0; k < ntohll(p_dataset_field->set_count); k++) {
				p_field_rec = &p_field_tbl[k];
				p_data_field = p_data_rec + ntohl(p_field_rec->field_offset) / 8;

				switch (p_field_rec->type) {
				case DBF_TYPE_U8:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 8; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 8) - 1)
							fscanf(fd, "%" SCNu8 SSA_DB_HELPER_DELIMITER,
							       ((uint8_t *)p_data_field + j));
						else
							fscanf(fd, "%" SCNu8 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint8_t *)p_data_field + j));
					}
					break;
				case DBF_TYPE_U16:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 16; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 16) - 1)
							fscanf(fd, "%" SCNu16 SSA_DB_HELPER_DELIMITER,
							       ((uint16_t *)p_data_field + (j * 2)));
						else
							fscanf(fd, "%" SCNu16 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint16_t *)p_data_field + (j * 2)));
					}
					break;
				case DBF_TYPE_U32:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 32; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 32) - 1)
							fscanf(fd, "%" PRIx32 SSA_DB_HELPER_DELIMITER,
							       ((uint32_t *)p_data_field + (j * 4)));
						else
							fscanf(fd, "%" PRIx32 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint32_t *)p_data_field + (j * 4)));
					}
					break;
				case DBF_TYPE_U64:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 64; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 64) - 1)
							fscanf(fd, "0x%" PRIx64 SSA_DB_HELPER_DELIMITER,
							       ((uint64_t *)p_data_field + (j * 8)));
						else
							fscanf(fd, "0x%" PRIx64 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint64_t *)p_data_field + (j * 8)));
					}
					break;
				case DBF_TYPE_NET16:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 16; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 16) - 1)
							fscanf(fd, "%" SCNu16 SSA_DB_HELPER_DELIMITER,
							       ((uint16_t *)p_data_field + (j * 2)));
						else
							fscanf(fd, "%" SCNu16 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint16_t *)p_data_field + (j * 2)));
						*((uint16_t *)p_data_field + (j * 2)) =
								htons(*((uint16_t *)p_data_field + (j * 2)));
					}
					break;
				case DBF_TYPE_NET32:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 32; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 32) - 1)
							fscanf(fd, "%" PRIx32 SSA_DB_HELPER_DELIMITER,
							       ((uint32_t *)p_data_field + (j * 4)));
						else
							fscanf(fd, "%" PRIx32 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint32_t *)p_data_field + (j * 4)));
						*((uint32_t *)p_data_field + (j * 4)) =
								htonl(*((uint32_t *)p_data_field + (j * 4)));
					}
					break;
				case DBF_TYPE_NET64:
					for (j = 0; j < ntohl(p_field_rec->field_size) / 64; j++) {
						if (j == (ntohl(p_field_rec->field_size) / 64) - 1)
							fscanf(fd, "0x%" PRIx64 SSA_DB_HELPER_DELIMITER,
							       ((uint64_t *)p_data_field + (j * 8)));
						else
							fscanf(fd, "0x%" PRIx64 SSA_DB_HELPER_ARRAY_DELIMITER,
							       ((uint64_t *)p_data_field + (j * 8)));
						*((uint64_t *)p_data_field + (j * 8)) =
								htonll(*((uint64_t *)p_data_field + (j * 8)));
					}
					break;
				case DBF_TYPE_NET128:
					/* TODO: add 128 bit handling */
					break;
				case DBF_TYPE_STRING:
					fscanf(fd, "%s" SSA_DB_HELPER_DELIMITER, ((char *) p_data_field));
					break;
				default:
					ssa_log_err(SSA_LOG_DEFAULT, "Unknown field type\n");
					break;
				}
			}
		}

		/* moving file descriptor 1 byte forward due to '\n' char at the end of line */
		fseek(fd, 1, SEEK_CUR);
	}
}

static void ssa_db_rec_tbl_dump_var_size(FILE *fd, enum ssa_db_helper_mode mode,
					 struct db_table_def *p_data_tbl_def,
					 struct db_dataset *p_dataset,
					 void *p_data_tbl)
{
	uint64_t i;
	uint8_t *p_data_rec;

	for (i = 0; i < ntohll(p_dataset->set_size); i++) {
		p_data_rec = (uint8_t *)((uint8_t *)p_data_tbl + i);
		if (mode == SSA_DB_HELPER_STANDARD)
			fprintf(fd, "%c", *(char *)p_data_rec);
		else
			fprintf(fd, "%" SCNu8 SSA_DB_HELPER_DELIMITER,
				*((uint8_t *)(p_data_rec)));
		/* fprintf(fd, "\n"); */
	}
	fprintf(fd, "\n");
}

static void ssa_db_rec_tbl_load_var_size(FILE *fd, enum ssa_db_helper_mode mode,
					 struct db_table_def *p_data_tbl_def,
					 struct db_dataset *p_dataset,
					 void *p_data_tbl)
{
	uint64_t i;
	uint8_t *p_data_rec;
	char c;

	if (mode != SSA_DB_HELPER_STANDARD && mode != SSA_DB_HELPER_DEBUG)
		return;

	for (i = 0; i < ntohll(p_dataset->set_size); i++) {
		p_data_rec = (uint8_t *)((uint8_t *)p_data_tbl + i);
		if (mode == SSA_DB_HELPER_STANDARD) {
			fscanf(fd, "%c", &c);
			memcpy((char *)p_data_rec, &c, sizeof(c));
		} else {
			fscanf(fd, "%" SCNu8 SSA_DB_HELPER_DELIMITER,
			       ((uint8_t *)(p_data_rec)));
		}

		/* moving file descriptor 1 byte forward due to '\n' char at the end of line */
		/* fseek(fd, 1, SEEK_CUR); */
	}
}

static uint32_t ssa_db_table_def_load_record_size(FILE *fd)
{
	struct db_table_def table_def;

	ssa_db_table_def_load(fd, &table_def);

	if (ntohl(table_def.record_size) == DB_VARIABLE_SIZE)
		return 1;

	return ntohl(table_def.record_size);
}

static uint64_t ssa_db_dataset_load_record_count(FILE *fd)
{
	struct db_dataset dataset;

	ssa_db_dataset_load(fd, &dataset);

	if (ntohll(dataset.set_count) == 0)
		return ntohll(dataset.set_size);

	return ntohll(dataset.set_count);
}

static void ssa_db_tbl_dump(char *dir_path, const struct ssa_db *p_ssa_db,
			    const size_t data_tbl_def_indx,
			    const size_t fields_tbl_def_indx,
			    const size_t dataset_indx,
			    enum ssa_db_helper_mode mode)
{
	FILE *fd;
	short contains_var_sized_records = 0;
	char buffer[128] = {};

	if (p_ssa_db->p_def_tbl[data_tbl_def_indx].record_size ==
	    htonl(DB_VARIABLE_SIZE))
		contains_var_sized_records = 1;

	sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_TABLE_DEF_NAME);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (1)\n", buffer);
		return;
	}

	ssa_db_table_def_dump(fd, p_ssa_db->p_def_tbl, data_tbl_def_indx);
	fclose(fd);

	sprintf(buffer, "%s/" SSA_DB_HELPER_DATASET_NAME, dir_path);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (2)\n", buffer);
		return;
	}

	ssa_db_dataset_dump(fd, &p_ssa_db->p_db_tables[dataset_indx]);
	fclose(fd);

	if (!contains_var_sized_records) {
		sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_FIELD_DEF_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (4)\n", buffer);
			return;
		}

		ssa_db_table_def_dump(fd, p_ssa_db->p_def_tbl, fields_tbl_def_indx);
		fclose(fd);

		sprintf(buffer, "%s/" SSA_DB_HELPER_FIELDS_DATASET_NAME, dir_path);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (5)\n", buffer);
			return;
		}

		ssa_db_dataset_dump(fd, &p_ssa_db->p_db_field_tables[dataset_indx]);
		fclose(fd);

		sprintf(buffer, "%s/" SSA_DB_HELPER_FIELDS_NAME, dir_path);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (6)\n", buffer);
			return;
		}

		ssa_db_field_tbl_dump(fd, &p_ssa_db->p_db_field_tables[dataset_indx],
				      (struct db_field_def *)p_ssa_db->pp_field_tables[dataset_indx]);
		fclose(fd);
	}

	sprintf(buffer, "%s/" SSA_DB_HELPER_DATA_NAME, dir_path);
	if (mode == SSA_DB_HELPER_STANDARD)
		fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_BIN);
	else
		fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);

	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file (3)\n", buffer);
		return;
	}
	/* TODO (optional): add distinguish between added and removed records */
	if (contains_var_sized_records)
		ssa_db_rec_tbl_dump_var_size(fd, mode,
					     &p_ssa_db->p_def_tbl[data_tbl_def_indx],
					     &p_ssa_db->p_db_tables[dataset_indx],
					     p_ssa_db->pp_tables[dataset_indx]);
	else
		ssa_db_rec_tbl_dump(fd, mode, &p_ssa_db->p_def_tbl[data_tbl_def_indx],
				    &p_ssa_db->p_db_tables[dataset_indx],
				    p_ssa_db->pp_tables[dataset_indx],
				    &p_ssa_db->p_db_field_tables[dataset_indx],
				    (struct db_field_def *)p_ssa_db->pp_field_tables[dataset_indx]);

	fclose(fd);
}

static int ssa_db_tbl_load(char *dir_path, struct ssa_db *p_ssa_db,
			   uint64_t tbl_idx, enum ssa_db_helper_mode mode)
{
	FILE *fd;
	struct db_table_def table_def, field_table_def;
	struct db_dataset dataset, field_dataset;
	int var_size_recs = 0;
	char buffer[SSA_DB_HELPER_PATH_MAX] = {};

	/* table definition loading */
	sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_TABLE_DEF_NAME);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
		return -1;
	}
	ssa_db_table_def_load(fd, &table_def);
	fclose(fd);

	ssa_db_table_def_insert(p_ssa_db->p_def_tbl,
				&p_ssa_db->db_table_def,
				table_def.version, table_def.size,
				table_def.type, table_def.access,
				table_def.id.db, table_def.id.table,
				table_def.id.field, table_def.name,
				ntohl(table_def.record_size),
				ntohl(table_def.ref_table_id));

	if (table_def.record_size == DB_VARIABLE_SIZE)
		var_size_recs = 1;

	/* data dataset loading */
	sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_DATASET_NAME);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
		return -1;
	}
	ssa_db_dataset_load(fd, &dataset);
	fclose(fd);

	ssa_db_dataset_init(&p_ssa_db->p_db_tables[tbl_idx],
			    dataset.version, dataset.size,
			    dataset.access, dataset.id.db,
			    dataset.id.table, dataset.id.field,
			    ntohll(dataset.epoch), ntohll(dataset.set_size),
			    ntohll(dataset.set_offset),
			    ntohll(dataset.set_count));

	if (!var_size_recs) {
		/* field table definition loading */
		sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_FIELD_DEF_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
			return -1;
		}
		ssa_db_table_def_load(fd, &field_table_def);
		fclose(fd);

		ssa_db_table_def_insert(p_ssa_db->p_def_tbl,
					&p_ssa_db->db_table_def,
					field_table_def.version,
					field_table_def.size,
					field_table_def.type,
					field_table_def.access,
					field_table_def.id.db,
					field_table_def.id.table,
					field_table_def.id.field,
					field_table_def.name,
					ntohl(field_table_def.record_size),
					ntohl(field_table_def.ref_table_id));

		/* field dataset loading */
		sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_FIELDS_DATASET_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
			return -1;
		}
		ssa_db_dataset_load(fd, &field_dataset);
		fclose(fd);

		ssa_db_dataset_init(&p_ssa_db->p_db_field_tables[tbl_idx],
				    field_dataset.version, field_dataset.size,
				    field_dataset.access, field_dataset.id.db,
				    field_dataset.id.table, field_dataset.id.field,
				    ntohll(field_dataset.epoch),
				    ntohll(field_dataset.set_size),
				    ntohll(field_dataset.set_offset),
				    ntohll(field_dataset.set_count));

		sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_FIELDS_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
			return -1;
		}
		ssa_db_field_tbl_load(fd, &field_dataset,
				      p_ssa_db->pp_field_tables[tbl_idx]);
		fclose(fd);
	}

	/* TODO (optional): add distinguish between added and removed records */
	sprintf(buffer, "%s/%s", dir_path, SSA_DB_HELPER_DATA_NAME);
	if (mode == SSA_DB_HELPER_STANDARD)
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_BIN);
	else
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
		return -1;
	}
	if (var_size_recs)
		ssa_db_rec_tbl_load_var_size(fd, mode, &table_def,&dataset,
					     p_ssa_db->pp_tables[tbl_idx]);
	else
		ssa_db_rec_tbl_load(fd, mode, &table_def,
				    &dataset, p_ssa_db->pp_tables[tbl_idx],
				    &field_dataset,
				    (struct db_field_def *)p_ssa_db->pp_field_tables[tbl_idx]);

	fclose(fd);

	return 0;
}

static void removedir(const char *dirname)
{
	DIR *dp;
	struct dirent *ep;
	char abs_filename[SSA_DB_HELPER_PATH_MAX];

	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			snprintf(abs_filename, SSA_DB_HELPER_PATH_MAX, "%s/%s",
				 dirname, ep->d_name);

			if (ep->d_type == DT_DIR) {
				if (strcmp(ep->d_name, ".") &&
				    strcmp(ep->d_name, ".."))
					removedir(abs_filename);
			} else {
				if (remove(abs_filename))
					ssa_log(SSA_LOG_DEFAULT,
						"unable to remove file %s ERROR %d (%s)\n",
						abs_filename, errno, strerror(errno));
			}
		}
		closedir(dp);
	} else {
		ssa_log_err(SSA_LOG_DEFAULT, "Couldn't open '%s' directory\n", dirname);
	}

	if (remove(dirname))
		ssa_log(SSA_LOG_DEFAULT,
			"unable to remove directory %s ERROR %d (%s)\n",
			dirname, errno, strerror(errno));
}

/* recursive function - equivalent to linux 'mkdir -p' */
static void mkpath(const char *dir, mode_t mode)
{
	struct stat dstat;
	char path[128];
	char *p = NULL;

	snprintf(path, sizeof path, "%s", dir);
	for (p = path + strlen(dir) - 1; p != path; p--) {
		if (*p != '/')
			continue;
		*p = '\0';
		break;
	}

	if (!lstat(path, &dstat)) {
		if (!lstat(dir, &dstat))
			removedir(dir);
		if (mkdir(dir, mode))
			ssa_log(SSA_LOG_DEFAULT,
				"unable to create %s directory ERROR %d (%s)\n",
				dir, errno, strerror(errno));
		return;
	}

	mkpath(path, mode);

	if (!lstat(dir, &dstat))
		removedir(dir);
	if (mkdir(dir, mode))
		ssa_log(SSA_LOG_DEFAULT,
			"unable to create %s directory ERROR %d (%s)\n",
			dir, errno, strerror(errno));
}

void ssa_db_save(const char *path_dir, const struct ssa_db *p_ssa_db,
		 enum ssa_db_helper_mode mode)
{
	FILE *fd;
	int i = 0, tbls_n = 0;
	char buffer[SSA_DB_HELPER_PATH_MAX] = {};

	ssa_log_func(SSA_LOG_DEFAULT);
	assert(p_ssa_db);

	mkpath(path_dir, S_IRWXU | S_IRWXG | S_IRWXO);

	tbls_n = ntohll(p_ssa_db->db_table_def.set_count);

	/****************** Dumping db_def record *******************/
	sprintf(buffer, "%s/%s", path_dir, SSA_DB_HELPER_DB_DEF_NAME);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_WRITE_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
		return;
	}
	ssa_db_db_def_dump(fd, &p_ssa_db->db_def);
	fclose(fd);
	/************************************************************/

	for (i = 0; i < tbls_n; ++i) {
		if (p_ssa_db->p_def_tbl[i].type == DBT_TYPE_DATA) {
			int j = 0, k = 0;
			struct db_id id = p_ssa_db->p_def_tbl[i].id; /* Data table id */

			for (j = 0; j < tbls_n; j++)
				if (p_ssa_db->p_def_tbl[j].type == DBT_TYPE_DEF &&
				    ntohl(p_ssa_db->p_def_tbl[j].ref_table_id) == id.table)
					break;

			for (k = 0; k < p_ssa_db->data_tbl_cnt; k++)
				if (p_ssa_db->p_db_tables[k].id.table == id.table)
					break;

			/* creating a directory for each dataset */
			sprintf(buffer, "mkdir \"%s/%s\"",
				path_dir, p_ssa_db->p_def_tbl[i].name);
			system(buffer);

			/* dump dataset and its field dataset */
			sprintf(buffer, "%s/%s",
				path_dir, p_ssa_db->p_def_tbl[i].name);
			ssa_db_tbl_dump(buffer, p_ssa_db, i, j, k, mode);
			ssa_log(SSA_LOG_DEFAULT, "%s table was saved\n",
				p_ssa_db->p_def_tbl[i].name);
		}
	}
}

static struct ssa_db *ssa_db_load_allocate_new(const char *path_dir,
					       char *tbl_names,
					       uint64_t data_tbls_n)
{
	FILE *fd;
	struct ssa_db *p_ssa_db = NULL;
	uint64_t *num_recs_arr, *num_fields_arr, *recs_size_arr;
	uint64_t i;
	char buffer[SSA_DB_HELPER_PATH_MAX] = {};

	num_recs_arr = (uint64_t *) malloc(sizeof(*num_recs_arr) * data_tbls_n);
	if (!num_recs_arr) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate records number array\n");
		return NULL;
	}

	num_fields_arr = (uint64_t *) malloc(sizeof(*num_fields_arr) * data_tbls_n);
	if (!num_fields_arr) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate fields number array\n");
		free(num_recs_arr);
		return NULL;
	}

	recs_size_arr = (uint64_t *) malloc(sizeof(*recs_size_arr) * data_tbls_n);
	if (!recs_size_arr) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate records size array\n");
		free(num_fields_arr);
		free(num_recs_arr);
		return NULL;
	}

	/* reading datasets */
	for (i = 0; i < data_tbls_n; i++) {
		sprintf(buffer, "%s/%s/%s", path_dir,
			tbl_names + DB_NAME_LEN * i,
			SSA_DB_HELPER_DATASET_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd)
			continue;

		num_recs_arr[i] = ssa_db_dataset_load_record_count(fd);
		fclose(fd);
	}

	/* reading field datasets */
	for (i = 0; i < data_tbls_n; i++) {
		sprintf(buffer, "%s/%s/%s", path_dir,
			tbl_names + DB_NAME_LEN * i,
			SSA_DB_HELPER_FIELDS_DATASET_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd) {
			num_fields_arr[i] = DB_VARIABLE_SIZE;
			continue;
		}

		num_fields_arr[i] = ssa_db_dataset_load_record_count(fd);
		fclose(fd);
	}

	/* reading def tables - extracting record sizes */
	for (i = 0; i < data_tbls_n; i++) {
		sprintf(buffer, "%s/%s/%s", path_dir,
			tbl_names + DB_NAME_LEN * i,
			SSA_DB_HELPER_TABLE_DEF_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd)
			continue;

		recs_size_arr[i] = ssa_db_table_def_load_record_size(fd);
		fclose(fd);
	}

	p_ssa_db = ssa_db_alloc(num_recs_arr, recs_size_arr, num_fields_arr,
				data_tbls_n);

	free(recs_size_arr);
	free(num_fields_arr);
	free(num_recs_arr);

	return p_ssa_db;
}

struct ssa_db *ssa_db_load(const char *path_dir, enum ssa_db_helper_mode mode)
{
	DIR *d;
	FILE *fd;
	struct dirent *dir;
	struct ssa_db *p_ssa_db = NULL;
	char *tbl_names;
	uint64_t data_tbls_n = 0;
	uint64_t i = 0;
	struct db_table_def table_def;
	char buffer[SSA_DB_HELPER_PATH_MAX] = {};

	ssa_log_func(SSA_LOG_DEFAULT);
	if (mode != SSA_DB_HELPER_STANDARD && mode != SSA_DB_HELPER_DEBUG) {
		ssa_log_err(SSA_LOG_DEFAULT, "mode (%d) not supported for loading\n", mode);
		return NULL;
	}

	d = opendir(path_dir);
	if (!d)
		return NULL;

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_DIR ||
		    !strcmp(dir->d_name, ".") ||
		    !strcmp(dir->d_name, ".."))
			continue;
		data_tbls_n++;
	}
	rewinddir(d);

	tbl_names = (char *) malloc(data_tbls_n * sizeof(*tbl_names) * DB_NAME_LEN);
	if (!tbl_names) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate table names buffer\n");
		closedir(d);
		return NULL;
	}

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_DIR ||
		    !strcmp(dir->d_name, ".") ||
		    !strcmp(dir->d_name, ".."))
			continue;

		sprintf(buffer, "%s/%s/%s", path_dir, dir->d_name,
			SSA_DB_HELPER_TABLE_DEF_NAME);
		fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
		if (!fd) {
			ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
			closedir(d);
			goto Error;
		}
		ssa_db_table_def_load(fd, &table_def);
		fclose(fd);

		strcpy((tbl_names + DB_NAME_LEN * table_def.id.table),
		       dir->d_name);
	}
	closedir(d);

	p_ssa_db = ssa_db_load_allocate_new(path_dir, tbl_names, data_tbls_n);
	if (!p_ssa_db) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed allocating SSA DB\n");
		goto Error;
	}

	sprintf(buffer, "%s/%s", path_dir, SSA_DB_HELPER_DB_DEF_NAME);
	fd = fopen(buffer, SSA_DB_HELPER_FILE_READ_MODE_TXT);
	if (!fd) {
		ssa_log_err(SSA_LOG_DEFAULT, "Failed opening %s file\n", buffer);
		goto Error;
	}
	ssa_db_db_def_load(fd, &p_ssa_db->db_def);
	fclose(fd);

	ssa_db_dataset_init(&p_ssa_db->db_table_def, DB_DS_VERSION,
			    sizeof(p_ssa_db->db_table_def),
			    DBT_ACCESS_NET_ORDER, p_ssa_db->db_def.id.db,
			    DBT_DEF_DS_ID, 0, 0 /* epoch */, 0 /* set_size */,
			    0 /* set_offset */, 0 /* set_count */);

	for (i = 0; i < data_tbls_n; i++) {
		sprintf(buffer, "%s/%s", path_dir, tbl_names + DB_NAME_LEN * i);
		ssa_db_tbl_load(buffer, p_ssa_db, i, mode);
		ssa_log(SSA_LOG_DEFAULT, "%s table was loaded\n",
			p_ssa_db->p_def_tbl[i].name);
	}
	free(tbl_names);

	return p_ssa_db;

Error:
	free(tbl_names);
	if (p_ssa_db)
		ssa_db_destroy(p_ssa_db);
	return NULL;
}
