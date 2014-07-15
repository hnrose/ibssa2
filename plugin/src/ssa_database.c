/*
 * Copyright (c) 2011-2013 Mellanox Technologies LTD. All rights reserved.
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

#include <stdlib.h>
#include <stddef.h>
#include <infiniband/ssa_smdb.h>
#include <infiniband/ssa_database.h>
#include <opensm/osm_switch.h>

struct ssa_db_lft *ssa_database_lft_init()
{
	struct ssa_db_lft *p_lft_db =
		(struct ssa_db_lft *) calloc(1, sizeof(*p_lft_db));

	if (p_lft_db) {
		cl_qmap_init(&p_lft_db->ep_db_lft_block_tbl);
		cl_qmap_init(&p_lft_db->ep_db_lft_top_tbl);
		cl_qmap_init(&p_lft_db->ep_dump_lft_block_tbl);
		cl_qmap_init(&p_lft_db->ep_dump_lft_top_tbl);
	}

	return p_lft_db;
}

void ssa_database_lft_delete(struct ssa_db_lft *p_lft_db)
{
	if (!p_lft_db)
		return;

	ssa_qmap_apply_func(&p_lft_db->ep_db_lft_block_tbl,
			    ep_map_rec_delete_pfn);
	ssa_qmap_apply_func(&p_lft_db->ep_db_lft_top_tbl,
			    ep_map_rec_delete_pfn);
	ssa_qmap_apply_func(&p_lft_db->ep_dump_lft_block_tbl,
			    ep_map_rec_delete_pfn);
	ssa_qmap_apply_func(&p_lft_db->ep_dump_lft_top_tbl,
			    ep_map_rec_delete_pfn);

	cl_qmap_remove_all(&p_lft_db->ep_db_lft_block_tbl);
	cl_qmap_remove_all(&p_lft_db->ep_db_lft_top_tbl);
	cl_qmap_remove_all(&p_lft_db->ep_dump_lft_block_tbl);
	cl_qmap_remove_all(&p_lft_db->ep_dump_lft_top_tbl);

	free(p_lft_db->p_db_lft_block_tbl);
	free(p_lft_db->p_dump_lft_block_tbl);
	free(p_lft_db->p_db_lft_top_tbl);
	free(p_lft_db->p_dump_lft_top_tbl);
	free(p_lft_db);
}

struct ssa_database *ssa_database_init(void)
{
	struct ssa_database *p_ssa_database =
		(struct ssa_database *) calloc(1, sizeof(struct ssa_database));
	if (!p_ssa_database)
		goto err1;

	cl_qlist_init(&p_ssa_database->lft_rec_list);
	pthread_mutex_init(&p_ssa_database->lft_rec_list_lock, NULL);

	p_ssa_database->p_lft_db = ssa_database_lft_init();
	if (!p_ssa_database->p_lft_db)
		goto err2;

	p_ssa_database->p_current_db = ssa_db_extract_init();
	if (!p_ssa_database->p_current_db)
		goto err3;

	p_ssa_database->p_previous_db = ssa_db_extract_init();
	if (!p_ssa_database->p_previous_db)
		goto err4;

	p_ssa_database->p_dump_db = ssa_db_extract_init();
	if (!p_ssa_database->p_dump_db)
		goto err5;

	return p_ssa_database;
err5:
	ssa_db_extract_delete(p_ssa_database->p_previous_db);
err4:
	ssa_db_extract_delete(p_ssa_database->p_current_db);
err3:
	ssa_database_lft_delete(p_ssa_database->p_lft_db);
err2:
	pthread_mutex_destroy(&p_ssa_database->lft_rec_list_lock);
	free(p_ssa_database);
err1:
	return NULL;
}

void ssa_database_delete(struct ssa_database *p_ssa_db)
{
	if (!p_ssa_db)
		return;

	ssa_db_extract_delete(p_ssa_db->p_dump_db);
	ssa_db_extract_delete(p_ssa_db->p_previous_db);
	ssa_db_extract_delete(p_ssa_db->p_current_db);
	ssa_database_lft_delete(p_ssa_db->p_lft_db);
	pthread_mutex_destroy(&p_ssa_db->lft_rec_list_lock);
	free(p_ssa_db);
}

struct ssa_db_extract *ssa_db_extract_init(void)
{
	struct ssa_db_extract *p_ssa_db;

	p_ssa_db = (struct ssa_db_extract *) calloc(1, sizeof(*p_ssa_db));
	if (p_ssa_db) {
		cl_qmap_init(&p_ssa_db->ep_guid_to_lid_tbl);
		cl_qmap_init(&p_ssa_db->ep_node_tbl);
		cl_qmap_init(&p_ssa_db->ep_port_tbl);
		cl_qmap_init(&p_ssa_db->ep_link_tbl);
	}
	return p_ssa_db;
}

void ssa_db_extract_delete(struct ssa_db_extract *p_ssa_db)
{
	if (p_ssa_db) {
		free(p_ssa_db->p_pkey_tbl);
		free(p_ssa_db->p_port_tbl);
		free(p_ssa_db->p_link_tbl);
		free(p_ssa_db->p_guid_to_lid_tbl);
		free(p_ssa_db->p_node_tbl);

		ssa_qmap_apply_func(&p_ssa_db->ep_guid_to_lid_tbl, ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db->ep_node_tbl, ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db->ep_port_tbl, ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db->ep_link_tbl, ep_map_rec_delete_pfn);

		cl_qmap_remove_all(&p_ssa_db->ep_node_tbl);
		cl_qmap_remove_all(&p_ssa_db->ep_guid_to_lid_tbl);
		cl_qmap_remove_all(&p_ssa_db->ep_port_tbl);
		cl_qmap_remove_all(&p_ssa_db->ep_link_tbl);
		free(p_ssa_db);
	}
}

uint64_t ep_rec_gen_key(uint16_t base, uint16_t index)
{
	uint64_t key;
	key = (uint64_t) base;
	key |= (uint64_t) index << 16;
	return key;
}

struct ep_map_rec *ep_map_rec_init(uint64_t offset)
{
        struct ep_map_rec *p_map_rec;

	p_map_rec = (struct ep_map_rec *) malloc(sizeof(*p_map_rec));
	if (p_map_rec)
		p_map_rec->offset = offset;

	return p_map_rec;
}

void ep_map_rec_delete(struct ep_map_rec *p_map_rec)
{
	free(p_map_rec);
}

void ep_map_rec_delete_pfn(cl_map_item_t * p_map_item)
{
	struct ep_map_rec *p_map_rec;

	p_map_rec = (struct ep_map_rec *) p_map_item;
	ep_map_rec_delete(p_map_rec);
}

void ep_qmap_clear(cl_qmap_t * p_map)
{
	struct ep_map_rec *p_map_rec, *p_map_rec_next;

	p_map_rec_next = (struct ep_map_rec *)cl_qmap_head(p_map);
	while (p_map_rec_next !=
	       (struct ep_map_rec *)cl_qmap_end(p_map)) {
		p_map_rec = p_map_rec_next;
		p_map_rec_next = (struct ep_map_rec *)cl_qmap_next(&p_map_rec->map_item);
		cl_qmap_remove_item(p_map, &p_map_rec->map_item);
		free(p_map_rec);
	}
}

void ssa_qmap_apply_func(cl_qmap_t *p_qmap, void (*pfn_func)(cl_map_item_t *))
{
	cl_map_item_t *p_map_item, *p_map_item_next;
        p_map_item_next = cl_qmap_head(p_qmap);
        while (p_map_item_next != cl_qmap_end(p_qmap)) {
		p_map_item = p_map_item_next;
		p_map_item_next = cl_qmap_next(p_map_item);
                pfn_func(p_map_item);
        }
}
