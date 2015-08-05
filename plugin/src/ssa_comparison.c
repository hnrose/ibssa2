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

#include <stdlib.h>
#include <asm/byteorder.h>
#include <common.h>
#include <infiniband/ssa_database.h>
#include <infiniband/ssa_comparison.h>
#include <ssa_log.h>

extern int smdb_deltas;
extern int addr_preload;
extern char addr_data_file[128];
extern struct ssa_db *ipdb;
extern struct host_addr *parse_addr(const char *addr_file, uint64_t *ipv4,
				    uint64_t *ipv6, uint64_t *name);

/** =========================================================================
 */
struct ssa_db_diff *
ssa_db_diff_init(uint64_t epoch, uint64_t data_rec_cnt[SMDB_TBL_ID_MAX])
{
	struct ssa_db_diff *p_ssa_db_diff;

	p_ssa_db_diff = (struct ssa_db_diff *) calloc(1, sizeof(*p_ssa_db_diff));
	if (p_ssa_db_diff) {
		p_ssa_db_diff->p_smdb = ssa_db_smdb_init(epoch, data_rec_cnt);

		cl_qmap_init(&p_ssa_db_diff->ep_guid_to_lid_tbl_added);
		cl_qmap_init(&p_ssa_db_diff->ep_node_tbl_added);
		cl_qmap_init(&p_ssa_db_diff->ep_port_tbl_added);
		cl_qmap_init(&p_ssa_db_diff->ep_link_tbl_added);
		cl_qmap_init(&p_ssa_db_diff->ep_guid_to_lid_tbl_removed);
		cl_qmap_init(&p_ssa_db_diff->ep_node_tbl_removed);
		cl_qmap_init(&p_ssa_db_diff->ep_port_tbl_removed);
		cl_qmap_init(&p_ssa_db_diff->ep_link_tbl_removed);
		cl_qmap_init(&p_ssa_db_diff->ep_lft_block_tbl);
		cl_qmap_init(&p_ssa_db_diff->ep_lft_top_tbl);
	}
	return p_ssa_db_diff;
}

/** =========================================================================
 */
void ssa_db_diff_destroy(struct ssa_db_diff * p_ssa_db_diff)
{
	if (p_ssa_db_diff) {
		ssa_db_smdb_destroy(p_ssa_db_diff->p_smdb);
		p_ssa_db_diff->p_smdb = NULL;

		ssa_qmap_apply_func(&p_ssa_db_diff->ep_guid_to_lid_tbl_added,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_guid_to_lid_tbl_removed,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_node_tbl_added,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_node_tbl_removed,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_port_tbl_added,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_port_tbl_removed,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_link_tbl_added,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_link_tbl_removed,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_lft_block_tbl,
				   ep_map_rec_delete_pfn);
		ssa_qmap_apply_func(&p_ssa_db_diff->ep_lft_top_tbl,
				   ep_map_rec_delete_pfn);

		cl_qmap_remove_all(&p_ssa_db_diff->ep_guid_to_lid_tbl_added);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_node_tbl_added);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_port_tbl_added);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_link_tbl_added);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_guid_to_lid_tbl_removed);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_node_tbl_removed);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_port_tbl_removed);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_link_tbl_removed);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_lft_block_tbl);
		cl_qmap_remove_all(&p_ssa_db_diff->ep_lft_top_tbl);
		free(p_ssa_db_diff);
	}
}

/** =========================================================================
 */
static void ssa_db_diff_compare_subnet_opts(struct ssa_db_extract * p_previous_db,
					    struct ssa_db_extract * p_current_db,
					    struct ssa_db_diff * p_ssa_db_diff,
					    boolean_t *tbl_changed)
{
	struct smdb_subnet_opts *p_subnet_opts =
		(struct smdb_subnet_opts *)
			p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_SUBNET_OPTS];
	struct db_dataset *p_dataset =
		(struct db_dataset *)
			&p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_SUBNET_OPTS];
	uint8_t dirty = p_ssa_db_diff->dirty;

	p_subnet_opts->change_mask = 0;

	if ((!p_previous_db->initialized && p_current_db->initialized) ||
	    !smdb_deltas) {
		p_subnet_opts->subnet_prefix = p_current_db->subnet_prefix;
		p_subnet_opts->sm_state = p_current_db->sm_state;
		p_subnet_opts->lmc = p_current_db->lmc;
		p_subnet_opts->subnet_timeout = p_current_db->subnet_timeout;
		p_subnet_opts->allow_both_pkeys = p_current_db->allow_both_pkeys;

		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SUBNET_PREFIX;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SM_STATE;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_LMC;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SUBNET_TIMEOUT;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_ALLOW_BOTH_PKEYS;

		if (smdb_deltas) {
			dirty = 1;
			goto Exit;
		} else {
			p_dataset->set_size = htonll(sizeof(*p_subnet_opts));
			p_dataset->set_count = htonll(1);
		}
	}

	if (p_previous_db->subnet_prefix != p_current_db->subnet_prefix) {
		p_subnet_opts->subnet_prefix = p_current_db->subnet_prefix;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SUBNET_PREFIX;
		dirty = 1;
	}
	if (p_previous_db->sm_state != p_current_db->sm_state) {
		p_subnet_opts->sm_state = p_current_db->sm_state;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SM_STATE;
		dirty = 1;
	}
	if (p_previous_db->lmc != p_current_db->lmc) {
		/* TODO: add error log message since the LMC is not supposed to change */
		p_subnet_opts->lmc = p_current_db->lmc;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_LMC;
		dirty = 1;
	}
	if (p_previous_db->subnet_timeout != p_current_db->subnet_timeout) {
		p_subnet_opts->subnet_timeout = p_current_db->subnet_timeout;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_SUBNET_TIMEOUT;
		dirty = 1;
	}
	if (p_previous_db->allow_both_pkeys != p_current_db->allow_both_pkeys) {
		p_subnet_opts->allow_both_pkeys = p_current_db->allow_both_pkeys;
		p_subnet_opts->change_mask |= SSA_DB_CHANGEMASK_ALLOW_BOTH_PKEYS;
		dirty = 1;
	}
Exit:
	if (dirty) {
		p_dataset->set_size = htonll(sizeof(*p_subnet_opts));
		p_dataset->set_count = htonll(1);
		p_ssa_db_diff->dirty = dirty;
		tbl_changed[SMDB_TBL_ID_SUBNET_OPTS] = TRUE;
	}
}

/** =========================================================================
 */
static void smdb_guid2lid_insert(cl_qmap_t *p_map,
				 struct db_dataset *p_dataset,
				 void **p_data_tbl,
				 uint64_t key,
				 cl_map_item_t * p_item,
				 void * p_data_tbl_src)
{
	struct ep_map_rec *p_map_rec_new, *p_map_rec_old;
	struct smdb_guid2lid *p_guid2lid_dest;
	struct smdb_guid2lid *p_guid2lid_src;
	uint64_t set_size, set_count;

	p_guid2lid_dest = (struct smdb_guid2lid *) *p_data_tbl;
	p_guid2lid_src = (struct smdb_guid2lid *) p_data_tbl_src;

	if (!p_guid2lid_dest) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized guid2lid records destination table\n");
		return;
	}

	if (!p_guid2lid_src) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized guid2lid records source table\n");
		return;
	}

	p_map_rec_new = (struct ep_map_rec *) malloc(sizeof(*p_map_rec_new));
	if (!p_map_rec_new) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to allocate offset object\n");
		return;
	}
	set_size = ntohll(p_dataset->set_size);
	set_count = ntohll(p_dataset->set_count);

	p_map_rec_new->offset = set_count;
	cl_qmap_insert(p_map, key, &p_map_rec_new->map_item);

	p_map_rec_old = (struct ep_map_rec *) p_item;
	memcpy(&p_guid2lid_dest[set_count],
	       &p_guid2lid_src[p_map_rec_old->offset],
	       sizeof(*p_guid2lid_dest));
	*p_data_tbl = p_guid2lid_dest;
	set_size += sizeof(*p_guid2lid_dest);
	set_count++;

	p_dataset->set_count = htonll(set_count);
	p_dataset->set_size = htonll(set_size);
}

/** =========================================================================
 */
static int smdb_guid2lid_cmp(cl_map_item_t * p_item_old,
			     void *p_data_tbl_old,
			     cl_map_item_t * p_item_new,
			     void *p_data_tbl_new)
{
	struct ep_map_rec *p_map_rec_old = (struct ep_map_rec *) p_item_old;
	struct ep_map_rec *p_map_rec_new = (struct ep_map_rec *) p_item_new;
	struct smdb_guid2lid *p_tbl_rec_old =
			(struct smdb_guid2lid *) p_data_tbl_old;
	struct smdb_guid2lid *p_tbl_rec_new =
			(struct smdb_guid2lid *) p_data_tbl_new;
	int res = 0;

	p_tbl_rec_old += p_map_rec_old->offset;
	p_tbl_rec_new += p_map_rec_new->offset;

	if (p_tbl_rec_old->lid != p_tbl_rec_new->lid ||
	    p_tbl_rec_old->lmc != p_tbl_rec_new->lmc ||
	    p_tbl_rec_old->is_switch != p_tbl_rec_new->is_switch)
		res = 1;

	return res;
}

/** =========================================================================
 */
static void smdb_node_insert(cl_qmap_t *p_map,
			     struct db_dataset *p_dataset,
			     void **p_data_tbl,
			     uint64_t key,
			     cl_map_item_t * p_item,
			     void *p_data_tbl_src)
{
	struct ep_map_rec *p_map_rec_new, *p_map_rec_old;
	struct smdb_node *p_node_dest;
	struct smdb_node *p_node_src;
	uint64_t set_size, set_count;

	p_node_dest = (struct smdb_node *) *p_data_tbl;
	p_node_src = (struct smdb_node *) p_data_tbl_src;

	if (!p_node_dest) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized node records destination table\n");
		return;
	}

	if (!p_node_src) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized node records source table\n");
		return;
	}

	p_map_rec_new = (struct ep_map_rec *) malloc(sizeof(*p_map_rec_new));
	if (!p_map_rec_new) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to allocate offset object\n");
		return;
	}
	set_size = ntohll(p_dataset->set_size);
	set_count = ntohll(p_dataset->set_count);

	p_map_rec_new->offset = set_count;
	cl_qmap_insert(p_map, key, &p_map_rec_new->map_item);

	p_map_rec_old = (struct ep_map_rec *) p_item;
	memcpy(&p_node_dest[set_count], &p_node_src[p_map_rec_old->offset],
	       sizeof(*p_node_dest));
	*p_data_tbl = p_node_dest;
	set_size += sizeof(*p_node_dest);
	set_count++;

	p_dataset->set_count = htonll(set_count);
	p_dataset->set_size = htonll(set_size);
}

/** =========================================================================
 */
static int smdb_node_cmp(cl_map_item_t * p_item_old,
			 void *p_data_tbl_old,
			 cl_map_item_t * p_item_new,
			 void *p_data_tbl_new)
{
	struct ep_map_rec *p_map_rec_old = (struct ep_map_rec *) p_item_old;
	struct ep_map_rec *p_map_rec_new = (struct ep_map_rec *) p_item_new;
	struct smdb_node *p_tbl_rec_old = (struct smdb_node *) p_data_tbl_old;
	struct smdb_node *p_tbl_rec_new = (struct smdb_node *) p_data_tbl_new;
	int res = 0;

	p_tbl_rec_old += p_map_rec_old->offset;
	p_tbl_rec_new += p_map_rec_new->offset;

	if (p_tbl_rec_old->is_enhanced_sp0 != p_tbl_rec_new->is_enhanced_sp0 ||
	    p_tbl_rec_old->node_type != p_tbl_rec_new->node_type ||
	    memcmp(p_tbl_rec_old->description, p_tbl_rec_new->description,
		   IB_NODE_DESCRIPTION_SIZE))
		res = 1;

	return res;
}

/** =========================================================================
 */
static void smdb_port_insert(cl_qmap_t *p_map,
			     struct db_dataset *p_dataset,
			     void **p_data_tbl,
			     struct db_dataset *p_ref_dataset,
			     void **p_data_ref_tbl,
			     uint64_t *p_offset,
			     uint64_t key,
			     cl_map_item_t * p_item,
			     void *p_data_tbl_src,
			     void *p_data_ref_tbl_src)
{
	struct ep_map_rec *p_map_rec_new, *p_map_rec_old;
	struct smdb_port *p_port_dest;
	struct smdb_port *p_port_src;
	uint64_t set_size, set_count;
	uint64_t offset_src;
	uint16_t size_pkey_tbl_src;
	uint8_t *p_pkey_tbl_dest;
	uint8_t *p_pkey_tbl_src;

	p_port_dest = (struct smdb_port *) *p_data_tbl;
	p_port_src = (struct smdb_port *) p_data_tbl_src;

	if (!p_port_dest) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized port records destination table\n");
		return;
	}

	if (!p_port_src) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized port records source table\n");
		return;
	}

	p_map_rec_new = (struct ep_map_rec *) malloc(sizeof(*p_map_rec_new));
	if (!p_map_rec_new) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to allocate offset object\n");
		return;
	}
	set_size = ntohll(p_dataset->set_size);
	set_count = ntohll(p_dataset->set_count);

	p_map_rec_new->offset = set_count;
	cl_qmap_insert(p_map, key, &p_map_rec_new->map_item);

	p_map_rec_old = (struct ep_map_rec *) p_item;
	memcpy(&p_port_dest[set_count], &p_port_src[p_map_rec_old->offset],
	       sizeof(*p_port_dest));
	*p_data_tbl = p_port_dest;
	set_size += sizeof(*p_port_dest);
	set_count++;

	if (p_data_ref_tbl && p_ref_dataset &&
	    p_data_ref_tbl_src && p_offset) {
		p_pkey_tbl_dest = (uint8_t *) *p_data_ref_tbl;
		p_pkey_tbl_src = (uint8_t *) p_data_ref_tbl_src;

		offset_src = ntohll(p_port_src[p_map_rec_old->offset].pkey_tbl_offset);
		size_pkey_tbl_src = ntohs(p_port_src[p_map_rec_old->offset].pkey_tbl_size);

		if (size_pkey_tbl_src == 0) {
			p_dataset->set_count = htonll(set_count);
			p_dataset->set_size = htonll(set_size);
			return;
		}

		memcpy(&p_pkey_tbl_dest[*p_offset], &p_pkey_tbl_src[offset_src],
		       size_pkey_tbl_src);
		p_port_dest[set_count - 1].pkey_tbl_offset = htonll(*p_offset);
		p_port_dest[set_count - 1].pkey_tbl_size = htons(size_pkey_tbl_src);
		p_ref_dataset->set_size = htonll(ntohll(p_ref_dataset->set_size)
						 + size_pkey_tbl_src);
		*p_offset += size_pkey_tbl_src;
	}

	p_dataset->set_count = htonll(set_count);
	p_dataset->set_size = htonll(set_size);
}

/** =========================================================================
 */
static int smdb_port_cmp(cl_map_item_t * p_item_old,
			 void *p_data_tbl_old,
			 void *p_data_ref_tbl_old,
			 cl_map_item_t * p_item_new,
			 void *p_data_tbl_new,
			 void *p_data_ref_tbl_new)
{
	struct ep_map_rec *p_map_rec_old = (struct ep_map_rec *) p_item_old;
	struct ep_map_rec *p_map_rec_new = (struct ep_map_rec *) p_item_new;
	struct smdb_port *p_tbl_rec_old = (struct smdb_port *) p_data_tbl_old;
	struct smdb_port *p_tbl_rec_new = (struct smdb_port *) p_data_tbl_new;
	uint8_t *p_tbl_ref_rec_old = (uint8_t *) p_data_ref_tbl_old;
	uint8_t *p_tbl_ref_rec_new = (uint8_t *) p_data_ref_tbl_new;
	int res = 0;

	p_tbl_rec_old += p_map_rec_old->offset;
	p_tbl_rec_new += p_map_rec_new->offset;
	p_tbl_ref_rec_old += ntohll(p_tbl_rec_old->pkey_tbl_offset);
	p_tbl_ref_rec_new += ntohll(p_tbl_rec_new->pkey_tbl_offset);

	if ((p_tbl_rec_old->pkey_tbl_size != p_tbl_rec_new->pkey_tbl_size) ||
	    (p_tbl_rec_old->port_lid != p_tbl_rec_new->port_lid) ||
	    (p_tbl_rec_old->mtu_cap != p_tbl_rec_new->mtu_cap) ||
	    (p_tbl_rec_old->rate != p_tbl_rec_new->rate) ||
	    (p_tbl_rec_old->vl_enforce != p_tbl_rec_new->vl_enforce))
		res = 1;

	/* comparing pkeys */
	if (res == 0 && p_data_ref_tbl_old && p_data_ref_tbl_new &&
	    memcmp(p_tbl_ref_rec_old, p_tbl_ref_rec_new,
		   ntohs(p_tbl_rec_old->pkey_tbl_size)))
		res = 1;

	return res;
}

/** =========================================================================
 */
static void smdb_link_insert(cl_qmap_t *p_map,
			     struct db_dataset *p_dataset,
			     void **p_data_tbl,
			     uint64_t key,
			     cl_map_item_t * p_item,
			     void *p_data_tbl_src)
{
	struct ep_map_rec *p_map_rec_new, *p_map_rec_old;
	struct smdb_link *p_link_dest, *p_link_src;
	uint64_t set_size, set_count;

	p_link_dest = (struct smdb_link *) *p_data_tbl;
	p_link_src = (struct smdb_link *) p_data_tbl_src;

	if (!p_link_dest) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized link records destination table\n");
		return;
	}

	if (!p_link_src) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "uninitialized link records source table\n");
		return;
	}

	p_map_rec_new = (struct ep_map_rec *) malloc(sizeof(*p_map_rec_new));
	if (!p_map_rec_new) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to allocate offset object\n");
		return;
	}
	set_size = ntohll(p_dataset->set_size);
	set_count = ntohll(p_dataset->set_count);

	p_map_rec_new->offset = set_count;
	cl_qmap_insert(p_map, key, &p_map_rec_new->map_item);

	p_map_rec_old = (struct ep_map_rec *) p_item;
	memcpy(&p_link_dest[set_count], &p_link_src[p_map_rec_old->offset],
	       sizeof(*p_link_dest));
	*p_data_tbl = p_link_dest;
	set_size += sizeof(*p_link_dest);
	set_count++;

	p_dataset->set_count = htonll(set_count);
	p_dataset->set_size = htonll(set_size);
}

/** =========================================================================
 */
static int smdb_link_cmp(cl_map_item_t * p_item_old,
			 void *p_data_tbl_old,
			 cl_map_item_t * p_item_new,
			 void *p_data_tbl_new)
{
	struct ep_map_rec *p_map_rec_old = (struct ep_map_rec *) p_item_old;
	struct ep_map_rec *p_map_rec_new = (struct ep_map_rec *) p_item_new;
	struct smdb_link *p_tbl_rec_old = (struct smdb_link *) p_data_tbl_old;
	struct smdb_link *p_tbl_rec_new = (struct smdb_link *) p_data_tbl_new;
	int res = 0;

	p_tbl_rec_old += p_map_rec_old->offset;
	p_tbl_rec_new += p_map_rec_new->offset;

	if ((p_tbl_rec_old->from_lid != p_tbl_rec_new->from_lid) ||
	    (p_tbl_rec_old->to_lid != p_tbl_rec_new->to_lid) ||
	    (p_tbl_rec_old->from_port_num != p_tbl_rec_new->from_port_num) ||
	    (p_tbl_rec_old->to_port_num != p_tbl_rec_new->to_port_num))
		res = 1;

	return res;
}

 /** =========================================================================
  */
static uint8_t ssa_db_diff_table_cmp(cl_qmap_t * p_map_old,
				     cl_qmap_t * p_map_new,
				     void *p_data_tbl_old,
				     void *p_data_tbl_new,
				     void (*qmap_insert_pfn)
				            (cl_qmap_t *,
					     struct db_dataset *,
					     void **, uint64_t,
					     cl_map_item_t *,
					     void *),
				     int (*cmp_pfn)
					(cl_map_item_t *, void *,
					 cl_map_item_t *, void *),
				     cl_qmap_t * p_map_added,
				     cl_qmap_t * p_map_removed,
				     struct db_dataset *p_dataset,
				     void **p_data_tbl)
{
	cl_map_item_t *p_item_old, *p_item_new;
	uint64_t key_old, key_new;
	uint8_t dirty = 0;

	if (!smdb_deltas) {
		for (p_item_new = cl_qmap_head(p_map_new);
		     p_item_new != cl_qmap_end(p_map_new);
		     p_item_new = cl_qmap_next(p_item_new)) {
			key_new = cl_qmap_key(p_item_new);
			qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl,
					key_new, p_item_new, p_data_tbl_new);
		}
	}

	p_item_old = cl_qmap_head(p_map_old);
	p_item_new = cl_qmap_head(p_map_new);
	while (p_item_old != cl_qmap_end(p_map_old) &&
	       p_item_new != cl_qmap_end(p_map_new)) {
		key_old = cl_qmap_key(p_item_old);
		key_new = cl_qmap_key(p_item_new);
		if (key_old < key_new) {
			if (smdb_deltas)
				qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl,
						key_old, p_item_old, p_data_tbl_old);
			p_item_old = cl_qmap_next(p_item_old);
			dirty = 1;
		} else if (key_old > key_new) {
			if (smdb_deltas)
				qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl,
						key_new, p_item_new, p_data_tbl_new);
			p_item_new = cl_qmap_next(p_item_new);
			dirty = 1;
		} else {
			if (cmp_pfn(p_item_old, p_data_tbl_old, p_item_new, p_data_tbl_new)) {
				if (smdb_deltas) {
					qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl,
							key_old, p_item_old, p_data_tbl_old);
					qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl,
							key_new, p_item_new, p_data_tbl_new);
				}
				dirty = 1;
			}
			p_item_old = cl_qmap_next(p_item_old);
			p_item_new = cl_qmap_next(p_item_new);
		}
	}

	while (p_item_new != cl_qmap_end(p_map_new)) {
		key_new = cl_qmap_key(p_item_new);
		if (smdb_deltas)
			qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl,
					key_new, p_item_new, p_data_tbl_new);
		p_item_new = cl_qmap_next(p_item_new);
		dirty = 1;
	}

	while (p_item_old != cl_qmap_end(p_map_old)) {
		key_old = cl_qmap_key(p_item_old);
		if (smdb_deltas)
			qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl,
					key_old, p_item_old, p_data_tbl_old);
		p_item_old = cl_qmap_next(p_item_old);
		dirty = 1;
	}

	return dirty;
}

/** =========================================================================
 */
static uint8_t ssa_db_diff_var_size_table_cmp(cl_qmap_t * p_map_old,
					      cl_qmap_t * p_map_new,
					      void *p_data_tbl_old,
					      void *p_data_ref_tbl_old,
					      void *p_data_tbl_new,
					      void *p_data_ref_tbl_new,
					      void (*qmap_insert_pfn)
						       (cl_qmap_t *, struct db_dataset *,
							void **, struct db_dataset *,
							void **, uint64_t *, uint64_t,
							cl_map_item_t *,
							void *, void *),
					      int (*cmp_pfn)
							(cl_map_item_t *, void *,
							 void *, cl_map_item_t *,
							 void *, void *),
					      cl_qmap_t * p_map_added,
					      cl_qmap_t * p_map_removed,
					      struct db_dataset *p_dataset,
					      void **p_data_tbl,
					      struct db_dataset *p_ref_dataset,
					      void **p_data_ref_tbl)
{
	cl_map_item_t *p_item_old, *p_item_new;
	uint64_t key_old, key_new;
	uint64_t ref_tbl_offset = 0;
	uint8_t dirty = 0;

	if (!smdb_deltas) {
		for (p_item_new = cl_qmap_head(p_map_new);
		     p_item_new != cl_qmap_end(p_map_new);
		     p_item_new = cl_qmap_next(p_item_new)) {
			key_new = cl_qmap_key(p_item_new);
			qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl, p_ref_dataset,
					p_data_ref_tbl, &ref_tbl_offset, key_new,
					p_item_new, p_data_tbl_new, p_data_ref_tbl_new);
		}
	}

	p_item_old = cl_qmap_head(p_map_old);
	p_item_new = cl_qmap_head(p_map_new);
	while (p_item_old != cl_qmap_end(p_map_old) && p_item_new != cl_qmap_end(p_map_new)) {
		key_old = cl_qmap_key(p_item_old);
		key_new = cl_qmap_key(p_item_new);
		if (key_old < key_new) {
			if (smdb_deltas)
				qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl, NULL,
						NULL, NULL, key_old, p_item_old,
						p_data_tbl_old, NULL);
			p_item_old = cl_qmap_next(p_item_old);
			dirty = 1;
		} else if (key_old > key_new) {
			if (smdb_deltas)
				qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl, p_ref_dataset,
						p_data_ref_tbl, &ref_tbl_offset, key_new,
						p_item_new, p_data_tbl_new, p_data_ref_tbl_new);
			p_item_new = cl_qmap_next(p_item_new);
			dirty = 1;
		} else {
			if (cmp_pfn(p_item_old, p_data_tbl_old, p_data_ref_tbl_old,
				    p_item_new, p_data_tbl_new, p_data_ref_tbl_new)) {
				if (smdb_deltas) {
					qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl, NULL,
							NULL, NULL, key_old, p_item_old,
							p_data_tbl_old, NULL);
					qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl, p_ref_dataset,
							p_data_ref_tbl, &ref_tbl_offset, key_new,
							p_item_new, p_data_tbl_new, p_data_ref_tbl_new);
				}
				dirty = 1;
			}
			p_item_old = cl_qmap_next(p_item_old);
			p_item_new = cl_qmap_next(p_item_new);
		}
	}

	while (p_item_new != cl_qmap_end(p_map_new)) {
		key_new = cl_qmap_key(p_item_new);
		if (smdb_deltas)
			qmap_insert_pfn(p_map_added, p_dataset, p_data_tbl, p_ref_dataset,
					p_data_ref_tbl, &ref_tbl_offset, key_new,
					p_item_new, p_data_tbl_new, p_data_ref_tbl_new);
		p_item_new = cl_qmap_next(p_item_new);
		dirty = 1;
	}

	while (p_item_old != cl_qmap_end(p_map_old)) {
		key_old = cl_qmap_key(p_item_old);
		if (smdb_deltas)
			qmap_insert_pfn(p_map_removed, p_dataset, p_data_tbl, NULL,
					NULL, NULL, key_old, p_item_old,
					p_data_tbl_old, NULL);
		p_item_old = cl_qmap_next(p_item_old);
		dirty = 1;
	}

	return dirty;
}

/** =========================================================================
 */
static void ssa_db_diff_compare_subnet_tables(struct ssa_db_extract * p_previous_db,
					      struct ssa_db_extract * p_current_db,
					      struct ssa_db_diff * const p_ssa_db_diff,
					      boolean_t *tbl_changed)
{
	uint8_t dirty = 0;

	/*
	 * Comparing guid2lid / node / port / link records
	 *
	 * For each record in previous SMDB version:
	 *
	 * 1. If the record is not present in current SMDB it will
	 *    be inserted to "removed" records.
	 *
	 * 2. If the record is present in current SMDB and not in
	 *    previous one than it will be added to "added" records.
	 *
	 * 3. If the record presents in both SMDB versions a
	 *    comparison between the versions will be done. In case
	 *    of at least 1 different value for the same field
	 *    the old record will be added to the "removed" records
	 *    and the new one will be added to "added" ones.
	 *
	 *    (when SMDB is updated using the ssa_db_diff
	 *    structure the "removed" records map has to applied first
	 *    and only afterwards the "added" records may be added,
	 *    for LFT records there is only single map for changed
	 *    blocks that need to be set)
	 */

	/*
	 * Comparing guid2lid records
	 */
	dirty |= ssa_db_diff_table_cmp(&p_previous_db->ep_guid_to_lid_tbl,
				       &p_current_db->ep_guid_to_lid_tbl,
				       p_previous_db->p_guid_to_lid_tbl,
				       p_current_db->p_guid_to_lid_tbl,
				       smdb_guid2lid_insert,
				       smdb_guid2lid_cmp,
				       &p_ssa_db_diff->ep_guid_to_lid_tbl_added,
				       &p_ssa_db_diff->ep_guid_to_lid_tbl_removed,
				       &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_GUID2LID],
				       (void **) &p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_GUID2LID]);

	if (dirty & 1)
		tbl_changed[SMDB_TBL_ID_GUID2LID] = TRUE;

	dirty = dirty << 1;
	/*
	 * Comparing ep_node_rec records
	 */
	dirty |= ssa_db_diff_table_cmp(&p_previous_db->ep_node_tbl,
				       &p_current_db->ep_node_tbl,
				       p_previous_db->p_node_tbl,
				       p_current_db->p_node_tbl,
				       smdb_node_insert,
				       smdb_node_cmp,
				       &p_ssa_db_diff->ep_node_tbl_added,
				       &p_ssa_db_diff->ep_node_tbl_removed,
				       &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_NODE],
				       (void **) &p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_NODE]);

	if (dirty & 1)
		tbl_changed[SMDB_TBL_ID_NODE] = TRUE;

	dirty = dirty << 1;
	/*
	 * Comparing ep_link_rec records
	 */
	dirty |= ssa_db_diff_table_cmp(&p_previous_db->ep_link_tbl,
				       &p_current_db->ep_link_tbl,
				       p_previous_db->p_link_tbl,
				       p_current_db->p_link_tbl,
				       smdb_link_insert,
				       smdb_link_cmp,
				       &p_ssa_db_diff->ep_link_tbl_added,
				       &p_ssa_db_diff->ep_link_tbl_removed,
				       &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_LINK],
				       (void **) &p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_LINK]);

	if (dirty & 1)
		tbl_changed[SMDB_TBL_ID_LINK] = TRUE;

	dirty = dirty << 1;
	/*
	 * Comparing ep_port_rec records
	 */
	dirty |= ssa_db_diff_var_size_table_cmp(&p_previous_db->ep_port_tbl,
						&p_current_db->ep_port_tbl,
						p_previous_db->p_port_tbl,
						p_previous_db->p_pkey_tbl,
						p_current_db->p_port_tbl,
						p_current_db->p_pkey_tbl,
						smdb_port_insert,
						smdb_port_cmp,
						&p_ssa_db_diff->ep_port_tbl_added,
						&p_ssa_db_diff->ep_port_tbl_removed,
						&p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_PORT],
						(void **) &p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_PORT],
						&p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_PKEY],
						(void **) &p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_PKEY]);

	if (dirty & 1) {
		tbl_changed[SMDB_TBL_ID_PORT] = TRUE;
		tbl_changed[SMDB_TBL_ID_PKEY] = TRUE;
	}

	if (dirty)
		p_ssa_db_diff->dirty = 1;
}

/** =========================================================================
 */
#ifdef SSA_PLUGIN_VERBOSE_LOGGING
static void ssa_db_diff_dump_fabric_params(struct ssa_db_diff * p_ssa_db_diff)
{
	struct ssa_db *p_smdb = ref_count_object_get(p_ssa_db_diff->p_smdb);
	struct smdb_subnet_opts *p_subnet_opts;
	uint8_t is_changed = 0;

	ssa_log(SSA_LOG_VERBOSE, "Fabric parameters:\n");

	p_subnet_opts = p_smdb->pp_tables[SMDB_TBL_ID_SUBNET_OPTS];
	if (p_subnet_opts->change_mask & SSA_DB_CHANGEMASK_SUBNET_PREFIX) {
		ssa_log(SSA_LOG_VERBOSE, "Subnet Prefix: 0x%" PRIx64 "\n",
			ntohll(p_subnet_opts->subnet_prefix));
		is_changed = 1;
	}
	if (p_subnet_opts->change_mask & SSA_DB_CHANGEMASK_SM_STATE) {
		ssa_log(SSA_LOG_VERBOSE, "SM state: %d\n",
			p_subnet_opts->sm_state);
		is_changed = 1;
	}
	if (p_subnet_opts->change_mask & SSA_DB_CHANGEMASK_LMC) {
		ssa_log(SSA_LOG_VERBOSE, "LMC: %u\n",
			p_subnet_opts->lmc);
		is_changed = 1;
	}
	if (p_subnet_opts->change_mask & SSA_DB_CHANGEMASK_SUBNET_TIMEOUT) {
		ssa_log(SSA_LOG_VERBOSE, "Subnet timeout: %u\n",
			p_subnet_opts->subnet_timeout);
		is_changed = 1;
	}
	if (p_subnet_opts->change_mask & SSA_DB_CHANGEMASK_ALLOW_BOTH_PKEYS) {
		ssa_log(SSA_LOG_VERBOSE, "Both pkeys %sabled\n",
			p_subnet_opts->allow_both_pkeys ? "en" : "dis");
		is_changed = 1;
	}

	if (!is_changed)
		ssa_log(SSA_LOG_VERBOSE, "No changes\n");
}

/** =========================================================================
 */
static void ssa_db_diff_dump_field(void * p_tbl, uint16_t max_rec)
{
	struct db_field_def *p_field_tbl = (struct db_field_def *) p_tbl;
	struct db_field_def *p_field_rec;
	uint8_t i;

	for (i = 0; i < max_rec; i++) {
		p_field_rec = &p_field_tbl[i];
		ssa_log(SSA_LOG_VERBOSE, "Field %s size %u offset %u\n",
			p_field_rec->name,
			ntohl(p_field_rec->field_size),
			ntohl(p_field_rec->field_offset));
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_node(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_node *p_node_tbl, *p_node;
	char buffer[64];

	assert(p_map_rec);

	if (p_tbl) {
		p_node_tbl = (struct smdb_node *) p_tbl;
		p_node = &p_node_tbl[p_map_rec->offset];
		if (p_node->node_type == IB_NODE_TYPE_SWITCH)
			sprintf(buffer, " with %s Switch Port 0\n",
				p_node->is_enhanced_sp0 ? "Enhanced" : "Base");
		else
			sprintf(buffer, "\n");
		ssa_log(SSA_LOG_VERBOSE, "Node GUID 0x%" PRIx64 " Type %d%s",
			ntohll(p_node->node_guid), p_node->node_type, buffer);
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_guid2lid(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_guid2lid *p_guid2lid_tbl, *p_guid2lid_tbl;

	assert(p_map_rec);

	if (p_tbl) {
		p_guid2lid_tbl = (struct smdb_guid2lid *) p_tbl;
		p_guid2lid_tbl_rec = &p_guid2lid_tbl[p_map_rec->offset];
		ssa_log(SSA_LOG_VERBOSE, "Port GUID 0x%" PRIx64 " LID %u LMC %u is_switch %d\n",
			ntohll(p_guid2lid->guid), ntohs(p_guid2lid->lid),
			p_guid2lid->lmc, p_guid2lid->is_switch);
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_port(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_port *p_port_tbl, *p_port;

	if (!p_map_rec)
		return;

	if (p_tbl) {
		p_port_tbl = (struct smdb_port *) p_tbl;
		p_port = &p_port_tbl[p_map_rec->offset];
		ssa_log(SSA_LOG_VERBOSE, "Port LID %u Port Num %u\n",
			ntohs(p_port->port_lid), p_port->port_num);
		ssa_log(SSA_LOG_VERBOSE, "MTUCapability %u rate %u\n",
			p_port->mtu_cap, p_port->rate & SSA_DB_PORT_RATE_MASK);
		ssa_log(SSA_LOG_VERBOSE, "FDR10 %s active\n",
			(p_port->rate & SSA_DB_PORT_IS_FDR10_ACTIVE_MASK) ? "" : "not");
		ssa_log(SSA_LOG_VERBOSE, "PKeys %u\n",
			ntohs(p_port->pkey_tbl_size) / sizeof(uint16_t));
		ssa_log(SSA_LOG_VERBOSE, "PKey Table offset %u \n",
			ntohll(p_port->pkey_tbl_offset));
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_lft_top(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_lft_top *p_lft_top_tbl, *p_lft_top;

	assert(p_map_rec);

	if (p_tbl) {
		p_lft_top_tbl = (struct smdb_lft_top *) p_tbl;
		p_lft_top = &p_lft_top_tbl[p_map_rec->offset];
		ssa_log(SSA_LOG_VERBOSE, "LID %u new LFT top %u\n",
			ntohs(p_lft_top->lid), ntohs(p_lft_top->lft_top));
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_lft_block(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_lft_block *p_lft_block_tbl, *p_lft_block;

	assert(p_map_rec);

	if (p_tbl) {
		p_lft_block_tbl = (struct smdb_lft_block *) p_tbl;
		p_lft_block = &p_lft_block_tbl[p_map_rec->offset];
		ssa_log(SSA_LOG_VERBOSE, "LID %u block #%u\n",
			ntohs(p_lft_block->lid),
			ntohs(p_lft_block->block_num));
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_link(cl_map_item_t * p_item, void * p_tbl)
{
	struct ep_map_rec *p_map_rec = (struct ep_map_rec *) p_item;
	struct smdb_link *p_link_tbl, *p_link;

	if (!p_map_rec)
		return;

	if (p_tbl) {
		p_link_tbl = (struct smdb_link *) p_tbl;
		p_link = &p_link_tbl[p_map_rec->offset];
		ssa_log(SSA_LOG_VERBOSE, "From LID %u port %u to LID %u port %u\n",
			ntohs(p_link->from_lid), p_link->from_port_num,
			ntohs(p_link->to_lid), p_link->to_port_num);
	}
}

/** =========================================================================
 */
static void ssa_db_diff_dump_qmap(cl_qmap_t * p_qmap,
				  void (*pfn_dump)(cl_map_item_t *, void *),
				  void * p_tbl)
{
	cl_map_item_t *p_map_item, *p_map_item_next;
	uint8_t is_changed = 0;

        p_map_item_next = cl_qmap_head(p_qmap);
        while (p_map_item_next != cl_qmap_end(p_qmap)) {
                p_map_item = p_map_item_next;
                p_map_item_next = cl_qmap_next(p_map_item);
                pfn_dump(p_map_item, p_tbl);
		is_changed = 1;
	}

	if (!is_changed)
		ssa_log(SSA_LOG_VERBOSE, "No changes\n");
}

/** =========================================================================
 */
static void ssa_db_diff_dump(struct ssa_db_diff * p_ssa_db_diff)
{
	struct ssa_db *p_smdb;
	int ssa_log_level = SSA_LOG_VERBOSE;

	if (!p_ssa_db_diff)
		return;

	p_smdb = ref_count_object_get(p_ssa_db_diff->p_smdb);
	if (!p_smdb)
		return;

	ssa_log(ssa_log_level, "Dumping SMDB changes\n");
	ssa_log(ssa_log_level, "===================================\n");
	ssa_db_diff_dump_fabric_params(p_ssa_db_diff);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "NODE records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "NODE field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_NODE],
			       SMDB_FIELD_ID_NODE_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "Added records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_node_tbl_added,
			      ssa_db_diff_dump_node,
			      p_smdb->pp_tables[SMDB_TBL_ID_NODE]);
	ssa_log(ssa_log_level, "Removed records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_node_tbl_removed,
			      ssa_db_diff_dump_node,
			      p_smdb->pp_tables[SMDB_TBL_ID_NODE]);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "GUID to LID records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "GUID to LID field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_GUID2LID],
			       SMDB_FIELD_ID_GUID_TO_LID_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "Added records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_guid_to_lid_tbl_added,
			      ssa_db_diff_dump_guid2lid,
			      p_smdb->pp_tables[SMDB_TBL_ID_GUID2LID]);
	ssa_log(ssa_log_level, "Removed records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_guid_to_lid_tbl_removed,
			      ssa_db_diff_dump_guid2lid,
			      p_smdb->pp_tables[SMDB_TBL_ID_GUID_TO_LID]);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "PORT records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "PORT field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_PORT],
			       SMDB_FIELD_ID_PORT_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "Added records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_port_tbl_added,
			      ssa_db_diff_dump_port,
			      p_smdb->pp_tables[SMDB_TBL_ID_PORT]);
	ssa_log(ssa_log_level, "Removed records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_port_tbl_removed,
			      ssa_db_diff_dump_port,
			      p_smdb->pp_tables[SMDB_TBL_ID_PORT]);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "LFT block records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "LFT block field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_LFT_BLOCK],
			       SMDB_FIELD_ID_LFT_BLOCK_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_lft_block_tbl,
			      ssa_db_diff_dump_lft_block,
			      p_smdb->pp_tables[SMDB_TBL_ID_LFT_BLOCK]);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "LFT top records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "LFT top field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_LFT_TOP],
			       SMDB_FIELD_ID_LFT_TOP_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_lft_top_tbl,
			      ssa_db_diff_dump_lft_top,
			      p_smdb->pp_tables[SMDB_TBL_ID_LFT_TOP]);

	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "Link Records:\n");
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "LINK field definitions:\n");
	ssa_db_diff_dump_field(p_smdb->pp_field_tables[SMDB_TBL_ID_LINK],
			       SMDB_FIELD_ID_LINK_MAX);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "Added records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_link_tbl_added,
			      ssa_db_diff_dump_link,
			      p_smdb->pp_tables[SMDB_TBL_ID_LINK]);
	ssa_log(ssa_log_level, "Removed records:\n");
	ssa_db_diff_dump_qmap(&p_ssa_db_diff->ep_link_tbl_removed,
			      ssa_db_diff_dump_link,
			      p_smdb->pp_tables[SMDB_TBL_ID_LINK]);
	ssa_log(ssa_log_level, "-----------------------------------\n");
	ssa_log(ssa_log_level, "===================================\n");
}
#endif

/** =========================================================================
 */
static void ep_lft_block_qmap_copy(cl_qmap_t *p_dest_qmap,
				   struct db_dataset *p_dest_dataset,
				   struct smdb_lft_block *p_dest_tbl,
				   cl_qmap_t *p_src_qmap,
				   struct smdb_lft_block *p_src_tbl)
{
	struct ep_map_rec *p_map_rec, *p_map_rec_next;
	struct ep_map_rec *p_map_rec_new, *p_map_rec_tmp;
	struct smdb_lft_block *p_lft_block;
	uint64_t offset;

	p_map_rec_next = (struct ep_map_rec *) cl_qmap_head(p_src_qmap);
	while (p_map_rec_next !=
	       (struct ep_map_rec *) cl_qmap_end(p_src_qmap)) {
		p_map_rec = p_map_rec_next;
		p_map_rec_next = (struct ep_map_rec *)
				   cl_qmap_next(&p_map_rec->map_item);
		p_lft_block = &p_src_tbl[p_map_rec->offset];

		p_map_rec_tmp = (struct ep_map_rec *)
			cl_qmap_get(p_dest_qmap, cl_qmap_key(&p_map_rec->map_item));

		if (p_map_rec_tmp != (struct ep_map_rec *) cl_qmap_end(p_dest_qmap)) {
			/* in case of existing record */
			memcpy(&p_dest_tbl[p_map_rec_tmp->offset],
			       p_lft_block, sizeof(*p_lft_block));
		} else {
			/* in case of new record added */
			if (p_dest_dataset) {
				offset = ntohll(p_dest_dataset->set_count);
				p_dest_dataset->set_size =
					htonll(ntohll(p_dest_dataset->set_size)
					       + sizeof(*p_lft_block));
				p_dest_dataset->set_count =
					htonll(ntohll(p_dest_dataset->set_count) + 1);
			} else {
				offset = cl_qmap_count(p_dest_qmap);
			}

			p_map_rec_new = ep_map_rec_init(offset);
			cl_qmap_insert(p_dest_qmap, cl_qmap_key(&p_map_rec->map_item),
				       &p_map_rec_new->map_item);

			memcpy(&p_dest_tbl[offset], p_lft_block,
			       sizeof(*p_lft_block));
		}
	}
}

/** =========================================================================
 */
static void ep_lft_top_qmap_copy(cl_qmap_t *p_dest_qmap,
				 struct db_dataset *p_dest_dataset,
				 struct smdb_lft_top *p_dest_tbl,
				 cl_qmap_t *p_src_qmap,
				 struct smdb_lft_top *p_src_tbl)
{
	struct ep_map_rec *p_map_rec, *p_map_rec_next;
	struct ep_map_rec *p_map_rec_new, *p_map_rec_tmp;
	struct smdb_lft_top *p_lft_top;
	uint64_t offset;

	p_map_rec_next = (struct ep_map_rec *) cl_qmap_head(p_src_qmap);
	while (p_map_rec_next !=
	       (struct ep_map_rec *) cl_qmap_end(p_src_qmap)) {
		p_map_rec = p_map_rec_next;
		p_map_rec_next = (struct ep_map_rec *)
				   cl_qmap_next(&p_map_rec->map_item);
		p_lft_top = &p_src_tbl[p_map_rec->offset];

		p_map_rec_tmp = (struct ep_map_rec *)
			cl_qmap_get(p_dest_qmap, cl_qmap_key(&p_map_rec->map_item));

		if (p_map_rec_tmp != (struct ep_map_rec *) cl_qmap_end(p_dest_qmap)) {
			/* in case of existing record */
			memcpy(&p_dest_tbl[p_map_rec_tmp->offset],
			       p_lft_top, sizeof(*p_lft_top));
		} else {
			/* in case of new record added */
			if (p_dest_dataset) {
				offset = ntohll(p_dest_dataset->set_count);
				p_dest_dataset->set_size =
					htonll(ntohll(p_dest_dataset->set_size)
					       + sizeof(*p_lft_top));
				p_dest_dataset->set_count =
					htonll(ntohll(p_dest_dataset->set_count) + 1);
			} else {
				offset = cl_qmap_count(p_dest_qmap);
			}

			p_map_rec_new = ep_map_rec_init(offset);
			cl_qmap_insert(p_dest_qmap, cl_qmap_key(&p_map_rec->map_item),
				       &p_map_rec_new->map_item);

			memcpy(&p_dest_tbl[offset], p_lft_top,
			       sizeof(*p_lft_top));
		}
	}
}

/** =========================================================================
 */
static uint64_t ssa_db_diff_new_qmap_recs(cl_qmap_t * p_map_old,
					  cl_qmap_t * p_map_new)
{
	cl_map_item_t *p_item_old, *p_item_new;
	uint64_t key_old, key_new;
	uint64_t new_recs = 0;

	p_item_old = cl_qmap_head(p_map_old);
	p_item_new = cl_qmap_head(p_map_new);
	while (p_item_old != cl_qmap_end(p_map_old) &&
	       p_item_new != cl_qmap_end(p_map_new)) {
		key_old = cl_qmap_key(p_item_old);
		key_new = cl_qmap_key(p_item_new);
		if (key_old < key_new) {
			p_item_old = cl_qmap_next(p_item_old);
		} else if (key_old > key_new) {
			new_recs++;
			p_item_new = cl_qmap_next(p_item_new);
		} else {
			p_item_old = cl_qmap_next(p_item_old);
			p_item_new = cl_qmap_next(p_item_new);
		}
	}

	while (p_item_new != cl_qmap_end(p_map_new)) {
		new_recs++;
		p_item_new = cl_qmap_next(p_item_new);
	}

	return new_recs;
}

/** =========================================================================
 */
static void
ssa_db_diff_update_epoch(struct ssa_db_diff *p_ssa_db_diff,
			 boolean_t *tbl_changed)
{
	struct ssa_db *p_smdb;
	char *tbl_name = NULL;
	uint64_t epoch_old, epoch_new, epoch;
	uint64_t i, k, tbl_cnt;
	boolean_t update_global_epoch = FALSE;

	ssa_log(SSA_LOG_VERBOSE, "[\n");

	assert(p_ssa_db_diff);
	assert(p_ssa_db_diff->p_smdb);

	p_smdb = p_ssa_db_diff->p_smdb;
	tbl_cnt = p_smdb->data_tbl_cnt;
	epoch_old = ssa_db_get_epoch(p_smdb, DB_DEF_TBL_ID);
	epoch_new = epoch_old + 1;
	if (epoch_new == DB_EPOCH_INVALID)
		epoch_new++;
	for (i = 0; i < tbl_cnt; i++) {
		if (smdb_deltas && p_smdb->p_db_tables[i].set_size == 0)
			continue;

		if (!smdb_deltas && tbl_changed[i] == FALSE)
			continue;

		epoch = ssa_db_set_epoch(p_smdb, i, epoch_new);
		if (epoch != DB_EPOCH_INVALID)
			update_global_epoch = TRUE;

		for (k = 0; k < p_smdb->db_table_def.set_count; k++) {
			if (p_smdb->p_def_tbl[k].id.table == i) {
				tbl_name = p_smdb->p_def_tbl[k].name;
				break;
			}
		}

		ssa_log(SSA_LOG_VERBOSE,
			"%s table epoch was updated to: 0x%" PRIx64 "\n",
			tbl_name, epoch_new);
	}

	if (update_global_epoch) {
		epoch = ssa_db_increment_epoch(p_smdb, DB_DEF_TBL_ID);
		ssa_log(SSA_LOG_VERBOSE,
			"%s epoch was updated: 0x%" PRIx64 " --> "
			"0x%" PRIx64 "\n", p_smdb->db_def.name,
			epoch_old, epoch);
	}

	ssa_log(SSA_LOG_VERBOSE, "]\n");
}

/** =========================================================================
 */
static void
ssa_db_diff_update_lfts(struct ssa_database *ssa_db, struct ssa_db_diff *p_ssa_db_diff,
			boolean_t tbl_changed[], int smdb_deltas, int first)
{
	uint64_t new_recs;

	if (first) {
		tbl_changed[SMDB_TBL_ID_LFT_BLOCK] = TRUE;
		tbl_changed[SMDB_TBL_ID_LFT_TOP] = TRUE;
	}

	if (!smdb_deltas || first) {
		ep_lft_block_qmap_copy(&p_ssa_db_diff->ep_lft_block_tbl,
				       &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_LFT_BLOCK],
				       p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_LFT_BLOCK],
				       &ssa_db->p_lft_db->ep_db_lft_block_tbl,
				       ssa_db->p_lft_db->p_db_lft_block_tbl);
		ep_lft_top_qmap_copy(&p_ssa_db_diff->ep_lft_top_tbl,
				     &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_LFT_TOP],
				     p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_LFT_TOP],
				     &ssa_db->p_lft_db->ep_db_lft_top_tbl,
				     ssa_db->p_lft_db->p_db_lft_top_tbl);
	}

	if (!first) {
		ep_lft_block_qmap_copy(&p_ssa_db_diff->ep_lft_block_tbl,
				       &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_LFT_BLOCK],
				       p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_LFT_BLOCK],
				       &ssa_db->p_lft_db->ep_dump_lft_block_tbl,
				       ssa_db->p_lft_db->p_dump_lft_block_tbl);
		ep_lft_top_qmap_copy(&p_ssa_db_diff->ep_lft_top_tbl,
				     &p_ssa_db_diff->p_smdb->p_db_tables[SMDB_TBL_ID_LFT_TOP],
				     p_ssa_db_diff->p_smdb->pp_tables[SMDB_TBL_ID_LFT_TOP],
				     &ssa_db->p_lft_db->ep_dump_lft_top_tbl,
				     ssa_db->p_lft_db->p_dump_lft_top_tbl);

		if (cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_top_tbl))
			tbl_changed[SMDB_TBL_ID_LFT_TOP] = TRUE;

		if (cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_block_tbl))
			tbl_changed[SMDB_TBL_ID_LFT_BLOCK] = TRUE;

		new_recs = ssa_db_diff_new_qmap_recs(&ssa_db->p_lft_db->ep_db_lft_top_tbl,
						     &ssa_db->p_lft_db->ep_dump_lft_top_tbl);
		if (new_recs > 0) {
			ssa_db->p_lft_db->p_db_lft_top_tbl = (struct smdb_lft_top *)
					realloc(&ssa_db->p_lft_db->p_db_lft_top_tbl[0],
						(cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_top_tbl) + new_recs) *
						 sizeof(*ssa_db->p_lft_db->p_db_lft_top_tbl));
		}

		new_recs = ssa_db_diff_new_qmap_recs(&ssa_db->p_lft_db->ep_db_lft_block_tbl,
						     &ssa_db->p_lft_db->ep_dump_lft_block_tbl);
		if (new_recs > 0) {
			ssa_db->p_lft_db->p_db_lft_block_tbl = (struct smdb_lft_block *)
					realloc(&ssa_db->p_lft_db->p_db_lft_block_tbl[0],
						(cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_block_tbl) + new_recs) *
						 sizeof(*ssa_db->p_lft_db->p_db_lft_block_tbl));
		}

		/* Apply LFT block / top changes on existing LFT database */
		ep_lft_block_qmap_copy(&ssa_db->p_lft_db->ep_db_lft_block_tbl, NULL,
				       ssa_db->p_lft_db->p_db_lft_block_tbl,
				       &ssa_db->p_lft_db->ep_dump_lft_block_tbl,
				       ssa_db->p_lft_db->p_dump_lft_block_tbl);
		ep_lft_top_qmap_copy(&ssa_db->p_lft_db->ep_db_lft_top_tbl, NULL,
				     ssa_db->p_lft_db->p_db_lft_top_tbl,
				     &ssa_db->p_lft_db->ep_dump_lft_top_tbl,
				     ssa_db->p_lft_db->p_dump_lft_top_tbl);
		/* Clear LFT dump data */
		ep_qmap_clear(&ssa_db->p_lft_db->ep_dump_lft_block_tbl);
		ep_qmap_clear(&ssa_db->p_lft_db->ep_dump_lft_top_tbl);
	}

	if (tbl_changed[SMDB_TBL_ID_LFT_BLOCK] == TRUE ||
	    tbl_changed[SMDB_TBL_ID_LFT_TOP] == TRUE)
		p_ssa_db_diff->dirty = 1;
}

static void ipdb_add_addrs(struct ssa_db *ipdb, struct host_addr *addrs,
			   boolean_t tbl_changed[], uint64_t cnt)
{
	struct db_dataset *dataset = NULL;
	struct ipdb_ipv4 *ipv4;
	struct ipdb_ipv6 *ipv6;
	struct ipdb_name *name;
	void *rec = NULL;
	uint64_t i, set_size, set_count;
	int tbl_id, tbl_id_lookup[] =
		{ [SSA_ADDR_IP]   = IPDB_TBL_ID_IPv4,
		  [SSA_ADDR_IP6]  = IPDB_TBL_ID_IPv6,
		  [SSA_ADDR_NAME] = IPDB_TBL_ID_NAME };
	size_t rec_size, size_lookup[] =
		{ [SSA_ADDR_IP]   = sizeof(*ipv4),
		  [SSA_ADDR_IP6]  = sizeof(*ipv6),
		  [SSA_ADDR_NAME] = sizeof(*name) };

	for (i = 0; i < cnt; i++) {
		tbl_id = tbl_id_lookup[addrs->addr_type];
		rec_size = size_lookup[addrs->addr_type];

		dataset = &ipdb->p_db_tables[tbl_id];
		set_count = ntohll(dataset->set_count);
		set_size = ntohll(dataset->set_size);

		rec = ipdb->pp_tables[tbl_id] + set_size;
		memset(rec, 0, rec_size);

		switch (addrs->addr_type) {
		case SSA_ADDR_IP:
			ipv4 = (struct ipdb_ipv4 *) rec;
			ipv4->qpn = htonl(addrs->qpn);
			ipv4->pkey = htons(addrs->pkey);
			ipv4->flags = addrs->flags;
			memcpy(ipv4->gid, &addrs->gid, sizeof(ipv4->gid));
			memcpy(ipv4->addr, addrs->addr, sizeof(ipv4->addr));
			tbl_changed[SMDB_TBL_ID_IPv4] = TRUE;
			break;
		case SSA_ADDR_IP6:
			ipv6 = (struct ipdb_ipv6 *) rec;
			ipv6->qpn = htonl(addrs->qpn);
			ipv6->pkey = htons(addrs->pkey);
			ipv6->flags = addrs->flags;
			memcpy(ipv6->gid, &addrs->gid, sizeof(ipv6->gid));
			memcpy(ipv6->addr, addrs->addr, sizeof(ipv6->addr));
			tbl_changed[SMDB_TBL_ID_IPv6] = TRUE;
			break;
		case SSA_ADDR_NAME:
			name = (struct ipdb_name *) rec;
			name->qpn = htonl(addrs->qpn);
			name->pkey = htons(addrs->pkey);
			name->flags = addrs->flags;
			memcpy(name->gid, &addrs->gid, sizeof(name->gid));
			strncpy((char *) name->addr, (char *) addrs->addr,
				sizeof(name->addr));
			tbl_changed[SMDB_TBL_ID_NAME] = TRUE;
			break;
		default:
			ssa_log_err(SSA_LOG_DEFAULT,
				    "unexpected address type %d\n",
				    addrs->addr_type);
			return;
		};

		dataset->set_count = htonll(set_count + 1);
		dataset->set_size = htonll(set_size + rec_size);

		addrs++;
	}
}

static void
update_addr_tables(struct ssa_db_diff *p_ssa_db_diff, boolean_t tbl_changed[])
{
	struct host_addr *host_addrs = NULL;
	static struct timespec mtime_last;
	static uint64_t recs[IPDB_TBL_ID_MAX];
	struct stat fstat;
	uint64_t epoch = 0x1;
	int ret;

	ret = stat(addr_data_file, &fstat);
	if (ret < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to get addr data file (%s) stats\n",
			    addr_data_file);
		return;
	}

	if (!memcmp(&fstat.st_mtime, &mtime_last, sizeof(mtime_last))) {
		if (ipdb)
			goto attach_ipdb;
		goto out;
	}

	host_addrs = parse_addr(addr_data_file,
				&recs[IPDB_TBL_ID_IPv4],
				&recs[IPDB_TBL_ID_IPv6],
				&recs[IPDB_TBL_ID_NAME]);
	if (!host_addrs)
		goto out;

	if (ipdb) {
		epoch = ssa_db_get_epoch(ipdb, DB_DEF_TBL_ID);
		epoch++;
		ssa_db_destroy(ipdb);
	}

	ipdb = ssa_ipdb_create(epoch, recs);
	if (!ipdb) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to create IPDB\n");
		goto out;
	}

	ipdb_add_addrs(ipdb, host_addrs, tbl_changed, recs[IPDB_TBL_ID_IPv4] +
		       recs[IPDB_TBL_ID_IPv6] + recs[IPDB_TBL_ID_NAME]);

	memcpy(&mtime_last, &fstat.st_mtime, sizeof(mtime_last));

	if (tbl_changed[SMDB_TBL_ID_IPv4] || tbl_changed[SMDB_TBL_ID_IPv6] ||
	    tbl_changed[SMDB_TBL_ID_NAME])
		p_ssa_db_diff->dirty = 1;

attach_ipdb:
	if (!p_ssa_db_diff->dirty)
		goto out;

	ret = ssa_db_attach(p_ssa_db_diff->p_smdb, "IPv4",
			    ipdb->p_db_tables[IPDB_TBL_ID_IPv4],
			    ipdb->pp_tables[IPDB_TBL_ID_IPv4]);
	if (ret < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to attach IPv4 table to SMDB\n");
		goto out;
	}

	ret = ssa_db_attach(p_ssa_db_diff->p_smdb, "IPv6",
			    ipdb->p_db_tables[IPDB_TBL_ID_IPv6],
			    ipdb->pp_tables[IPDB_TBL_ID_IPv6]);
	if (ret < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to attach IPv6 table to SMDB\n");
		goto out;
	}

	ret = ssa_db_attach(p_ssa_db_diff->p_smdb, "NAME",
			    ipdb->p_db_tables[IPDB_TBL_ID_NAME],
			    ipdb->pp_tables[IPDB_TBL_ID_NAME]);
	if (ret < 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to attach NAME table to SMDB\n");
		goto out;
	}

out:
	if (host_addrs)
		free(host_addrs);
	return;
}

/** =========================================================================
 */
struct ssa_db_diff *
ssa_db_compare(struct ssa_database * ssa_db, uint64_t epoch_prev, int first)
{
	struct ssa_db_diff *p_ssa_db_diff = NULL;
	boolean_t tbl_changed[SMDB_TBL_ID_MAX] = { FALSE };
	uint64_t data_rec_cnt[SMDB_TBL_ID_MAX] = { 0 };

	ssa_log(SSA_LOG_VERBOSE, "[\n");

	if (!ssa_db || !ssa_db->p_previous_db ||
	    !ssa_db->p_current_db || !ssa_db->p_dump_db ||
	    !ssa_db->p_lft_db) {
		ssa_log_err(SSA_LOG_DEFAULT, "bad arguments\n");
		goto Exit;
	}

	data_rec_cnt[SMDB_TBL_ID_SUBNET_OPTS] = 1;
	data_rec_cnt[SMDB_TBL_ID_GUID2LID] =
		cl_qmap_count(&ssa_db->p_current_db->ep_guid_to_lid_tbl) +
		cl_qmap_count(&ssa_db->p_previous_db->ep_guid_to_lid_tbl);
	data_rec_cnt[SMDB_TBL_ID_NODE] =
		cl_qmap_count(&ssa_db->p_current_db->ep_node_tbl) +
		cl_qmap_count(&ssa_db->p_previous_db->ep_node_tbl);
	data_rec_cnt[SMDB_TBL_ID_LINK] =
		cl_qmap_count(&ssa_db->p_current_db->ep_link_tbl) +
		cl_qmap_count(&ssa_db->p_previous_db->ep_link_tbl);
	data_rec_cnt[SMDB_TBL_ID_PORT] =
		cl_qmap_count(&ssa_db->p_current_db->ep_port_tbl) +
		cl_qmap_count(&ssa_db->p_previous_db->ep_port_tbl);
	data_rec_cnt[SMDB_TBL_ID_PKEY] =
		ssa_db->p_current_db->pkey_tbl_rec_num;
	data_rec_cnt[SMDB_TBL_ID_LFT_TOP] =
		cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_top_tbl) +
		cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_top_tbl);
	data_rec_cnt[SMDB_TBL_ID_LFT_BLOCK] =
		cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_block_tbl) +
		cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_block_tbl);

	p_ssa_db_diff = ssa_db_diff_init(epoch_prev, data_rec_cnt);
	if (!p_ssa_db_diff) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to initialize diff structure\n");
		goto Exit;
	}

	ssa_db_diff_compare_subnet_opts(ssa_db->p_previous_db, ssa_db->p_current_db,
					p_ssa_db_diff, tbl_changed);
	ssa_db_diff_compare_subnet_tables(ssa_db->p_previous_db, ssa_db->p_current_db,
					  p_ssa_db_diff, tbl_changed);
	ssa_db_diff_update_lfts(ssa_db, p_ssa_db_diff, tbl_changed, smdb_deltas, first);

	if (addr_preload)
		update_addr_tables(p_ssa_db_diff, tbl_changed);

	if (!p_ssa_db_diff->dirty) {
                ssa_log(SSA_LOG_VERBOSE, "SMDB was not changed\n");
                goto Exit;
        }

	ssa_db_diff_update_epoch(p_ssa_db_diff, tbl_changed);
#ifdef SSA_PLUGIN_VERBOSE_LOGGING
	ssa_db_diff_dump(p_ssa_db_diff);
#endif
Exit:
	ssa_log(SSA_LOG_VERBOSE, "]\n");

	return p_ssa_db_diff;
}
