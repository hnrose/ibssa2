/*
 * Copyright (c) 2011-2014 Mellanox Technologies LTD. All rights reserved.
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

#include <infiniband/ssa_smdb_api.h>
#include <infiniband/ssa_database.h>
#include <infiniband/ssa_comparison.h>
#include <infiniband/ssa_extract.h>
#include <common.h>
#include <ssa_log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#define SSA_EXTRACT_PKEYS_MAX	(1 << 15)

const char *port_state_str[] = {
	"No change",
	"Down",
	"Initialize",
	"Armed",
	"Active"
};

extern struct ssa_database *ssa_db;

/** ===========================================================================
 */
static void
ssa_db_extract_subnet_opts(osm_subn_t *p_subn, struct ssa_db_extract *p_ssa_db)
{
	p_ssa_db->subnet_prefix = p_subn->opt.subnet_prefix;
	p_ssa_db->sm_state = p_subn->sm_state;
	p_ssa_db->lmc = p_subn->opt.lmc;
	p_ssa_db->subnet_timeout = p_subn->opt.subnet_timeout;
	p_ssa_db->allow_both_pkeys = (uint8_t) p_subn->opt.allow_both_pkeys;
}

/** ===========================================================================
 */
static int
ssa_db_extract_alloc_tbls(osm_subn_t *p_subn, struct ssa_db_extract *p_ssa_db)
{
	const osm_pkey_tbl_t *p_pkey_tbl;
	osm_switch_t *p_sw;
	osm_port_t *p_port;
	uint64_t links, ports, lft_blocks;
	uint32_t guids, nodes, lft_tops;
	uint32_t switch_ports_num = 0;
	uint32_t pkey_cnt = 0;
	uint16_t lids;

	nodes = (uint32_t) cl_qmap_count(&p_subn->node_guid_tbl);
	if (!p_ssa_db->p_node_tbl) {
		p_ssa_db->p_node_tbl = (struct ep_node_tbl_rec *)
		    malloc(sizeof(*p_ssa_db->p_node_tbl) * nodes);
		if (!p_ssa_db->p_node_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate nodes table\n");
			goto err0;
		}
	}

	lft_tops = (uint32_t) cl_qmap_count(&p_subn->sw_guid_tbl);
	if (!ssa_db->p_lft_db->p_db_lft_top_tbl) {
		ssa_db->p_lft_db->p_db_lft_top_tbl =
		    (struct ep_lft_top_tbl_rec *)
			malloc(sizeof(*ssa_db->p_lft_db->p_db_lft_top_tbl) *
			       lft_tops);
		if (!ssa_db->p_lft_db->p_db_lft_top_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate LFT tops table\n");
			goto err1;
		}
	}

	lids = (uint16_t) cl_ptr_vector_get_size(&p_subn->port_lid_tbl);

	lft_blocks = ((lids % IB_SMP_DATA_SIZE) ?
	    (lids / IB_SMP_DATA_SIZE + 1) : (lids / IB_SMP_DATA_SIZE));
	lft_blocks = (uint64_t) lft_tops * lft_blocks * (1 << p_ssa_db->lmc);
	if (!ssa_db->p_lft_db->p_db_lft_block_tbl) {
		ssa_db->p_lft_db->p_db_lft_block_tbl =
		    (struct ep_lft_block_tbl_rec *)
			malloc(sizeof(*ssa_db->p_lft_db->p_db_lft_block_tbl) *
			       lft_blocks);
		if (!ssa_db->p_lft_db->p_db_lft_block_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate LFT blocks table\n");
			goto err2;
		}
	}

	guids = (uint32_t) cl_qmap_count(&p_subn->port_guid_tbl);
	if (!p_ssa_db->p_guid_to_lid_tbl) {
		p_ssa_db->p_guid_to_lid_tbl = (struct ep_guid_to_lid_tbl_rec *)
				malloc(sizeof(*p_ssa_db->p_guid_to_lid_tbl) *
				       guids);
		if (!p_ssa_db->p_guid_to_lid_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate GUID to LID table\n");
			goto err3;
		}
	}

	for (p_sw = (osm_switch_t *)cl_qmap_head(&p_subn->sw_guid_tbl);
	     p_sw != (osm_switch_t *)cl_qmap_end(&p_subn->sw_guid_tbl);
	     p_sw = (osm_switch_t *)cl_qmap_next(&p_sw->map_item))
			switch_ports_num += p_sw->num_ports;

	links = guids + switch_ports_num;
	if (!p_ssa_db->p_link_tbl) {
		p_ssa_db->p_link_tbl = (struct ep_link_tbl_rec *)
				malloc(sizeof(*p_ssa_db->p_link_tbl) * links);
		if (!p_ssa_db->p_link_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate links table\n");
			goto err4;
		}
	}

	ports = links;
	if (!p_ssa_db->p_port_tbl) {
		p_ssa_db->p_port_tbl = (struct ep_port_tbl_rec *)
				malloc(sizeof(*p_ssa_db->p_port_tbl) * ports);
		if (!p_ssa_db->p_port_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate ports table\n");
			goto err5;
		}
	}

	for (p_port = (osm_port_t *)cl_qmap_head(&p_subn->port_guid_tbl);
	     p_port != (osm_port_t *)cl_qmap_end(&p_subn->port_guid_tbl);
	     p_port = (osm_port_t *)cl_qmap_next(&p_port->map_item)) {
		p_pkey_tbl = osm_physp_get_pkey_tbl(p_port->p_physp);
		pkey_cnt += (uint32_t)
		    cl_map_count((const cl_map_t *) &p_pkey_tbl->keys);
	}

	if (!p_ssa_db->p_pkey_tbl) {
		p_ssa_db->p_pkey_tbl = (uint16_t *)
		    malloc(sizeof(*p_ssa_db->p_pkey_tbl) * pkey_cnt);
		if (!p_ssa_db->p_pkey_tbl) {
			ssa_log(SSA_LOG_DEFAULT,
				"ERROR - unable to allocate pkeys table\n");
			goto err6;
		}
	}
	p_ssa_db->pkey_tbl_rec_num = pkey_cnt;

	return 0;

err6:
	free(p_ssa_db->p_port_tbl);
err5:
	free(p_ssa_db->p_link_tbl);
err4:
	free(p_ssa_db->p_guid_to_lid_tbl);
err3:
	free(ssa_db->p_lft_db->p_db_lft_block_tbl);
err2:
	free(ssa_db->p_lft_db->p_db_lft_top_tbl);
err1:
	free(p_ssa_db->p_node_tbl);
err0:
	return -1;
}

/** ===========================================================================
 */
static void
ssa_db_extract_node_tbl_rec(osm_node_t *p_node, uint64_t *p_offset,
			    struct ssa_db_extract *p_ssa_db)
{
	struct ep_map_rec *p_map_rec;
#ifdef SSA_PLUGIN_VERBOSE_LOGGING
	char buffer[64];
	if (osm_node_get_type(p_node) == IB_NODE_TYPE_SWITCH)
		sprintf(buffer, " with %s Switch Port 0\n",
			ib_switch_info_is_enhanced_port0(
			    &p_node->sw->switch_info) ? "Enhanced" : "Base");
	else
		sprintf(buffer, "\n");
	ssa_log(SSA_LOG_VERBOSE, "Node GUID 0x%" PRIx64 " Type %d%s",
		ntohll(osm_node_get_node_guid(p_node)),
		osm_node_get_type(p_node), buffer);
#endif

	ep_node_tbl_rec_init(p_node, &p_ssa_db->p_node_tbl[*p_offset]);

	p_map_rec = ep_map_rec_init(*p_offset);
	if (!p_map_rec) {
		/* add memory allocation failure handling */
		ssa_log(SSA_LOG_VERBOSE,
			"Quick MAP rec memory allocation failed\n");
	}

	cl_qmap_insert(&p_ssa_db->ep_node_tbl,
		       osm_node_get_node_guid(p_node),
		       &p_map_rec->map_item);

	*p_offset = *p_offset + 1;
}

/** ===========================================================================
 */
static void
ssa_db_extract_lft(osm_switch_t *p_sw, uint64_t *p_top_offset,
		   uint64_t *p_block_offset)
{
	struct ep_map_rec *p_map_rec;
	uint64_t rec_key;
	uint16_t max_block, lid_ho, i;

	max_block = p_sw->lft_size / IB_SMP_DATA_SIZE;
	lid_ho = ntohs(osm_node_get_base_lid(p_sw->p_node, 0));
	rec_key = (uint64_t) lid_ho;

	ep_lft_top_tbl_rec_init(lid_ho, p_sw->lft_size,
				&ssa_db->p_lft_db->p_db_lft_top_tbl[*p_top_offset]);
	p_map_rec = ep_map_rec_init(*p_top_offset);
	cl_qmap_insert(&ssa_db->p_lft_db->ep_db_lft_top_tbl,
		       rec_key, &p_map_rec->map_item);
	*p_top_offset = *p_top_offset + 1;

	for(i = 0; i < max_block; i++) {
		rec_key = ep_rec_gen_key(lid_ho, i);
		ep_lft_block_tbl_rec_init(p_sw, lid_ho, i,
					  &ssa_db->p_lft_db->p_db_lft_block_tbl[*p_block_offset]);

		p_map_rec = ep_map_rec_init(*p_block_offset);
		cl_qmap_insert(&ssa_db->p_lft_db->ep_db_lft_block_tbl,
			       rec_key, &p_map_rec->map_item);
		*p_block_offset = *p_block_offset + 1;
	}
}

/** ===========================================================================
 */
static void
ssa_db_extract_guid_to_lid_tbl_rec(osm_port_t *p_port, uint64_t *p_offset,
				   struct ssa_db_extract *p_ssa_db)
{
	struct ep_map_rec *p_map_rec;
#ifdef SSA_PLUGIN_VERBOSE_LOGGING
	uint8_t is_fdr10_active;

	ssa_log(SSA_LOG_VERBOSE, "Port GUID 0x%" PRIx64 " LID %u Port state %d"
		"(%s)\n", ntohll(osm_physp_get_port_guid(p_port->p_physp)),
		ntohs(osm_port_get_base_lid(p_port)),
		osm_physp_get_port_state(p_port->p_physp),
		(osm_physp_get_port_state(p_port->p_physp) < 5 ?
		 port_state_str[osm_physp_get_port_state(p_port->p_physp)] :
		 "???"));
	is_fdr10_active =
	    p_port->p_physp->ext_port_info.link_speed_active & FDR10;
	ssa_log(SSA_LOG_VERBOSE, "FDR10 %s active\n",
		is_fdr10_active ? "" : "not");
#endif

	/* check for valid LID first */
	if ((ntohs(osm_port_get_base_lid(p_port)) < IB_LID_UCAST_START_HO) ||
	    (ntohs(osm_port_get_base_lid(p_port)) > IB_LID_UCAST_END_HO)) {
		ssa_log(SSA_LOG_VERBOSE, "Port GUID 0x%" PRIx64
			" has invalid LID %u\n",
			ntohll(osm_physp_get_port_guid(p_port->p_physp)),
			ntohs(osm_port_get_base_lid(p_port)));
	}

	ep_guid_to_lid_tbl_rec_init(p_port,
				    &p_ssa_db->p_guid_to_lid_tbl[*p_offset]);
	p_map_rec = ep_map_rec_init(*p_offset);
	if (!p_map_rec) {
		/* add memory allocation failure handling */
		ssa_log(SSA_LOG_VERBOSE, "Quick MAP rec memory allocation failed\n");
	}
	cl_qmap_insert(&p_ssa_db->ep_guid_to_lid_tbl,
		       osm_physp_get_port_guid(p_port->p_physp),
		       &p_map_rec->map_item);

	*p_offset = *p_offset + 1;
}

/** ===========================================================================
 */
static void
ssa_db_extract_port_tbl_rec(osm_physp_t *p_physp, uint16_t *p_lid_ho,
			    uint64_t pkey_base_offset, uint16_t pkey_tbl_size,
			    uint64_t *p_port_offset,
			    struct ssa_db_extract *p_ssa_db)
{
	struct ep_map_rec *p_map_rec;
	uint64_t rec_key;
	uint16_t lid_ho;

	if (p_lid_ho) {
		/* in case of switch port */
		rec_key = ep_rec_gen_key(*p_lid_ho,
					 osm_physp_get_port_num(p_physp));
		lid_ho = *p_lid_ho;
	} else {
		rec_key = ep_rec_gen_key(ntohs(osm_physp_get_base_lid(p_physp)),
					 osm_physp_get_port_num(p_physp));
		lid_ho = 0;
	}

	ep_port_tbl_rec_init(p_physp, pkey_base_offset, pkey_tbl_size,
			     htons(lid_ho),
			     &p_ssa_db->p_port_tbl[*p_port_offset]);
	p_map_rec = ep_map_rec_init(*p_port_offset);
	cl_qmap_insert(&p_ssa_db->ep_port_tbl, rec_key,
		       &p_map_rec->map_item);
	*p_port_offset = *p_port_offset + 1;
}

/** ===========================================================================
 */
static void
ssa_db_extract_link_tbl_rec(osm_physp_t *p_physp, uint16_t *p_lid_ho,
			    uint64_t *p_link_offset,
			    struct ssa_db_extract *p_ssa_db)
{
	struct ep_map_rec *p_map_rec;
	uint64_t rec_key;

	if (p_lid_ho)
		rec_key = ep_rec_gen_key(*p_lid_ho,
					 osm_physp_get_port_num(p_physp));
	else
		rec_key = ep_rec_gen_key(ntohs(osm_physp_get_base_lid(p_physp)),
					 osm_physp_get_port_num(p_physp));

	ep_link_tbl_rec_init(p_physp, &p_ssa_db->p_link_tbl[*p_link_offset]);
	p_map_rec = ep_map_rec_init(*p_link_offset);
	cl_qmap_insert(&p_ssa_db->ep_link_tbl, rec_key, &p_map_rec->map_item);
	*p_link_offset = *p_link_offset + 1;
}

/** ===========================================================================
 */
static void ssa_db_extract_dump_port_qos(osm_port_t *p_port)
{
#ifdef SSA_PLUGIN_VERBOSE_LOGGING
	const osm_pkey_tbl_t *p_pkey_tbl;
	const ib_pkey_table_t *block;
	//char *header_line =    "#in out : 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15";
	//char *separator_line = "#--------------------------------------------------------";
	//ib_slvl_table_t *p_tbl;
	ib_net16_t pkey;
	uint16_t block_index, max_pkeys, pkey_idx;
	//uint8_t out_port, in_port, num_ports;
	//uint8_t n;

//	ssa_log(SSA_LOG_VERBOSE, "\t\t\tSLVL tables\n");
//	ssa_log(SSA_LOG_VERBOSE, "%s\n", header_line);
//	ssa_log(SSA_LOG_VERBOSE, "%s\n", separator_line);
//
//	out_port = p_port->p_physp->port_num;
//	num_ports = p_port->p_physp->p_node->node_info.num_ports;
//	if (osm_node_get_type(p_port->p_physp->p_node) ==
//		IB_NODE_TYPE_SWITCH) {
//		/* no need to print SL2VL table for port that is down */
//		/* TODO: not sure if it is needed */
//		/*if (!p_port->p_physp->p_remote_physp)
//			continue; */
//
//		for (in_port = 0; in_port <= num_ports; in_port++) {
//			p_tbl = osm_physp_get_slvl_tbl(p_port->p_physp,
//						       in_port);
//			for (i = 0, n = 0; i < 16; i++)
//				n += sprintf(buffer + n, " %-2d",
//					ib_slvl_table_get(p_tbl, i));
//				ssa_log(SSA_LOG_VERBOSE, "%-3d %-3d :%s\n",
//					in_port, out_port, buffer);
//		}
//	} else {
//		p_tbl = osm_physp_get_slvl_tbl(p_port->p_physp, 0);
//		for (i = 0, n = 0; i < 16; i++)
//			n += sprintf(buffer + n, " %-2d",
//					ib_slvl_table_get(p_tbl, i));
//			ssa_log(SSA_LOG_VERBOSE, "%-3d %-3d :%s\n", out_port,
//				out_port, buffer);
//	}
//
	max_pkeys = ntohs(p_port->p_node->node_info.partition_cap);
	ssa_log(SSA_LOG_VERBOSE, "PartitionCap %u\n", max_pkeys);
	p_pkey_tbl = osm_physp_get_pkey_tbl(p_port->p_physp);
	ssa_log(SSA_LOG_VERBOSE, "PKey Table %u used blocks\n",
		p_pkey_tbl->used_blocks);
	for (block_index = 0; block_index < p_pkey_tbl->used_blocks;
	     block_index++) {
		block = osm_pkey_tbl_new_block_get(p_pkey_tbl, block_index);
		if (!block)
			continue;
		for (pkey_idx = 0; pkey_idx < IB_NUM_PKEY_ELEMENTS_IN_BLOCK;
		     pkey_idx++) {
			pkey = block->pkey_entry[pkey_idx];
			if (ib_pkey_is_invalid(pkey))
				continue;
			ssa_log(SSA_LOG_VERBOSE, "PKey 0x%04x at block %u "
				"index %u\n", ntohs(pkey), block_index,
				pkey_idx);
		}
	}
#endif
}

/** ===========================================================================
 */
void static
ssa_db_extract_switch_port(osm_port_t *p_port, uint64_t *p_pkey_base_offset,
			   uint64_t *p_pkey_offset, uint64_t *p_port_offset,
			   uint64_t *p_link_offset,
			   struct ssa_db_extract *p_ssa_db)
{
	osm_node_t *p_node = p_port->p_physp->p_node;
	const osm_pkey_tbl_t *p_pkey_tbl;
	const ib_pkey_table_t *block;
	osm_physp_t *p_physp;
	uint32_t i;
	ib_net16_t pkey;
	uint16_t lid_ho, block_index, pkey_idx;

	for (i = 0; i < p_node->physp_tbl_size; i++) {
		p_physp = osm_node_get_physp_ptr(p_node, i);
		if (!p_physp)
			continue;

		/* TODO: add filtering for down ports */

		if (i == 0) {
			lid_ho = ntohs(osm_physp_get_base_lid(p_physp));

			p_pkey_tbl = osm_physp_get_pkey_tbl(p_physp);
			for (block_index = 0; block_index < p_pkey_tbl->used_blocks;
			     block_index++) {
				block = osm_pkey_tbl_block_get(p_pkey_tbl, block_index);
				if (!block)
					continue;
				for (pkey_idx = 0; pkey_idx < IB_NUM_PKEY_ELEMENTS_IN_BLOCK;
				     pkey_idx++) {
					pkey = block->pkey_entry[pkey_idx];
					if (ib_pkey_is_invalid(pkey))
						continue;

					p_ssa_db->p_pkey_tbl[*p_pkey_base_offset + *p_pkey_offset] = pkey;
					*p_pkey_offset = *p_pkey_offset + 1;
				}
			}

			if (*p_pkey_offset >= SSA_EXTRACT_PKEYS_MAX) {
				ssa_log_err(SSA_LOG_DEFAULT,
					    "ERROR - truncating number of pkeys "
					    "from %d to %d (maximum) for LID %u\n",
					    *p_pkey_offset, SSA_EXTRACT_PKEYS_MAX - 1, lid_ho);
				*p_pkey_offset = SSA_EXTRACT_PKEYS_MAX - 1;
			}

			ssa_db_extract_port_tbl_rec(p_physp, &lid_ho,
						    htonll(*p_pkey_base_offset * sizeof(pkey)),
						    htons(*p_pkey_offset * sizeof(pkey)),
						    p_port_offset, p_ssa_db);
		} else {
			ssa_db_extract_port_tbl_rec(p_physp, &lid_ho, 0, 0,
						    p_port_offset, p_ssa_db);
		}

		if (!osm_physp_get_remote(p_physp))
			continue;

		ssa_db_extract_link_tbl_rec(p_physp, &lid_ho, p_link_offset,
					    p_ssa_db);
	}
}

/** ===========================================================================
 */
void static
ssa_db_extract_host_port(osm_port_t *p_port, uint64_t *p_pkey_base_offset,
			 uint64_t *p_pkey_offset, uint64_t *p_port_offset,
			 uint64_t *p_link_offset,
			 struct ssa_db_extract *p_ssa_db)
{
	const osm_pkey_tbl_t *p_pkey_tbl;
	const ib_pkey_table_t *block;
	osm_physp_t *p_physp = p_port->p_physp;
	ib_net16_t pkey;
	uint16_t block_index, pkey_idx;

	p_pkey_tbl = osm_physp_get_pkey_tbl(p_physp);
	for (block_index = 0; block_index < p_pkey_tbl->used_blocks;
	     block_index++) {
		block = osm_pkey_tbl_block_get(p_pkey_tbl, block_index);
		if (!block)
			continue;
		for (pkey_idx = 0; pkey_idx < IB_NUM_PKEY_ELEMENTS_IN_BLOCK;
		     pkey_idx++) {
			pkey = block->pkey_entry[pkey_idx];
			if (ib_pkey_is_invalid(pkey))
				continue;

			p_ssa_db->p_pkey_tbl[*p_pkey_base_offset + *p_pkey_offset] = pkey;
			*p_pkey_offset = *p_pkey_offset + 1;
		}
	}

	if (*p_pkey_offset >= SSA_EXTRACT_PKEYS_MAX) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "ERROR - truncating number of pkeys "
			    "from %d to %d (maximum) for LID %u\n",
			    *p_pkey_offset, SSA_EXTRACT_PKEYS_MAX - 1,
			    ntohs(osm_physp_get_base_lid(p_physp)));
		*p_pkey_offset = SSA_EXTRACT_PKEYS_MAX - 1;
	}

	ssa_db_extract_port_tbl_rec(p_physp, NULL, htonll(*p_pkey_base_offset * sizeof(pkey)),
				    htons(*p_pkey_offset * sizeof(pkey)),
				    p_port_offset, p_ssa_db);

	if (!osm_physp_get_remote(p_physp))
		return;

	ssa_db_extract_link_tbl_rec(p_physp, NULL, p_link_offset, p_ssa_db);
}

/** ===========================================================================
 */
struct ssa_db_extract *ssa_db_extract(osm_opensm_t *p_osm)
{
	struct ssa_db_extract *p_ssa;
	osm_subn_t *p_subn = &p_osm->subn;
	osm_node_t *p_node, *p_next_node;
	osm_port_t *p_port, *p_next_port;
	uint64_t guid_to_lid_offset = 0;
	uint64_t node_offset = 0, link_offset = 0, port_offset = 0;
	uint64_t pkey_base_offset = 0, pkey_cur_offset = 0;
	uint64_t lft_top_offset = 0, lft_block_offset = 0;
	int lft_extract = 0;
	uint8_t ret = 0;

	ssa_log(SSA_LOG_VERBOSE, "[\n");

	p_ssa = ssa_db->p_dump_db;
	ssa_db_extract_subnet_opts(p_subn, p_ssa);

	ret = ssa_db_extract_alloc_tbls(p_subn, p_ssa);
	if (ret)
		return NULL;

	if (cl_is_qmap_empty(&ssa_db->p_lft_db->ep_db_lft_block_tbl) &&
	    cl_is_qmap_empty(&ssa_db->p_lft_db->ep_db_lft_top_tbl))
		lft_extract = 1;
	else if (cl_is_qmap_empty(&ssa_db->p_lft_db->ep_db_lft_block_tbl))
		ssa_log_warn(SSA_LOG_DEFAULT, "inconsistent LFT block records\n");
	else if (cl_is_qmap_empty(&ssa_db->p_lft_db->ep_db_lft_top_tbl))
		ssa_log_warn(SSA_LOG_DEFAULT, "inconsistent LFT top records\n");

	p_next_node = (osm_node_t *)cl_qmap_head(&p_subn->node_guid_tbl);
	while (p_next_node !=
	       (osm_node_t *)cl_qmap_end(&p_subn->node_guid_tbl)) {
		p_node = p_next_node;
		p_next_node = (osm_node_t *)cl_qmap_next(&p_node->map_item);

		ssa_db_extract_node_tbl_rec(p_node, &node_offset, p_ssa);

		/* TODO: add more cases when full dump is needed */
		if (!lft_extract)
			continue;

		/*		Adding LFT tables
		 * When the first SMDB dump is performed, all LFTs
		 * are added automatically, further dumps or changes
		 * will be done only on OSM_EVENT_ID_LFT_CHANGE
		 */
		if (osm_node_get_type(p_node) == IB_NODE_TYPE_SWITCH)
			ssa_db_extract_lft(p_node->sw, &lft_top_offset,
					   &lft_block_offset);
	}

	p_next_port = (osm_port_t *)cl_qmap_head(&p_subn->port_guid_tbl);
	while (p_next_port !=
	       (osm_port_t *)cl_qmap_end(&p_subn->port_guid_tbl)) {
		p_port = p_next_port;
		p_next_port = (osm_port_t *)cl_qmap_next(&p_port->map_item);

		ssa_db_extract_guid_to_lid_tbl_rec(p_port, &guid_to_lid_offset,
						   p_ssa);

		ssa_db_extract_dump_port_qos(p_port);

		/* TODO:: add log info ??? */
		if (osm_node_get_type(p_port->p_physp->p_node) == IB_NODE_TYPE_SWITCH)
			ssa_db_extract_switch_port(p_port, &pkey_base_offset,
						   &pkey_cur_offset,
						   &port_offset, &link_offset,
						   p_ssa);
		else
			ssa_db_extract_host_port(p_port, &pkey_base_offset,
						 &pkey_cur_offset,
						 &port_offset, &link_offset,
						 p_ssa);

		pkey_base_offset += pkey_cur_offset;
		pkey_cur_offset = 0;
	}

	p_ssa->initialized = 1;
	ssa_log(SSA_LOG_VERBOSE, "]\n");

	return p_ssa;
}

/** ===========================================================================
 */
void ssa_db_validate_lft(int first)
{
	struct ep_lft_block_tbl_rec lft_block_tbl_rec;
	struct ep_lft_top_tbl_rec lft_top_tbl_rec;
	int i;

	if (!first || !(ssa_get_log_level() & SSA_LOG_DB))
		return;

	for (i = 0;
	     i < cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_block_tbl); i++) {
		lft_block_tbl_rec = ssa_db->p_lft_db->p_db_lft_block_tbl[i];
		ssa_log(SSA_LOG_DB,
			"LFT Block Record: LID %u Block num %u\n",
			ntohs(lft_block_tbl_rec.lid),
			ntohs(lft_block_tbl_rec.block_num));
	}

	for (i = 0;
	     i < cl_qmap_count(&ssa_db->p_lft_db->ep_db_lft_top_tbl); i++) {
		lft_top_tbl_rec = ssa_db->p_lft_db->p_db_lft_top_tbl[i];
		ssa_log(SSA_LOG_DB, "LFT Top Record: LID %u New Top %u\n",
			ntohs(lft_top_tbl_rec.lid),
			ntohs(lft_top_tbl_rec.lft_top));
	}
}

/** ===========================================================================
 */
void ssa_db_validate(struct ssa_db_extract *p_ssa_db)
{
	struct ep_guid_to_lid_tbl_rec guid_to_lid_tbl_rec;
	struct ep_node_tbl_rec node_tbl_rec;
	struct ep_link_tbl_rec link_tbl_rec;
	struct ep_port_tbl_rec port_tbl_rec;
	uint64_t i;
	char buffer[64];

	if (!p_ssa_db || !p_ssa_db->initialized ||
	    !(ssa_get_log_level() & SSA_LOG_DB))
		return;

	ssa_log(SSA_LOG_DB, "[\n");

	/* First, most Fabric/SM related parameters */
	ssa_log(SSA_LOG_DB, "Subnet prefix 0x%" PRIx64 "\n",
		ntohll(p_ssa_db->subnet_prefix));
	ssa_log(SSA_LOG_DB,
		"LMC %u Subnet timeout %u Both Pkeys %sabled\n",
		p_ssa_db->lmc, p_ssa_db->subnet_timeout,
		p_ssa_db->allow_both_pkeys ? "en" : "dis");

	for (i = 0; i < cl_qmap_count(&p_ssa_db->ep_node_tbl); i++) {
		node_tbl_rec = p_ssa_db->p_node_tbl[i];
		if (node_tbl_rec.node_type == IB_NODE_TYPE_SWITCH)
			sprintf(buffer, " with %s Switch Port 0\n",
				node_tbl_rec.is_enhanced_sp0 ?
				"Enhanced" : "Base");
		else
			sprintf(buffer, "\n");
		ssa_log(SSA_LOG_DB, "Node GUID 0x%" PRIx64 " Type %d%s",
			ntohll(node_tbl_rec.node_guid), node_tbl_rec.node_type,
			buffer);
	}

	for (i = 0; i < cl_qmap_count(&p_ssa_db->ep_guid_to_lid_tbl); i++) {
		guid_to_lid_tbl_rec = p_ssa_db->p_guid_to_lid_tbl[i];
		ssa_log(SSA_LOG_DB,
			"Port GUID 0x%" PRIx64 " LID %u LMC %u is_switch %d\n",
			ntohll(guid_to_lid_tbl_rec.guid),
			ntohs(guid_to_lid_tbl_rec.lid),
			guid_to_lid_tbl_rec.lmc, guid_to_lid_tbl_rec.is_switch);

	}

	for (i = 0; i < cl_qmap_count(&p_ssa_db->ep_port_tbl); i++) {
		port_tbl_rec = p_ssa_db->p_port_tbl[i];
		ssa_log(SSA_LOG_DB, "Port LID %u Port Num %u\n",
			ntohs(port_tbl_rec.port_lid), port_tbl_rec.port_num);
		ssa_log(SSA_LOG_DB, "NeighborMTU %u rate %u\n",
			port_tbl_rec.neighbor_mtu,
			port_tbl_rec.rate & SSA_DB_PORT_RATE_MASK);
		ssa_log(SSA_LOG_DB, "FDR10 %s active\n",
			(port_tbl_rec.rate & SSA_DB_PORT_IS_FDR10_ACTIVE_MASK)
			? "" : "not");
		ssa_log(SSA_LOG_DB, "PKeys %u\n",
			ntohs(port_tbl_rec.pkey_tbl_size) /
			      sizeof(*p_ssa_db->p_pkey_tbl));
	}

	for (i = 0; i < cl_qmap_count(&p_ssa_db->ep_link_tbl); i++) {
		link_tbl_rec = p_ssa_db->p_link_tbl[i];
		ssa_log(SSA_LOG_DB,
			"Link Record: from LID %u port %u to LID %u port %u\n",
			ntohs(link_tbl_rec.from_lid),
			link_tbl_rec.from_port_num, ntohs(link_tbl_rec.to_lid),
			link_tbl_rec.to_port_num);
	}

	ssa_log(SSA_LOG_DB, "]\n");
}

/** ===========================================================================
 */
/* TODO: Add meaningful return value */
void ssa_db_update(struct ssa_database *ssa_db)
{
	ssa_log(SSA_LOG_VERBOSE, "[\n");

        if (!ssa_db || !ssa_db->p_previous_db ||
	    !ssa_db->p_current_db || !ssa_db->p_dump_db) {
                /* error handling */
                return;
        }

	/* Updating previous SMDB with current one */
	if (ssa_db->p_current_db->initialized) {
		ssa_db_extract_delete(ssa_db->p_previous_db);
		ssa_db->p_previous_db = ssa_db->p_current_db;
	} else {
		ssa_db_extract_delete(ssa_db->p_current_db);
	}
	ssa_db->p_current_db = ssa_db->p_dump_db;
	ssa_db->p_dump_db = ssa_db_extract_init();

	ssa_log(SSA_LOG_VERBOSE, "]\n");
}

/** ===========================================================================
 */
static void
ssa_db_lft_block_handle(struct ssa_db_lft_change_rec *p_lft_change_rec)
{
	struct ep_map_rec *p_map_rec, *p_map_rec_old;
	uint64_t rec_num, key;
	uint16_t block_num;

	rec_num = cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_block_tbl);
	if (rec_num % SSA_TABLE_BLOCK_SIZE == 0) {
		ssa_db->p_lft_db->p_dump_lft_block_tbl =
		    (struct ep_lft_block_tbl_rec *)
			realloc(&ssa_db->p_lft_db->p_dump_lft_block_tbl[0],
				(rec_num / SSA_TABLE_BLOCK_SIZE + 1) *
				 SSA_TABLE_BLOCK_SIZE *
				 sizeof(*ssa_db->p_lft_db->p_dump_lft_block_tbl));
	}

	block_num = p_lft_change_rec->lft_change.block_num;
	ssa_log(SSA_LOG_VERBOSE, "LFT change block event received "
				 "for LID %u Block %u\n",
				 ntohs(p_lft_change_rec->lid), block_num);

	key = ep_rec_gen_key(ntohs(p_lft_change_rec->lid), block_num);

	p_map_rec = ep_map_rec_init(rec_num);
	p_map_rec_old = (struct ep_map_rec *)
		cl_qmap_insert(&ssa_db->p_lft_db->ep_dump_lft_block_tbl,
			       key, &p_map_rec->map_item);
	if (p_map_rec != p_map_rec_old) {
		/* in case of a record with the same key already exist */
		rec_num = p_map_rec_old->offset;
		free(p_map_rec);
	}

	ssa_db->p_lft_db->p_dump_lft_block_tbl[rec_num].lid = p_lft_change_rec->lid;
	ssa_db->p_lft_db->p_dump_lft_block_tbl[rec_num].block_num = htons(block_num);

	memcpy(ssa_db->p_lft_db->p_dump_lft_block_tbl[rec_num].block,
	       p_lft_change_rec->block, IB_SMP_DATA_SIZE);
}

/** ===========================================================================
 */
static void
ssa_db_lft_top_handle(struct ssa_db_lft_change_rec *p_lft_change_rec)
{
	struct ep_map_rec *p_map_rec, *p_map_rec_old;
	uint64_t rec_num, key;

	rec_num = cl_qmap_count(&ssa_db->p_lft_db->ep_dump_lft_top_tbl);
	if (rec_num % SSA_TABLE_BLOCK_SIZE == 0) {
		ssa_db->p_lft_db->p_dump_lft_top_tbl =
		    (struct ep_lft_top_tbl_rec *)
			realloc(&ssa_db->p_lft_db->p_dump_lft_top_tbl[0],
				(rec_num / SSA_TABLE_BLOCK_SIZE + 1) *
				 SSA_TABLE_BLOCK_SIZE *
				 sizeof(*ssa_db->p_lft_db->p_dump_lft_top_tbl));
	}

	ssa_log(SSA_LOG_VERBOSE, "LFT change top event received "
				 "for LID %u New Top %u\n",
				 ntohs(p_lft_change_rec->lid),
				 p_lft_change_rec->lft_change.lft_top);

	key = (uint64_t) ntohs(p_lft_change_rec->lid);

	p_map_rec = ep_map_rec_init(rec_num);
	p_map_rec_old = (struct ep_map_rec *)
		cl_qmap_insert(&ssa_db->p_lft_db->ep_dump_lft_top_tbl,
			       key, &p_map_rec->map_item);
	if (p_map_rec != p_map_rec_old) {
		/* in case of a record with the same key already exist */
		rec_num = p_map_rec_old->offset;
		free(p_map_rec);
	}

	ssa_db->p_lft_db->p_dump_lft_top_tbl[rec_num].lid =
		p_lft_change_rec->lid;
	ssa_db->p_lft_db->p_dump_lft_top_tbl[rec_num].lft_top =
		htons(p_lft_change_rec->lft_change.lft_top);
}

/** ===========================================================================
 */
void ssa_db_lft_handle(void)
{
	struct ssa_db_lft_change_rec *p_lft_change_rec;
	cl_list_item_t *p_item;

	pthread_mutex_lock(&ssa_db->lft_rec_list_lock);

	while ((p_item = cl_qlist_remove_head(&ssa_db->lft_rec_list)) !=
	       cl_qlist_end(&ssa_db->lft_rec_list)) {
		p_lft_change_rec =
		    cl_item_obj(p_item, p_lft_change_rec, list_item);
		switch (p_lft_change_rec->lft_change.flags) {
		case LFT_CHANGED_BLOCK:
			ssa_db_lft_block_handle(p_lft_change_rec);
			break;
		case LFT_CHANGED_LFT_TOP:
			ssa_db_lft_top_handle(p_lft_change_rec);
			break;
		default:
			ssa_log(SSA_LOG_ALL, "Unknown LFT change event (%d)\n",
				p_lft_change_rec->lft_change.flags);
			break;
		}
		free(p_lft_change_rec);
        }

	pthread_mutex_unlock(&ssa_db->lft_rec_list_lock);
}
