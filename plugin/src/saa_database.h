/*
 * Copyright (c) 2011-2012 Mellanox Technologies LTD. All rights reserved.
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

#ifndef _SAA_DATABASE_H_
#define _SAA_DATABASE_H_

#include <iba/ib_types.h>
#include <complib/cl_ptr_vector.h>
#include <complib/cl_qmap.h>
#include <opensm/osm_node.h>
#include <opensm/osm_port.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else                           /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif                          /* __cplusplus */

BEGIN_C_DECLS

typedef struct ep_guid_to_lid_rec {
	cl_map_item_t map_item;
	uint16_t lid;
	uint8_t lmc;		/* or just fabric lmc ? */
#if 1
	/* Below is to optimize SP0 (if not in other tables) */
	uint8_t is_switch;	/* ??? */
#else
	uint8_t pad;		/* ??? */
#endif
} ep_guid_to_lid_rec_t;

typedef struct ep_node_rec {
	cl_map_item_t map_item;
#if 1
	/* or just device_id, vendor_id, enh SP0 ? */
	ib_node_info_t node_info;
#else
	/* or just is_tavor ? */
	uint32_t vendor_id;	/* needed for Tavor MTU */
	uint16_t device_id;	/* needed for Tavor MTU */
	uint16_t pad;
#endif
	ib_node_desc_t node_desc;
	uint8_t is_enhanced_sp0;
	uint8_t pad[3];
} ep_node_rec_t;

typedef struct ep_pkey_rec {
	/* port number only needed for switch external ports, not if only end ports */
	/* actual pkey table blocks or pkeys map ? */
#if 1
	uint16_t max_pkeys;     /* from NodeInfo.PartitionCap */
	uint16_t used_blocks;
	ib_pkey_table_t pkey_tbl[0];
#else
	cl_map_t pkeys;
#endif
} ep_pkey_rec_t;

typedef struct ep_port_rec {
	/* or just (subnet prefix), cap mask, port state ?, active speeds, active width, and mtu cap ? */
	ib_port_info_t port_info;
	uint8_t is_fdr10_active;
	uint8_t pad[3];
	ep_pkey_rec_t ep_pkey_rec;
} ep_port_rec_t;

typedef struct saa_db {
	/* mutex ??? */
	cl_qmap_t ep_guid_to_lid_tbl;	/* port GUID -> LID */
	cl_qmap_t ep_node_tbl;		/* node GUID based */
	cl_ptr_vector_t ep_port_tbl;	/* LID based */

	/* Fabric/SM related */
	uint64_t subnet_prefix;		/* even if full PortInfo used */
	uint8_t sm_state;
	uint8_t lmc;
	uint8_t subnet_timeout;
	uint8_t fabric_mtu;
	uint8_t fabric_rate;
	boolean_t enable_quirks;	/* or uint8_t ? */
	/* boolean_t allow_both_pkeys ? */
	/* prefix_routes */
} saa_db_t;

typedef struct saa_database {
	/* mutex ??? */
	saa_db_t *p_current_db;
	saa_db_t *p_previous_db;
	saa_db_t *p_dump_db;	
} saa_database_t;


extern saa_database_t *saa_db;

saa_database_t *saa_database_init();
void saa_database_delete(saa_database_t *p_saa_db);
saa_db_t *saa_db_init(uint16_t lids);
void saa_db_delete(saa_db_t *p_saa_db);
ep_guid_to_lid_rec_t *ep_guid_to_lid_rec_init(osm_port_t *p_port);
void ep_guid_to_lid_rec_delete(ep_guid_to_lid_rec_t *p_ep_guid_to_lid_rec);
ep_node_rec_t *ep_node_rec_init(osm_node_t *p_osm_node);
void ep_node_rec_delete(ep_node_rec_t *p_ep_node_rec);
ep_port_rec_t *ep_port_rec_init(osm_port_t *p_port);
void ep_port_rec_delete(ep_port_rec_t *p_ep_port_rec);

END_C_DECLS
#endif				/* _SAA_DATABASE_H_ */
