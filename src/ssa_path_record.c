/*
 * Copyright 2004-2013 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the terms of the
 * OpenIB.org BSD license included below:
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
#endif              /* HAVE_CONFIG_H */

#include <string.h>
#include <math.h>
#include <stdarg.h>
#include <assert.h>
#include <ssa_smdb.h>
#include "ssa_path_record.h"

#define MIN(X,Y) ((X) < (Y) ?  (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ?  (X) : (Y))

#define MAX_HOPS 64
#define LFT_NO_PATH 255


int ssa_pr_log_level = SSA_PR_EEROR_LEVEL;

static ssa_pr_status_t ssa_pr_path_params(const struct ssa_db_smdb *p_ssa_db_smdb,
		const struct ep_guid_to_lid_tbl_rec *p_source_rec,
		const struct ep_guid_to_lid_tbl_rec *p_dest_rec,
		ssa_path_parms_t *p_path_prm);

static int ordered_rates[] = {
	0, 0,	/*  0, 1 - reserved */
	1,	/*  2 - 2.5 Gbps */
	3,	/*  3 - 10  Gbps */
	6,	/*  4 - 30  Gbps */
	2,	/*  5 - 5   Gbps */
	5,	/*  6 - 20  Gbps */
	8,	/*  7 - 40  Gbps */
	9,	/*  8 - 60  Gbps */
	11,	/*  9 - 80  Gbps */
	12,	/* 10 - 120 Gbps */
	4,	/* 11 -  14 Gbps (17 Gbps equiv) */
	10,	/* 12 -  56 Gbps (68 Gbps equiv) */
	14,	/* 13 - 112 Gbps (136 Gbps equiv) */
	15,	/* 14 - 168 Gbps (204 Gbps equiv) */
	7,	/* 15 -  25 Gbps (31.25 Gbps equiv) */
	13,	/* 16 - 100 Gbps (125 Gbps equiv) */
	16,	/* 17 - 200 Gbps (250 Gbps equiv) */
	17	/* 18 - 300 Gbps (375 Gbps equiv) */
};

static int ib_path_compare_rates(IN const int rate1, IN const int rate2)
{
	int orate1 = 0, orate2 = 0;

	SSA_ASSERT(rate1 >= IB_MIN_RATE && rate1 <= IB_MAX_RATE);
	SSA_ASSERT(rate2 >= IB_MIN_RATE && rate2 <= IB_MAX_RATE);

	if (rate1 <= IB_MAX_RATE)
		orate1 = ordered_rates[rate1];
	if (rate2 <= IB_MAX_RATE)
		orate2 = ordered_rates[rate2];
	if (orate1 < orate2)
		return -1;
	if (orate1 == orate2)
		return 0;
	return 1;
}

inline static size_t get_dataset_count(const struct ssa_db_smdb *p_ssa_db_smdb,
		unsigned int table_id)
{
	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(table_id < SSA_TABLE_ID_MAX);
	SSA_ASSERT(&p_ssa_db_smdb->db_tables[table_id]);

	return ntohll(p_ssa_db_smdb->db_tables[table_id].set_count);
}

static const struct ep_guid_to_lid_tbl_rec *find_guid_to_lid_rec_by_guid(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be64_t port_guid)
{
	size_t i = 0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = NULL;
	size_t count = 0;

	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(port_guid);

	p_guid_to_lid_tbl = (struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_GUID_TO_LID];
	SSA_ASSERT(p_guid_to_lid_tbl);

	count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);

	for (i = 0; i < count; i++) {
		if (port_guid == p_guid_to_lid_tbl[i].guid) 
			return p_guid_to_lid_tbl + i;
	}

	SSA_PR_LOG_ERROR("GUID to LID record is not found. GUID: 0x%016"PRIx64,ntohll(port_guid));

	return NULL;
}


ssa_pr_status_t ssa_pr_half_world(struct ssa_db_smdb *p_ssa_db_smdb, 
		be64_t port_guid,
		ssa_pr_path_dump_t dump_clbk,
		void *clbk_prm)
{
	const struct ep_guid_to_lid_tbl_rec *p_source_rec = NULL;
	size_t guid_to_lid_count = 0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = NULL;
	size_t i = 0;
	size_t source_lids_count = 0;
	uint16_t source_base_lid = 0;
	uint16_t source_last_lid = 0;
	uint16_t source_lid = 0;

	SSA_ASSERT(port_guid);
	SSA_ASSERT(p_ssa_db_smdb);

	p_guid_to_lid_tbl = (const struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_GUID_TO_LID];
	SSA_ASSERT(p_guid_to_lid_tbl);

	guid_to_lid_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);

	p_source_rec = find_guid_to_lid_rec_by_guid(p_ssa_db_smdb,port_guid);

	if (NULL == p_source_rec) {
		SSA_PR_LOG_ERROR("GUID to LID record is not found. GUID: 0x%016"PRIx64,ntohll(port_guid));
		return SSA_PR_ERROR;
	}

	source_base_lid = ntohs(p_source_rec->lid);
	source_last_lid = source_base_lid + pow(2,p_source_rec->lmc) - 1;

	for(source_lid = source_base_lid; source_lid <= source_last_lid; ++source_lid) {
		for (i = 0; i < guid_to_lid_count; i++) {
			uint16_t dest_base_lid = 0;
			uint16_t dest_last_lid = 0;
			uint16_t dest_lid = 0;

			const struct ep_guid_to_lid_tbl_rec* p_dest_rec = p_guid_to_lid_tbl + i;
			dest_base_lid = ntohs(p_dest_rec->lid);
			dest_last_lid = dest_base_lid + pow(2,p_dest_rec->lmc) - 1;

			for(dest_lid = dest_base_lid; dest_lid <= dest_last_lid; ++dest_lid) {
				ssa_path_parms_t path_prm;
				ssa_pr_status_t path_res = SSA_PR_SUCCESS;

				path_prm.from_guid = port_guid; 
				path_prm.from_lid = htons(source_lid); 
				path_prm.to_guid = p_dest_rec->guid;
				path_prm.to_lid = htons(dest_lid);

				SSA_PR_LOG_DEBUG("Search for path: (0x%"SCNx16") -> (0x%"SCNx16")",
						source_lid,dest_lid);

				path_res = ssa_pr_path_params(p_ssa_db_smdb,p_source_rec,p_dest_rec,&path_prm);
				if(SSA_PR_SUCCESS == path_res) {
					ssa_path_parms_t revers_path_prm;
					ssa_pr_status_t revers_path_res = SSA_PR_SUCCESS;

					revers_path_prm.from_guid = path_prm.to_guid;
					revers_path_prm.from_lid = path_prm.to_lid; 
					revers_path_prm.to_guid = path_prm.from_guid;
					revers_path_prm.to_lid = path_prm.from_lid;
					revers_path_prm.reversible = 1;

					revers_path_res = ssa_pr_path_params(p_ssa_db_smdb,p_dest_rec,p_source_rec,&revers_path_prm);

					if(SSA_PR_ERROR == revers_path_res) {
						SSA_PR_LOG_INFO("Reverse path calculation is failed. Source LID 0x%"SCNx16" Destination LID: 0x%"SCNx16,source_lid,dest_lid);
					}
					else
						path_prm.reversible = SSA_PR_SUCCESS == revers_path_res;

					if(NULL != dump_clbk)
						dump_clbk(&path_prm,clbk_prm);

				} else if(SSA_PR_ERROR == path_res) {
					SSA_PR_LOG_ERROR("Path calculation is failed: (0x%"SCNx16") -> (0x%"SCNx16") "
							"\"Half World\" calculation is stopped." ,source_lid,dest_lid);
					return SSA_PR_ERROR;
				} 
			}
		}
	}
	return SSA_PR_SUCCESS;
}
										
static int find_destination_port(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be16_t source_lid,
		const be16_t dest_lid)
{
	size_t i = 0;

	struct ep_lft_top_tbl_rec *p_lft_top_tbl = NULL;
	size_t lft_top_count = 0;

	struct ep_lft_block_tbl_rec *p_lft_block_tbl = NULL;
	size_t lft_block_count = 0;

	size_t lft_block_num = 0;
	size_t lft_port_num = 0;

	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(source_lid);
	SSA_ASSERT(dest_lid);

	p_lft_top_tbl = (struct ep_lft_top_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LFT_TOP];
	SSA_ASSERT(p_lft_top_tbl);

	p_lft_block_tbl =(struct ep_lft_block_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LFT_BLOCK];
	SSA_ASSERT(p_lft_block_tbl);

	lft_top_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LFT_TOP);
	lft_block_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LFT_BLOCK);

	lft_block_num = floorl(ntohs(dest_lid) / IB_SMP_DATA_SIZE);
	lft_port_num = ntohs(dest_lid) % IB_SMP_DATA_SIZE;

	for (i = 0; i < lft_top_count && source_lid != p_lft_top_tbl[i].lid; i++);
	if(i >= lft_top_count) {
		SSA_PR_LOG_ERROR("LFT routing is failed. LFT top is not found. "
				"Source LID (0x%"SCNx16") Destination LID: (0x%"SCNx16")",
			ntohs(source_lid));
		return -1;
	}
	if(i >= lft_top_count || ntohs(dest_lid) > ntohs(p_lft_top_tbl[i].lft_top)) {
		SSA_PR_LOG_ERROR("LFT routing is failed. Destination LID exceeds LFT top . "
				"Source LID (0x%"SCNx16") Destination LID: (0x%"SCNx16") LFT top: %u",
			ntohs(source_lid),ntohs(dest_lid),p_lft_top_tbl[i].lft_top);
		return -1;
	}

	for (i = 0;i < lft_block_count;++i) 
		if(source_lid == p_lft_block_tbl[i].lid && lft_block_num == ntohs(p_lft_block_tbl[i].block_num))
			return p_lft_block_tbl[i].block[lft_port_num];

	return LFT_NO_PATH ;
}

static const struct ep_port_tbl_rec *find_port(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be16_t lid,
		const int port_num)
{
	size_t i = 0;
	const struct ep_port_tbl_rec  *p_port_tbl = NULL;
	size_t count = 0;

	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(lid);

	p_port_tbl = (const struct ep_port_tbl_rec*)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_PORT];
	SSA_ASSERT(p_port_tbl );

	count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_PORT);

	for (i = 0; i < count; i++) {
		if(p_port_tbl[i].port_lid == lid &&
				(!(p_port_tbl[i].rate & SSA_DB_PORT_IS_SWITCH_MASK) || port_num == p_port_tbl[i].port_num))
				return p_port_tbl + i;
	}

	if(port_num >= 0) {
		SSA_PR_LOG_ERROR("Port is not found. LID: 0x%"SCNx16" Port num: %d",
			   ntohs(lid),port_num);
	} else {
		SSA_PR_LOG_ERROR("Port is not found. LID: 0x%"SCNx16,ntohs(lid));
	}

	return NULL;
}

static inline const struct ep_port_tbl_rec *get_switch_port(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be16_t switch_lid,
		const int port_num)
{
	return find_port(p_ssa_db_smdb,switch_lid,port_num);
}

static inline const struct ep_port_tbl_rec *get_host_port(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be16_t lid)
{
	/*
	 * For host there is only one record in port table.
	 * Port num is not relevant
	 * */
	return find_port(p_ssa_db_smdb,lid,-1);
}

static const struct ep_link_tbl_rec *find_link(const struct ssa_db_smdb *p_ssa_db_smdb,
		const be16_t lid,
		const int port_num)
{
	size_t i = 0;
	const struct ep_link_tbl_rec  *p_link_tbl =  NULL;
	size_t link_count = 0;

	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(lid);

	p_link_tbl = (const struct ep_link_tbl_rec*)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LINK];
	SSA_ASSERT(p_link_tbl);

	link_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LINK);

	for (i = 0;i < link_count;i++)
		if(lid == p_link_tbl[i].from_lid && (port_num < 0 || port_num == p_link_tbl[i].from_port_num))
			return p_link_tbl + i;

	if(port_num >= 0) {
		SSA_PR_LOG_ERROR("Link is not found. LID: 0x%"SCNx16" Port num: %u",
			   ntohs(lid),port_num);
	} else {
		SSA_PR_LOG_ERROR("Link is not found. LID: 0x%"SCNx16,ntohs(lid));
	}

	return NULL;
}

static ssa_pr_status_t ssa_pr_path_params(const struct ssa_db_smdb *p_ssa_db_smdb,
		const struct ep_guid_to_lid_tbl_rec *p_source_rec,
		const struct ep_guid_to_lid_tbl_rec *p_dest_rec,
		ssa_path_parms_t *p_path_prm)
{
	int source_port_num = -1; 
	const struct ep_port_tbl_rec *source_port = NULL;
	const struct ep_port_tbl_rec *dest_port = NULL;
	const struct ep_port_tbl_rec *port = NULL;
	const struct ep_subnet_opts_tbl_rec *opt_rec = NULL;

	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(p_source_rec);
	SSA_ASSERT(p_dest_rec);
	SSA_ASSERT(p_path_prm);

	opt_rec = 
		(const struct ep_subnet_opts_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_SUBNET_OPTS];
	SSA_ASSERT(opt_rec);

	if(p_source_rec->is_switch) 
		source_port = get_switch_port(p_ssa_db_smdb,p_source_rec->lid,0);
	else
		source_port = get_host_port(p_ssa_db_smdb,p_source_rec->lid);
	if(NULL == source_port) {
		SSA_PR_LOG_ERROR("Source port is not found. Path record calculation is stopped."
			   " LID: 0x%"SCNx16,htons(p_source_rec->lid));
		return SSA_PR_ERROR;
	}

	if(p_dest_rec->is_switch)
		dest_port = get_switch_port(p_ssa_db_smdb,p_dest_rec->lid,0);	
	else
		dest_port = get_host_port(p_ssa_db_smdb,p_dest_rec->lid);
	if(NULL == dest_port) {
		SSA_PR_LOG_ERROR("Destination port is not found. Path record calculation is stopped."
			   " LID: 0x%"SCNx16,htons(p_dest_rec->lid));
		return SSA_PR_ERROR;
	}

	p_path_prm->pkt_life = source_port == dest_port ? 0 : opt_rec[0].subnet_timeout;
	p_path_prm->mtu = source_port->neighbor_mtu;
	p_path_prm->rate = source_port->rate & SSA_DB_PORT_RATE_MASK;
	p_path_prm->pkt_life = 0;
	p_path_prm->hops = 0;

	if(p_source_rec->is_switch) {
		const int out_port_num = find_destination_port(p_ssa_db_smdb,
				p_source_rec->lid,p_dest_rec->lid);
		if(out_port_num  < 0) {
			SSA_PR_LOG_ERROR("Failed to faind outgoing port for LID: 0x%"SCNx16
					" on switch LID: 0x%"SCNx16". "
					"Path record calculation is sttoped."
					,htons(p_dest_rec->lid),htons(p_source_rec->lid));
			return SSA_PR_ERROR;
		} else if(LFT_NO_PATH == source_port_num) {
			SSA_PR_LOG_DEBUG("There is no path from LID: 0x%"SCNx16" to LID: 0x%"SCNx16" .",
					htons(p_source_rec->lid),htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}

		port = find_port(p_ssa_db_smdb,p_source_rec->lid,out_port_num);	
		if(NULL == port) {
			SSA_PR_LOG_ERROR("Port is not found. Path record calculation is stopped."
					" LID: 0x%"SCNx16" num: %u",htons(p_source_rec->lid),out_port_num);
			return SSA_PR_ERROR;
		}
	} else {
		port = source_port;
	}

	while(port != dest_port) {
		const struct ep_link_tbl_rec *link_rec = find_link(p_ssa_db_smdb,port->port_lid,
				port->rate &  SSA_DB_PORT_IS_SWITCH_MASK ? port->port_num:-1);
		int out_port_num = -1;

		if(NULL == link_rec) {
			SSA_PR_LOG_ERROR("There is no link from port LID: 0x%"SCNx16" num: %u. "
					"Path record calculation is stopped",
					ntohs(port->port_lid),
					port->port_num);
			return SSA_PR_ERROR;
		}

		port = find_port(p_ssa_db_smdb,link_rec->to_lid,link_rec->to_port_num);
		if(NULL == port) {
			SSA_PR_LOG_ERROR("Port is not found. Path record calculation is stopped."
					" LID: 0x%"SCNx16" num: %u",htons(link_rec->to_lid),link_rec->to_port_num);
			return SSA_PR_ERROR;
		}

		if(port == dest_port)
			break;

		if(!(port->rate & SSA_DB_PORT_IS_SWITCH_MASK)) {
			SSA_PR_LOG_ERROR("Error: Internal error, bad path while routing "
				"(GUID: 0x%016"PRIx64") port %d to "
				"(GUID: 0x%016"PRIx64") port %d; "
				"ended at (LID: 0x%04"SCNx16") port %d",
					ntohll(p_source_rec->guid),source_port->port_num,
					ntohll(p_dest_rec->guid),dest_port->port_num,
					ntohs(port->port_lid),port->port_num);

			return SSA_PR_ERROR;
		}	

		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		if(ib_path_compare_rates(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
			p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;

		out_port_num  = find_destination_port(p_ssa_db_smdb,link_rec->to_lid,p_dest_rec->lid);
		if(LFT_NO_PATH == out_port_num){
			SSA_PR_LOG_DEBUG("There is no path from LID: 0x%"SCNx16" to LID: 0x%"SCNx16" .",
					htons(p_source_rec->lid),htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}

		port = find_port(p_ssa_db_smdb,link_rec->to_lid,out_port_num);
		if(NULL == port) {
			SSA_PR_LOG_ERROR("Port is not found. Path record calculation is stopped."
					" LID: 0x%"SCNx16" num: %u",
					htons(link_rec->to_lid),out_port_num);
			return SSA_PR_ERROR;
		}

		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		if(ib_path_compare_rates(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
			p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;
		p_path_prm->hops++;

		if (p_path_prm->hops > MAX_HOPS) {
			SSA_PR_LOG_ERROR(
				"Path from GUID 0x%016" PRIx64 " (port %d) "
				"to lid %u GUID 0x%016" PRIx64 " (port %d) "
				"needs more than %d hops, max %d hops allowed.",
				ntohll(p_source_rec->guid),source_port->port_num,
				ntohs(p_dest_rec->lid),ntohll(p_dest_rec->guid),
				dest_port->port_num,
				p_path_prm->hops,
				MAX_HOPS);
			return SSA_PR_ERROR;	
		}
	}

	p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
	if(ib_path_compare_rates(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
		p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;

	return SSA_PR_SUCCESS;
}
const char* get_time()
{
	static char buffer[64] = {};
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", timeinfo);

	return buffer;
}
