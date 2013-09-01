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
#include <ssa_smdb.h>
#include "ssa_path_record.h"

#define MIN(X,Y) ((X) < (Y) ?  (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ?  (X) : (Y))

#define MAX_HOPS 64
#define LFT_NO_PATH 255

FILE *flog1 = NULL;


static ssa_pr_status_t ssa_pr_path_params(const struct ssa_db_smdb* p_ssa_db_smdb,
		const struct ep_guid_to_lid_tbl_rec *p_source_rec,
		const struct ep_guid_to_lid_tbl_rec *p_dest_rec,
		ssa_path_parms_t* p_path_prm);


static size_t get_dataset_count(const struct ssa_db_smdb* p_ssa_db_smdb,
		unsigned int table_id)
{
	const struct db_dataset *p_dataset = &p_ssa_db_smdb->db_tables[table_id];
	return ntohll(p_dataset->set_count);
}
/*
typedef int record_cmp(const void*,const void*);
static void* find_record(const struct ssa_db_smdb* p_ssa_db_smdb,
		const unsigned int table_id,
		const size_t record_size,
		record_cmp cmp,
		const void* prm)
{
	size_t i =0 ;
	const size_t count = get_dataset_count(p_ssa_db_smdb,table_id);

	for (i = 0; i < count; i++) {
		if(cmp(p_ssa_db_smdb->p_tables[table_id]+count*record_size,prm))
			return p_ssa_db_smdb->p_tables[table_id]+count*record_size;
	}
	return NULL;
}

static int node_guid_cmp(const void* record, const void* prm)
{
	struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = 
		(ep_guid_to_lid_tbl_rec*)record;
	return ntohs(record->guid) == *(uint64_t*)prm; 
}
*/

static const struct ep_guid_to_lid_tbl_rec* find_guid_to_lid_rec_by_guid(const struct ssa_db_smdb* p_ssa_db_smdb,
		const be64_t port_guid)
{
	size_t i =0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = 
		(struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_GUID_TO_LID];
	const size_t count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);

	for (i = 0; i < count; i++) {
		if (port_guid == p_guid_to_lid_tbl[i].guid) 
			return p_guid_to_lid_tbl+i;
	}
	return NULL;
}

static const struct ep_guid_to_lid_tbl_rec* find_guid_to_lid_rec_by_lid(const struct ssa_db_smdb* p_ssa_db_smdb,
		const be16_t base_lid)
{
	size_t i =0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = 
		(struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_GUID_TO_LID];
	const size_t count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);

	for (i = 0; i < count; i++) {
		if (base_lid == p_guid_to_lid_tbl[i].lid) 
			return p_guid_to_lid_tbl+i;
	}
	return NULL;
}

ssa_pr_status_t ssa_pr_half_world(struct ssa_db_smdb* p_ssa_db_smdb, 
		be64_t port_guid,
		ssa_pr_path_dump_t dump_clbk,
		void *clbk_prm)
{
	const struct ep_guid_to_lid_tbl_rec *p_source_rec = NULL;
	const size_t guid_to_lid_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl =
		        (const struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_GUID_TO_LID];
	size_t i = 0;
	unsigned int source_lids_count = 0;
	uint16_t source_base_lid = 0;
	uint16_t source_last_lid = 0;
	uint16_t source_lid = 0;

	p_source_rec = find_guid_to_lid_rec_by_guid(p_ssa_db_smdb,port_guid);

	if (NULL == p_source_rec) {
		return SSA_PR_ERROR;
	}

	source_base_lid = ntohs(p_source_rec->lid);
	source_last_lid = source_base_lid + pow(2,p_source_rec->lmc) -1;


	for(source_lid = source_base_lid ; source_lid<=source_last_lid; ++source_lid){
		ssa_log(SSA_LOG_VERBOSE,"%s 0x%"PRIx64", base LID %"SCNu16"\n",!p_source_rec->is_switch?"Channel Adapter":"Switch",
				port_guid,source_lid);
		ssa_log(SSA_LOG_VERBOSE,"# LID  : SL : MTU : RATE\n");
		for (i = 0; i < guid_to_lid_count; i++) {
			uint16_t dest_base_lid = 0;
			uint16_t dest_last_lid = 0;
			uint16_t dest_lid = 0;

			const struct ep_guid_to_lid_tbl_rec* p_dest_rec = p_guid_to_lid_tbl+i;
			dest_base_lid = ntohs(p_dest_rec->lid);
			dest_last_lid = dest_base_lid + pow(2, p_dest_rec->lmc) - 1;

			for(dest_lid = dest_base_lid ; dest_lid<=dest_last_lid; ++dest_lid){
				ssa_path_parms_t path_prm;
				ssa_pr_status_t path_res = SSA_PR_SUCCESS;

				path_prm.from_guid = port_guid; 
				path_prm.from_lid = htons(source_lid); 
				path_prm.to_guid = p_dest_rec->guid;
				path_prm.to_lid = htons(dest_lid);

				path_res = ssa_pr_path_params(p_ssa_db_smdb,p_source_rec,p_dest_rec,&path_prm);
				if(SSA_PR_SUCCESS == path_res ){
					ssa_path_parms_t revers_path_prm;
					ssa_pr_status_t revers_path_res = SSA_PR_SUCCESS;

					revers_path_prm.from_guid = path_prm.to_guid;
					revers_path_prm.from_lid = path_prm.to_lid; 
					revers_path_prm.to_guid = path_prm.from_guid;
					revers_path_prm.to_lid = path_prm.from_lid;

					revers_path_res = ssa_pr_path_params(p_ssa_db_smdb,p_dest_rec,p_source_rec,&revers_path_prm) ;

					if(SSA_PR_ERROR == revers_path_res)
						ssa_log(SSA_LOG_VERBOSE,"Error. Path calculation is failed. Source LID 0x%"SCNu16" Destination LID: 0x%"SCNu16"\n",source_lid,dest_lid );
					else
						path_prm.reversible = SSA_PR_SUCCESS == revers_path_res ;
					ssa_log(SSA_LOG_VERBOSE,"0x%04"SCNx16" : %3u : %3u : %3u\n",dest_lid,0,path_prm.mtu,path_prm.rate);

					if(NULL!=dump_clbk)
						dump_clbk(&path_prm,clbk_prm);
				}else if(SSA_PR_ERROR == path_res)
					ssa_log(SSA_LOG_VERBOSE,"Path record calucation is failed. Source LID: %"SCNu16", dest LID: %"SCNu16"\n"); 
				
			}
		}
	}
	return SSA_PR_SUCCESS;
}
										
static int find_destination_port(const struct ssa_db_smdb* p_ssa_db_smdb,
		const be16_t source_lid,
		const be16_t dest_lid)
{
	size_t i =0;

	struct ep_lft_top_tbl_rec *p_lft_top_tbl = 
		(struct ep_lft_top_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LFT_TOP];
	const size_t lft_top_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LFT_TOP);

	struct ep_lft_block_tbl_rec *p_lft_block_tbl = 
		(struct ep_lft_block_tbl_rec *)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LFT_BLOCK];
	const size_t lft_block_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LFT_BLOCK);

	const size_t lft_block_num = floorl(ntohs(dest_lid)/IB_SMP_DATA_SIZE);
	const size_t lft_port_num = ntohs(dest_lid)%IB_SMP_DATA_SIZE;

//	ssa_log(SSA_LOG_VERBOSE,"Source lid: %"SCNx16" Destination lid: %"SCNx16" lft block num: %u lft port num: %u\n",
//			source_lid,dest_lid,lft_block_num,lft_port_num);

	for (i = 0; i < lft_top_count && source_lid !=p_lft_top_tbl[i].lid ; i++);
	if(i >= lft_top_count || dest_lid > p_lft_top_tbl[i].lft_top){
		ssa_log(SSA_LOG_VERBOSE,"Error: Source lid: %"SCNx16" Destination lid: %"SCNx16" Current lft top block index: %u top lid in the block: %u\n",
			source_lid,i,p_lft_top_tbl[i].lft_top);
		return -1;
	}

	for (i = 0; i < lft_block_count;++i ) 
		if(source_lid == p_lft_block_tbl[i].lid && lft_block_num == ntohs(p_lft_block_tbl[i].block_num))
			return p_lft_block_tbl[i].block[lft_port_num];

	ssa_log(SSA_LOG_VERBOSE,"Path not found.  Switch lid: %"SCNx16" Destination lid: %"SCNx16" block index: %u index in  the block: %u\n",
			source_lid,dest_lid,ntohs(lft_block_num),lft_port_num);

	return LFT_NO_PATH ;
}

static const struct ep_port_tbl_rec* find_port(const struct ssa_db_smdb* p_ssa_db_smdb,
		const be16_t lid,
		const int port_num)
{
	size_t i = 0;
	const struct ep_port_tbl_rec  *p_port_tbl = 
		(const struct ep_port_tbl_rec*)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_PORT];
	const size_t count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_PORT);

	for (i = 0; i < count; i++){
		if(p_port_tbl[i].port_lid==lid && 
				(!(p_port_tbl[i].rate & SSA_DB_PORT_IS_SWITCH_MASK) || port_num == p_port_tbl[i].port_num))
			return p_port_tbl+i;
	}
	return NULL;
}

static const struct ep_link_tbl_rec* find_link(const struct ssa_db_smdb* p_ssa_db_smdb,
		const be16_t lid,
		const int port_num)
{
	size_t i = 0;
	const struct ep_link_tbl_rec  *p_link_tbl = 
		(const struct ep_link_tbl_rec*)p_ssa_db_smdb->p_tables[SSA_TABLE_ID_LINK];
	const size_t link_count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_LINK);

	for (i = 0; i < link_count; i++)
		if(lid==p_link_tbl[i].from_lid && (port_num<0 || port_num == p_link_tbl[i].from_port_num))
			return p_link_tbl+i;

	return NULL;
}

static ssa_pr_status_t ssa_pr_path_params(const struct ssa_db_smdb* p_ssa_db_smdb,
		const struct ep_guid_to_lid_tbl_rec *p_source_rec,
		const struct ep_guid_to_lid_tbl_rec *p_dest_rec,
		ssa_path_parms_t* p_path_prm)
{
	int source_port_num = -1 ; 
	int dest_port_num = -1 ;
	const struct ep_port_tbl_rec *source_port = NULL ;
	const struct ep_port_tbl_rec *dest_port = NULL ;
	const struct ep_port_tbl_rec *port = NULL ;

	p_path_prm->mtu = 0 ;
	p_path_prm->rate = 0 ;
	p_path_prm->pkt_life = 0 ;
	p_path_prm->hops = 0;

//	ssa_log(SSA_LOG_VERBOSE,"Compute path: (0x%"SCNx16") - (0x%"SCNx16")\n",ntohs(p_source_rec->lid),ntohs(p_dest_rec->lid));

	if(p_source_rec->is_switch){
		source_port_num = find_destination_port(p_ssa_db_smdb,p_source_rec->lid,p_dest_rec->lid);
		//ssa_log(SSA_LOG_VERBOSE,"Source %"SCNx16" is switch. Destination port is: %d\n",ntohs(p_source_rec->lid),source_port_num);
		if(source_port_num < 0){
			ssa_log(SSA_LOG_VERBOSE,"Error: Destination port is not found. Switch lid:%"SCNx16" , Destination lid:%"SCNx16"\n",
					htons(p_source_rec->lid),htons(p_dest_rec->lid));
			return SSA_PR_ERROR;
		}else if( LFT_NO_PATH == source_port_num){
			ssa_log(SSA_LOG_VERBOSE,"No path found. Switch LID:%"SCNu16" Destination LID:%"SCNu16" \n",htons(p_source_rec->lid),htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}	
	}

	dest_port_num = p_dest_rec->is_switch ? 0 : -1 ;

	source_port = find_port(p_ssa_db_smdb,p_source_rec->lid,source_port_num);
	dest_port = find_port(p_ssa_db_smdb,p_dest_rec->lid,dest_port_num);

	if(NULL == source_port){
		ssa_log(SSA_LOG_VERBOSE,"Error: Port is not found. Switch lid:%"SCNx16"\n",htons(p_source_rec->lid));
		return SSA_PR_ERROR;
	}

	if(NULL == dest_port){
		ssa_log(SSA_LOG_VERBOSE,"Error: Port is not found. Switch lid:%"SCNx16"\n",htons(p_dest_rec->lid));
		return SSA_PR_ERROR;
	}

//	ssa_log(SSA_LOG_VERBOSE,"Source: (%"SCNx16",%d) -  Destination: (%"SCNx16",%d)\n",ntohs(source_port->port_lid),source_port->port_num,
//			ntohs(dest_port->port_lid),dest_port->port_num);

	p_path_prm->pkt_life = source_port == dest_port ? 0 : p_ssa_db_smdb->subnet_timeout;
	p_path_prm->mtu = source_port->neighbor_mtu;
	p_path_prm->rate = source_port->rate & SSA_DB_PORT_RATE_MASK;

	port = source_port;
	while( port != dest_port){
		const struct ep_link_tbl_rec* link_rec = find_link(p_ssa_db_smdb,port->port_lid,
				port->rate &  SSA_DB_PORT_IS_SWITCH_MASK ? port->port_num:-1);
		//const struct ep_guid_to_lid_tbl_rec *guid_to_lid_rec = find_guid_to_lid_rec_by_lid(p_ssa_db_smdb,link_rec->to_lid);
		int outgoing_port_num = -1 ;


//		ssa_log(SSA_LOG_VERBOSE,"Current port: (%"SCNx16",%d)\n",htons(port->port_lid),port->port_num);

		if(NULL == link_rec/* || NULL == guid_to_lid_rec*/){
			ssa_log(SSA_LOG_VERBOSE,"Error: Link record is not found\n");
			return SSA_PR_ERROR;
		}

//		ssa_log(SSA_LOG_VERBOSE,"Link: (%"SCNx16",%d) - (%"SCNx16",%d)\n",htons(link_rec->from_lid),link_rec->from_port_num,
//			htons(link_rec->to_lid),link_rec->to_port_num);

		port = find_port(p_ssa_db_smdb,link_rec->to_lid,link_rec->to_port_num);
		if(NULL == port){
			ssa_log(SSA_LOG_VERBOSE,"Error: Port is not found. lid:%"SCNx16" , port num:%u\n",
					htons(link_rec->to_lid),link_rec->to_port_num);
			return SSA_PR_ERROR;
		}

		if(port == dest_port){
			//ssa_log(SSA_LOG_VERBOSE,"Destination port is reached\n");
			break;
		}

		//if(!guid_to_lid_rec->is_switch)
		//	return SSA_PR_ERROR;
		if(!(port->rate & SSA_DB_PORT_IS_SWITCH_MASK)){
			ssa_log(SSA_LOG_VERBOSE,"Error: Next port is not switch\n");
			return SSA_PR_ERROR;
		}	

		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		p_path_prm->rate = MIN(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK);

		outgoing_port_num  = find_destination_port(p_ssa_db_smdb,link_rec->to_lid,p_dest_rec->lid);
		if( LFT_NO_PATH == outgoing_port_num){
			ssa_log(SSA_LOG_VERBOSE,"No path found. Switch LID:%"SCNu16" Destination LID:%"SCNu16" \n",htons(link_rec->to_lid),htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}

//		ssa_log(SSA_LOG_VERBOSE,"Outgoing port num:%u\n",outgoing_port_num);

		port = find_port(p_ssa_db_smdb,link_rec->to_lid,outgoing_port_num);
		if(NULL == port){
			ssa_log(SSA_LOG_VERBOSE,"Error: Port is not found. lid:%"SCNx16" , port num:%u\n",
					htons(link_rec->to_lid),outgoing_port_num);
			return SSA_PR_ERROR;
		}
//		ssa_log(SSA_LOG_VERBOSE,"Outgoing port. lid:  lid:%"SCNx16" , port num:%u\n", htons(port->port_lid),port->port_num);


		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		p_path_prm->rate = MIN(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK);
		p_path_prm->hops++;

		if (p_path_prm->hops > MAX_HOPS){
			ssa_log(SSA_LOG_VERBOSE,"Error: Max hops number is reached. %d\n",MAX_HOPS);
			return SSA_PR_ERROR;	
		}
	}

//	ssa_log(SSA_LOG_VERBOSE,"Path: mtu:%u rate:%u hops:%u \n",p_path_prm->mtu,p_path_prm->rate,p_path_prm->hops);

	return SSA_PR_SUCCESS;
}

int  ssa_open_log1(char *log_file)
{
	char buffer[256]={};

	if(flog1)
		return 0;

	// TODO: Remove this
	flog1 = stdout;
	return 0;

	sprintf(buffer, "%s/%s",".", log_file);
	flog1 = fopen(buffer, "aw");
	if (!(flog1)) {
		fprintf(stderr, 
				"SSA Access Layer: Failed to open output file \"%s\"\n",
				buffer);
		return -1;
	}
	return 0;
}

void ssa_close_log1(void)
{
	fclose(flog1);
	flog1 = NULL ;
}

void ssa_write_log1(int level, const char *format, ...)
{
	va_list args;
	char buffer[256];

	va_start(args, format);
	vsprintf(buffer, format, args);
	fprintf_log(flog1, buffer);
	fflush(flog1);
	va_end(args);
}

