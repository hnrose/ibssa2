/*
 * Copyright 2004-2014 Mellanox Technologies LTD. All rights reserved.
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
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <assert.h>
#include <math.h>
#include <infiniband/ssa_db.h>
#include <infiniband/ssa_smdb.h>
#include <infiniband/ssa_prdb.h>
#include <infiniband/ssa_path_record.h>
#include "ssa_path_record_helper.h"
#include "ssa_path_record_data.h"

#ifndef MIN
#define MIN(X,Y) ((X) < (Y) ?  (X) : (Y))
#endif
#ifndef MAX
#define MAX(X,Y) ((X) > (Y) ?  (X) : (Y))
#endif

#define MAX_HOPS 64
#define PK_DEFAULT_VAL ntohs(0xffff)
#define SL_DEFAULT_VAL 0

struct ssa_pr_context {
	struct ssa_pr_smdb_index *p_index;
};

static
ssa_pr_status_t ssa_pr_path_params(const struct ssa_db *p_ssa_db_smdb,
				   const struct ssa_pr_context *p_context,
				   const struct ep_guid_to_lid_tbl_rec *p_source_rec,
				   const struct ep_guid_to_lid_tbl_rec *p_dest_rec,
				   ssa_path_parms_t *p_path_prm);

inline static size_t get_dataset_count(const struct ssa_db *p_ssa_db_smdb,
				       unsigned int table_id)
{
	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(table_id < SSA_TABLE_ID_MAX);
	SSA_ASSERT(&p_ssa_db_smdb->p_db_tables[table_id]);

	return ntohll(p_ssa_db_smdb->p_db_tables[table_id].set_count);
}

static void insert_pr_to_prdb(const ssa_path_parms_t *p_path_prm, void *prm)
{
	struct ssa_db *p_prdb = NULL;
	struct db_dataset *p_dataset = NULL;
	uint64_t set_size = 0, set_count = 0;
	struct ep_pr_tbl_rec *p_rec = NULL;

	p_prdb = (struct ssa_db*)prm;
	SSA_ASSERT(p_prdb);

	p_dataset = p_prdb->p_db_tables + SSA_PR_TABLE_ID;
	SSA_ASSERT(p_dataset);

	set_size = ntohll(p_dataset->set_size);
	set_count = ntohll(p_dataset->set_count);

	p_rec = ((struct ep_pr_tbl_rec *)p_prdb->pp_tables[SSA_PR_TABLE_ID]) + set_count;
	SSA_ASSERT(p_rec);

	p_rec->guid = p_path_prm->to_guid;
	p_rec->lid = p_path_prm->to_lid;
	p_rec->pk = p_path_prm->pkey;
	p_rec->mtu = p_path_prm->mtu;
	p_rec->rate = p_path_prm->rate;
	p_rec->sl = p_path_prm->sl;
	p_rec->is_reversible = p_path_prm->reversible;

	set_size += sizeof(struct ep_pr_tbl_rec);
	set_count++;

	p_dataset->set_count = htonll(set_count);
	p_dataset->set_size = htonll(set_size);
}

ssa_pr_status_t ssa_pr_half_world(struct ssa_db *p_ssa_db_smdb, void *p_ctnx,
				  be64_t port_guid,
				  ssa_pr_path_dump_t dump_clbk, void *clbk_prm)
{
	const struct ep_guid_to_lid_tbl_rec *p_source_rec = NULL;
	size_t guid_to_lid_count = 0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = NULL;
	size_t i = 0;
	size_t source_lids_count = 0;
	uint16_t source_base_lid = 0;
	uint16_t source_last_lid = 0;
	uint16_t source_lid = 0;
	struct ssa_pr_context *p_context = (struct ssa_pr_context *)p_ctnx;
	clock_t start, end;
	double cpu_time_used;

	SSA_ASSERT(port_guid);
	SSA_ASSERT(p_ssa_db_smdb);
	SSA_ASSERT(p_context);

	if (ssa_pr_rebuild_indexes(p_context->p_index, p_ssa_db_smdb)) {
		SSA_PR_LOG_ERROR("Index rebuild failed.");
		return SSA_PR_ERROR;
	}

	p_guid_to_lid_tbl = (const struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_GUID_TO_LID];
	SSA_ASSERT(p_guid_to_lid_tbl);

	guid_to_lid_count = get_dataset_count(p_ssa_db_smdb,
					      SSA_TABLE_ID_GUID_TO_LID);

	p_source_rec = find_guid_to_lid_rec_by_guid(p_ssa_db_smdb, port_guid);
	if (NULL == p_source_rec) {
		SSA_PR_LOG_ERROR("GUID to LID record not found. GUID: 0x%016" PRIx64,
				 ntohll(port_guid));
		return SSA_PR_ERROR;
	}

	source_base_lid = ntohs(p_source_rec->lid);
	source_last_lid = source_base_lid + pow(2, p_source_rec->lmc) - 1;

	for (source_lid = source_base_lid; source_lid <= source_last_lid; ++source_lid) {
		start = clock();
		for (i = 0; i < guid_to_lid_count; i++) {
			uint16_t dest_base_lid = 0;
			uint16_t dest_last_lid = 0;
			uint16_t dest_lid = 0;

			const struct ep_guid_to_lid_tbl_rec* p_dest_rec = p_guid_to_lid_tbl + i;
			dest_base_lid = ntohs(p_dest_rec->lid);
			dest_last_lid = dest_base_lid +
					pow(2, p_dest_rec->lmc) - 1;

			for (dest_lid = dest_base_lid; dest_lid <= dest_last_lid; ++dest_lid) {
				ssa_path_parms_t path_prm;
				ssa_pr_status_t path_res = SSA_PR_SUCCESS;

				path_prm.from_guid = port_guid;
				path_prm.from_lid = htons(source_lid);
				path_prm.to_guid = p_dest_rec->guid;
				path_prm.to_lid = htons(dest_lid);
				path_prm.sl = SL_DEFAULT_VAL;
				path_prm.pkey = PK_DEFAULT_VAL;

				path_res = ssa_pr_path_params(p_ssa_db_smdb,
							      p_context,
							      p_source_rec,
							      p_dest_rec,
							      &path_prm);
				if (SSA_PR_SUCCESS == path_res) {
					ssa_path_parms_t revers_path_prm;
					ssa_pr_status_t revers_path_res = SSA_PR_SUCCESS;

					revers_path_prm.from_guid = path_prm.to_guid;
					revers_path_prm.from_lid = path_prm.to_lid;
					revers_path_prm.to_guid = path_prm.from_guid;
					revers_path_prm.to_lid = path_prm.from_lid;
					revers_path_prm.reversible = 1;
					revers_path_prm.sl = SL_DEFAULT_VAL;
					revers_path_prm.pkey= PK_DEFAULT_VAL;

					revers_path_res = ssa_pr_path_params(p_ssa_db_smdb,
									     p_context,
									     p_dest_rec,
									     p_source_rec,
									     &revers_path_prm);

					if (SSA_PR_ERROR == revers_path_res) {
						SSA_PR_LOG_INFO("Reverse path calculation failed. Source LID 0x%" SCNx16 " Destination LID: 0x%" SCNx16,
								source_lid,
								dest_lid);
					} else
						path_prm.reversible = SSA_PR_SUCCESS == revers_path_res;

					if (NULL != dump_clbk)
						dump_clbk(&path_prm, clbk_prm);

				} else if (SSA_PR_ERROR == path_res) {
					SSA_PR_LOG_ERROR("Path calculation failed: (0x%" SCNx16 ") -> (0x%" SCNx16 ") "
							 "\"Half World\" calculation stopped.",
							 source_lid, dest_lid);
					return SSA_PR_ERROR;
				}
			}
		}
		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		SSA_PR_LOG_DEBUG("\"half world\" path records for: 0x%" SCNx16
				 " time: %f sec.", source_lid, cpu_time_used);
	}
	return SSA_PR_SUCCESS;
}

struct ssa_db *ssa_pr_compute_half_world(struct ssa_db *p_ssa_db_smdb,
					 void *p_ctnx, be64_t port_guid)
{
	struct ssa_db *p_prdb = NULL;
	uint64_t record_num = 0;
	size_t guid_to_lid_count = 0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = NULL;
	const struct ep_guid_to_lid_tbl_rec *p_curr_rec = NULL;
	size_t i = 0;
	ssa_pr_status_t res = SSA_PR_SUCCESS;
	uint16_t source_base_lid = 0;
	uint16_t source_last_lid = 0;

	SSA_ASSERT(p_ssa_db_smdb);

	p_guid_to_lid_tbl = (const struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_GUID_TO_LID];
	SSA_ASSERT(p_guid_to_lid_tbl);

	guid_to_lid_count = get_dataset_count(p_ssa_db_smdb,
					      SSA_TABLE_ID_GUID_TO_LID);
	record_num = guid_to_lid_count * guid_to_lid_count * 2;

	p_prdb = ssa_prdb_create(record_num);
	if (!p_prdb) {
		SSA_PR_LOG_ERROR("Path record database creation failed."
				 " Number of records: %ll", record_num);
		return NULL;
	}

	res = ssa_pr_half_world(p_ssa_db_smdb, p_ctnx, port_guid,
				insert_pr_to_prdb,p_prdb);
	if (SSA_PR_ERROR == res) {
		SSA_PR_LOG_ERROR("\"Half world\" calculation failed for GUID: 0x%" PRIx64,
				 ntohll(port_guid));
		goto Error;
	}
	return p_prdb;

Error:
	if (p_prdb) {
		ssa_db_destroy(p_prdb);
		return NULL;
	}
}

ssa_pr_status_t ssa_pr_whole_world(struct ssa_db *p_ssa_db_smdb,
				   void *context, ssa_pr_path_dump_t dump_clbk,
				   void *clbk_prm)
{
	size_t i = 0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl = NULL;
	size_t count = 0;
	ssa_pr_status_t res = SSA_PR_SUCCESS;

	SSA_ASSERT(p_ssa_db_smdb);

	p_guid_to_lid_tbl = (struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_GUID_TO_LID];
	SSA_ASSERT(p_guid_to_lid_tbl);

	count = get_dataset_count(p_ssa_db_smdb, SSA_TABLE_ID_GUID_TO_LID);

	for (i = 0; i < count; i++) {
		res = ssa_pr_half_world(p_ssa_db_smdb,context,
					p_guid_to_lid_tbl[i].guid,
					dump_clbk, clbk_prm);
		if (SSA_PR_ERROR == res) {
			SSA_PR_LOG_ERROR("\"Half world\" calculation failed for GUID: 0x%" PRIx64
					 " . \"Whole world\" calculation stopped.",
					 ntohll(p_guid_to_lid_tbl[i].guid));
			return res;
		}
	}
	return SSA_PR_SUCCESS;
}

static inline
const struct ep_port_tbl_rec *get_switch_port(const struct ssa_db *p_ssa_db_smdb,
					      const struct ssa_pr_smdb_index *p_index,
					      const be16_t switch_lid,
					      const int port_num)
{
	return find_port(p_ssa_db_smdb, p_index, switch_lid, port_num);
}

static inline
const struct ep_port_tbl_rec *get_host_port(const struct ssa_db *p_ssa_db_smdb,
					    const struct ssa_pr_smdb_index *p_index,
					    const be16_t lid)
{
	/*
	 * For host there is only one record in port table.
	 * Port num is not relevant
	 */
	return find_port(p_ssa_db_smdb, p_index, lid, -1);
}

static
ssa_pr_status_t ssa_pr_path_params(const struct ssa_db *p_ssa_db_smdb,
				   const struct ssa_pr_context *p_context,
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
	SSA_ASSERT(p_context);
	SSA_ASSERT(p_context->p_index);
	SSA_ASSERT(p_source_rec);
	SSA_ASSERT(p_dest_rec);
	SSA_ASSERT(p_path_prm);

	opt_rec = 
		(const struct ep_subnet_opts_tbl_rec *)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_SUBNET_OPTS];
	SSA_ASSERT(opt_rec);

	if (p_source_rec->is_switch)
		source_port = get_switch_port(p_ssa_db_smdb, p_context->p_index,
					      p_source_rec->lid, 0);
	else
		source_port = get_host_port(p_ssa_db_smdb, p_context->p_index,
					    p_source_rec->lid);
	if (NULL == source_port) {
		SSA_PR_LOG_ERROR("Source port not found. Path record calculation stopped."
				 " LID: 0x%" SCNx16,
				 htons(p_source_rec->lid));
		return SSA_PR_ERROR;
	}

	if (p_dest_rec->is_switch)
		dest_port = get_switch_port(p_ssa_db_smdb, p_context->p_index,
					    p_dest_rec->lid, 0);
	else
		dest_port = get_host_port(p_ssa_db_smdb, p_context->p_index,
					  p_dest_rec->lid);
	if (NULL == dest_port) {
		SSA_PR_LOG_ERROR("Destination port not found. Path record calculation stopped."
				 " LID: 0x%" SCNx16,
				 htons(p_dest_rec->lid));
		return SSA_PR_ERROR;
	}

	p_path_prm->pkt_life = source_port == dest_port ? 0 : opt_rec[0].subnet_timeout;
	p_path_prm->mtu = source_port->neighbor_mtu;
	p_path_prm->rate = source_port->rate & SSA_DB_PORT_RATE_MASK;
	p_path_prm->pkt_life = 0;
	p_path_prm->hops = 0;

	if (p_source_rec->is_switch) {
		const int out_port_num = find_destination_port(p_ssa_db_smdb,
							       p_context->p_index,
							       p_source_rec->lid,
							       p_dest_rec->lid);
		if (out_port_num  < 0) {
			SSA_PR_LOG_ERROR("Failed to find outgoing port for LID: 0x%" SCNx16
					 " on switch LID: 0x%" SCNx16 ". "
					 "Path record calculation stopped.",
					 htons(p_dest_rec->lid),
					 htons(p_source_rec->lid));
			return SSA_PR_ERROR;
		} else if (LFT_NO_PATH == out_port_num) {
			SSA_PR_LOG_DEBUG("There is no path from LID: 0x%" SCNx16 " to LID: 0x%" SCNx16" .",
					 htons(p_source_rec->lid),
					 htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}

		port = find_port(p_ssa_db_smdb, p_context->p_index,
				 p_source_rec->lid, out_port_num);
		if (NULL == port) {
			SSA_PR_LOG_ERROR("Port not found. Path record calculation stopped."
					 " LID: 0x%" SCNx16 " num: %u",
					 htons(p_source_rec->lid),
					 out_port_num);
			return SSA_PR_ERROR;
		}
	} else {
		port = source_port;
	}

	while (port != dest_port) {
		int out_port_num = -1;

		port = find_linked_port(p_ssa_db_smdb, p_context->p_index,
					port->port_lid, port->port_num);
		if (NULL == port) {
			SSA_PR_LOG_ERROR("Port not found. Path record calculation stopped.");
			return SSA_PR_ERROR;
		}

		if (port == dest_port)
			break;

		if (!(port->rate & SSA_DB_PORT_IS_SWITCH_MASK)) {
			SSA_PR_LOG_ERROR("Error: Internal error, bad path while routing "
					 "(GUID: 0x%016" PRIx64 ") port %d to "
					 "(GUID: 0x%016" PRIx64 ") port %d; "
					 "ended at (LID: 0x%04" SCNx16 ") port %d",
					 ntohll(p_source_rec->guid),
					 source_port->port_num,
					 ntohll(p_dest_rec->guid),
					 dest_port->port_num,
					 ntohs(port->port_lid),
					 port->port_num);
			return SSA_PR_ERROR;
		}

		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		if (ib_path_compare_rates_fast(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
			p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;

		out_port_num  = find_destination_port(p_ssa_db_smdb,
						      p_context->p_index,
						      port->port_lid,
						      p_dest_rec->lid);
		if (LFT_NO_PATH == out_port_num) {
			SSA_PR_LOG_DEBUG("There is no path from LID: 0x%" SCNx16 " to LID: 0x%" SCNx16 ".",
					 htons(p_source_rec->lid),
					 htons(p_dest_rec->lid));
			return SSA_PR_NO_PATH;
		}

		port = find_port(p_ssa_db_smdb, p_context->p_index,
				 port->port_lid, out_port_num);
		if (NULL == port) {
			SSA_PR_LOG_ERROR("Port not found. Path record calculation stopped."
					 " LID: 0x%" SCNx16 " num: %u",
					 htons(port->port_lid), out_port_num);
			return SSA_PR_ERROR;
		}

		p_path_prm->mtu = MIN(p_path_prm->mtu,port->neighbor_mtu);
		if(ib_path_compare_rates_fast(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
			p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;
		p_path_prm->hops++;

		if (p_path_prm->hops > MAX_HOPS) {
			SSA_PR_LOG_ERROR(
				"Path from GUID 0x%016" PRIx64 " (port %d) "
				"to lid %u GUID 0x%016" PRIx64 " (port %d) "
				"needs more than %d hops, max %d hops allowed.",
				ntohll(p_source_rec->guid),
				source_port->port_num, ntohs(p_dest_rec->lid),
				ntohll(p_dest_rec->guid), dest_port->port_num,
				p_path_prm->hops, MAX_HOPS);
			return SSA_PR_ERROR;
		}
	}

	p_path_prm->mtu = MIN(p_path_prm->mtu, port->neighbor_mtu);
	if(ib_path_compare_rates_fast(p_path_prm->rate,port->rate & SSA_DB_PORT_RATE_MASK) > 0)
		p_path_prm->rate = port->rate & SSA_DB_PORT_RATE_MASK;

	return SSA_PR_SUCCESS;
}

void *ssa_pr_create_context(FILE *log_fd, int log_level)
{
	struct ssa_pr_context *p_context = NULL;

	ssa_pr_log_level = log_level;
	ssa_pr_log_fd = log_fd;

	p_context = (struct ssa_pr_context *)malloc(sizeof(struct ssa_pr_context));
	if (!p_context) {
		SSA_PR_LOG_ERROR("Cannot allocate path record calculation context");
		goto Error;
	}

	memset(p_context,'\0',sizeof(struct ssa_pr_context));

	p_context->p_index = (struct ssa_pr_smdb_index *)malloc(sizeof(struct ssa_pr_smdb_index));
	if (!p_context->p_index) {
		SSA_PR_LOG_ERROR("Cannot allocate path record data index");
		goto Error;
	}

	memset(p_context->p_index,'\0',sizeof(struct ssa_pr_smdb_index));
	p_context->p_index->epoch = -1;

	return p_context;

Error:
	if (p_context && p_context->p_index) {
		free(p_context->p_index);
		p_context->p_index = NULL;
	}

	if (p_context) {
		free(p_context);
		p_context = NULL;
	}

	ssa_pr_log_level = 0;
	ssa_pr_log_fd = NULL;

	return NULL;
}

void ssa_pr_destroy_context(void *ctx)
{
	struct ssa_pr_context *p_context = (struct ssa_pr_context *)ctx;

	if (p_context) {
		if (p_context->p_index) {
			ssa_pr_destroy_indexes(p_context->p_index);
			free(p_context->p_index);
			p_context->p_index = NULL;
		}
		free(p_context);
		p_context = NULL;
	}

	ssa_pr_log_level = 0;
	ssa_pr_log_fd = NULL;
}
