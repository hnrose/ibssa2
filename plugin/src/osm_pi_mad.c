/*
 * Copyright (c) 2012 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012 Intel Corporation. All rights reserved.
 * Copyright (c) 2012 Lawrence Livermore National Securities.  All rights reserved.
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

#include <arpa/inet.h>
#include "osm_headers.h"

#include "ibssa_mad.h"
#include "ibssa_helper.h"
#include "osm_pi_main.h"

static inline osm_madw_t *pi_get_mad(struct ibssa_plugin *pi,
					IN osm_madw_t *p_madw)
{
	return (osm_mad_pool_get(&pi->osm->mad_pool,
				       pi->qp1_handle, MAD_BLOCK_SIZE,
				       &p_madw->mad_addr));
}


static void pi_send_resp(IN osm_madw_t *p_madw,
			IN osm_madw_t *p_resp_madw,
			IN struct ibssa_plugin *pi,
			uint16_t status)
{
	ib_api_status_t api_status;

	struct ib_ssa_mad * mad, * resp_mad;

	if (!p_resp_madw) {
		p_resp_madw = pi_get_mad(pi, p_madw);
		if (!p_resp_madw) {
			PI_LOG(pi, OSM_LOG_ERROR,
				"osm_vendor_send failed could not get mad from mad pool\n");
			return;
		}
	}

	mad = (struct ib_ssa_mad *)p_madw->p_mad;
	resp_mad = (struct ib_ssa_mad *)p_resp_madw->p_mad;

	resp_mad->hdr.base_version = 1;
	resp_mad->hdr.mgmt_class = IB_SSA_CLASS;
	resp_mad->hdr.class_version = IB_SSA_CLASS_VERSION;
	resp_mad->hdr.method = IB_SSA_METHOD_GETRESP;
	resp_mad->hdr.status = cl_hton16(status);
	resp_mad->hdr.tid = mad->hdr.tid;
	resp_mad->hdr.attr_id = mad->hdr.attr_id;
	resp_mad->hdr.attr_mod = mad->hdr.attr_mod;

	api_status = osm_vendor_send(pi->qp1_handle, p_resp_madw, FALSE);
	if (api_status != IB_SUCCESS) {
		PI_LOG(pi, OSM_LOG_ERROR,
			"osm_vendor_send failed, status = %s\n",
			ib_get_err_str(api_status));
	}
}

static void pi_send_member_rec_getresp(IN osm_madw_t * p_madw,
				     IN struct ibssa_plugin * pi,
				     enum ssa_class_status st)
{
	uint16_t status = 0;
	struct ib_ssa_mad * ssa_mad, * resp_ssa_mad;

	osm_madw_t *p_resp_madw = pi_get_mad(pi, p_madw);
	if (!p_resp_madw) {
		PI_LOG(pi, OSM_LOG_ERROR,
			"osm_vendor_send failed could not get mad from mad pool\n");
		return;
	}

	ssa_mad = (struct ib_ssa_mad *)p_madw->p_mad;
	resp_ssa_mad = (struct ib_ssa_mad *)p_resp_madw->p_mad;
	memcpy(resp_ssa_mad->data, ssa_mad->data, sizeof(resp_ssa_mad->data));

	status |= (st << 8);

	pi_send_resp(p_madw, p_resp_madw, pi, status);

	PI_LOG(pi, PI_LOG_DEBUG, "AppGetResp(SSAMemberRecord) status %s\n",
			ib_ssa_status_str(st));
}

static void pi_handle_set_member_rec(IN osm_madw_t * p_madw,
				     IN struct ibssa_plugin * pi,
				     struct ib_ssa_mad * ssa_mad)
{
	uint64_t service_guid;
	struct ibssa_tree *tree;
	struct ibssa_node *new_node;
	struct ib_ssa_member_record * mr =
			(struct ib_ssa_member_record *)ssa_mad->data;
	char buf[256];

	PI_LOG(pi, PI_LOG_DEBUG, "AppSet(SSAMemberRecord) from %s : 0x%x\n",
		net_gid_2_str(&mr->port_gid, buf, 256),
		cl_ntoh16(osm_madw_get_mad_addr_ptr(p_madw)->dest_lid));

	service_guid = cl_ntoh64(mr->service_guid);
	tree = (struct ibssa_tree *)cl_qmap_get(&pi->service_trees, service_guid);
	if (!tree) {
		pi_send_member_rec_getresp(p_madw, pi, SSA_SERVICE_GUID_NOT_SUP);
		return;
	}
	if (tree->self.ssa_version != mr->ssa_version) {
		pi_send_member_rec_getresp(p_madw, pi, SSA_SERVICE_VERSION);
		return;
	}
	if (tree->self.pkey != cl_ntoh16(mr->pkey)) {
		pi_send_member_rec_getresp(p_madw, pi, SSA_SERVICE_UNSUP_PKEY);
		return;
	}

	new_node = calloc(1, sizeof(*new_node));
	if (!new_node) {
		pi_send_member_rec_getresp(p_madw, pi, SSA_SERVICE_INTERNAL_ERR);
		return;
	}

	cl_qlist_init(&new_node->children);
	new_node->port_gid.global.subnet_prefix
			= cl_ntoh64(mr->port_gid.global.subnet_prefix);
	new_node->port_gid.global.interface_id
			= cl_ntoh64(mr->port_gid.global.interface_id);
	new_node->service_id = cl_ntoh64(mr->service_id);
	new_node->pkey = cl_ntoh16(mr->pkey);
	new_node->node_type = mr->node_type;
	new_node->ssa_version = mr->ssa_version;

	cl_qlist_insert_tail(&tree->conn_req, &new_node->list);

	pi_send_member_rec_getresp(p_madw, pi, SSA_SERVICE_OK);

	cl_event_signal(&pi->wake_up);
}

static void pi_handle_getresp_info_record(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* move node from conn_req into the service tree */
}

static void pi_handle_delete_member_rec(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* we assume the node has disconnected from it's parents */

	/* send new parent messages to all it's children */
	/* after we have reparented all the children, remove node from tree */
}

static void pi_mad_rcv_callback(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)context;
	PI_LOG_ENTER(pi);

	/* 2 types of MAD's incomming
	 * 1) ib_ssa_member_records (initial requests)
	 * 2) ib_ssa_info_record (echo's upon our set)
	 */

	/* FIXME
	 * Just like the current SA we should probably verify that we
	 * are master etc.
	 */

	struct ib_ssa_mad * mad = (struct ib_ssa_mad *)p_madw->p_mad;

	/* FIXME verify key */

	switch ((mad->hdr.method << 16) | cl_ntoh16(mad->hdr.attr_id))
	{
		case ((IB_SSA_METHOD_SET << 16) | IB_SSA_ATTR_SSAMemberRecord):
			pi_handle_set_member_rec(p_madw, pi, mad);
			break;
		case ((IB_SSA_METHOD_GETRESP << 16) | IB_SSA_ATTR_SSAInfoRecord):
			pi_handle_getresp_info_record(p_madw, context, p_req_madw);
			break;
		case ((IB_SSA_METHOD_DELETE << 16) | IB_SSA_ATTR_SSAMemberRecord):
			pi_handle_delete_member_rec(p_madw, context, p_req_madw);
			break;
		case IB_SSA_METHOD_GET:
		case IB_SSA_METHOD_DELETERESP:
		default:
			pi_send_resp(p_madw, NULL, pi, UMAD_STATUS_METHOD_NOT_SUPPORTED
						| UMAD_STATUS_ATTR_NOT_SUPPORTED);
			break;
	}

	osm_mad_pool_put(&pi->osm->mad_pool, p_madw);

	PI_LOG_EXIT(pi);
}

static void pi_mad_send_err_callback(IN void *context, IN osm_madw_t * p_madw)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)context;

	/* we need to be careful on send errors.
	 *
	 * Nodes connecting are specified to just spin forever after they issue
	 * their ib_ssa_member_record.
	 * So when do we determine they are dead and remove them from our
	 * conn_req pool?
	 *
	 * FIXME
	 *
	 * I think we need to change this specification that nodes have a timeout
	 * for when they expect their ib_ssa_info_records.
	 * also, having multiple ib_ssa_info_records returned makes this a bit
	 * more complicated.  What happens if only some of the ib_ssa_info_records
	 * succeed?
	 * for now it was decided that MSSA would just retry some time later.
	 * We will see how this works in practice.
	 */

	struct ib_ssa_mad * mad = (struct ib_ssa_mad *)p_madw->p_mad;

	switch ((mad->hdr.method << 16) | cl_ntoh16(mad->hdr.attr_id)) {
		case ((IB_SSA_METHOD_GETRESP << 16) | IB_SSA_ATTR_SSAMemberRecord):
			break;
		case ((IB_SSA_METHOD_SET << 16) | IB_SSA_ATTR_SSAInfoRecord):
			break;
		case ((IB_SSA_METHOD_DELETERESP << 16) | IB_SSA_ATTR_SSAMemberRecord):
			break;
		default:
			PI_LOG(pi, PI_LOG_ERROR,
				"ERR IBSSA: invalid method/attribute on send???");
			break;
	}
}

/** =========================================================================
 * MAD processing support functions for plugin
 */
ib_api_status_t ibssa_plugin_mad_bind(struct ibssa_plugin *pi)
{
	osm_bind_info_t  bind_info;
	ib_api_status_t  status = IB_SUCCESS;
	osm_subn_opt_t * opt = &pi->osm->subn.opt;
	ib_net64_t       sm_port_guid = pi->osm->subn.sm_port_guid;

	PI_LOG_ENTER(pi);

	if (pi->qp1_handle != OSM_BIND_INVALID_HANDLE) {
		PI_LOG(pi, PI_LOG_ERROR, "ERR IBSSA: "
			"Multiple binds not allowed\n");
		status = IB_ERROR;
		goto Exit;
	}

	bind_info.class_version = IB_SSA_CLASS_VERSION;
	bind_info.is_responder = TRUE;
	bind_info.is_report_processor = FALSE;
	bind_info.is_trap_processor = FALSE;
	bind_info.mad_class = IB_SSA_CLASS;
	bind_info.port_guid = sm_port_guid;
	bind_info.recv_q_size = OSM_SM_DEFAULT_QP1_RCV_SIZE;
	bind_info.send_q_size = OSM_SM_DEFAULT_QP1_SEND_SIZE;
	bind_info.timeout = opt->transaction_timeout;
	bind_info.retries = opt->transaction_retries;

	pi->qp1_handle = osm_vendor_bind(pi->osm->p_vendor, &bind_info,
					&pi->osm->mad_pool,
					pi_mad_rcv_callback,
					pi_mad_send_err_callback,
					pi);

	if (pi->qp1_handle == OSM_BIND_INVALID_HANDLE) {
		status = IB_ERROR;
		PI_LOG(pi, PI_LOG_ERROR, "ERR IBSSA: "
			"Vendor specific bind failed (%s) on port GUID "
			"0x%"PRIx64"\n",
			ib_get_err_str(status), cl_ntoh64(sm_port_guid));
		goto Exit;
	}

	PI_LOG(pi, PI_LOG_INFO,
		"bound to port GUID 0x%" PRIx64 "\n", cl_ntoh64(sm_port_guid));

	pi->sm_port_guid = sm_port_guid;

Exit:
	PI_LOG_EXIT(pi);
	return status;
}

void ibssa_mad_send_primary(struct ibssa_plugin *pi,
			struct ibssa_node * node,
			struct ibssa_node * primary)
{
	char str[256], str2[256];
	PI_LOG(pi, PI_LOG_VERBOSE, "Setting parent : node (%s) -> primary parent (%s)\n",
			gid_2_str(&node->port_gid, str, 256),
			gid_2_str(&primary->port_gid, str2, 256));
}
