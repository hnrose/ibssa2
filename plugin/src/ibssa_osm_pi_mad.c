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

#include "osm_headers.h"

#include "ibssa_mad.h"
#include "ibssa_osm_plugin.h"

static void pi_handle_set_member_rec(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* add node to proper service_guid tree and signal thread to process
	 * the request */
}
static void pi_handle_getresp_info_record(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* verify the tid and retire mad */
}
static void pi_handle_delete_member_rec(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* we assume the node has disconnected from it's parents */

	/* send new parent messages to all it's children */
	/* after we have reparented all the children, remove node from tree */
}

static void pi_handle_invalid_rcv(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
	/* retire MAD, optional send invalid query response. */
}

static void pi_mad_rcv_callback(IN osm_madw_t * p_madw, IN void *context,
				     IN osm_madw_t * p_req_madw)
{
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
			pi_handle_set_member_rec(p_madw, context, p_req_madw);
			break;
		case ((IB_SSA_METHOD_GETRESP << 16) | IB_SSA_ATTR_SSAInfoRecord):
			pi_handle_getresp_info_record(p_madw, context, p_req_madw);
			break;
		case ((IB_SSA_METHOD_DELETE << 16) | IB_SSA_ATTR_SSAMemberRecord):
			pi_handle_delete_member_rec(p_madw, context, p_req_madw);
			break;
		case IB_SSA_METHOD_GET:
		case IB_SSA_METHOD_DELETERESP:
			pi_handle_invalid_rcv(p_madw, context, p_req_madw);
			break;
	}
}

static void pi_mad_send_err_callback(IN void *context, IN osm_madw_t * p_madw)
{
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
	}
}

/** =========================================================================
 * MAD processing support functions for plugin
 */
ib_api_status_t ibssa_plugin_mad_bind(struct ibssa_plugin *pi)
{
	osm_bind_info_t bind_info;
	ib_api_status_t status = IB_SUCCESS;
	osm_subn_opt_t *opt = &pi->osm->subn.opt;

	PI_LOG_ENTER(pi);

	if (pi->qp1_handle != OSM_BIND_INVALID_HANDLE) {
		PI_LOG(pi, PI_LOG_ERROR, "ERR IBSSA: "
			"Multiple binds not allowed\n");
		status = IB_ERROR;
		goto Exit;
	}

	bind_info.class_version = 1;
	bind_info.is_responder = TRUE;
	bind_info.is_report_processor = FALSE;
	bind_info.is_trap_processor = FALSE;
	bind_info.mad_class = IB_SSA_CLASS;
	bind_info.port_guid = opt->guid;
	bind_info.recv_q_size = OSM_SM_DEFAULT_QP1_RCV_SIZE;
	bind_info.send_q_size = OSM_SM_DEFAULT_QP1_SEND_SIZE;
	bind_info.timeout = opt->transaction_timeout;
	bind_info.retries = opt->transaction_retries;

	PI_LOG(pi, PI_LOG_VERBOSE,
		"Binding to port GUID 0x%" PRIx64 "\n", cl_ntoh64(opt->guid));

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
			ib_get_err_str(status), cl_ntoh64(opt->guid));
		goto Exit;
	}

	PI_LOG(pi, PI_LOG_INFO,
		"bound to port GUID 0x%" PRIx64 "\n", cl_ntoh64(opt->guid));

Exit:
	PI_LOG_EXIT(pi);
	return status;
}
