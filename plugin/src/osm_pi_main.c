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

#include "osm_pi_main.h"
#include "osm_pi_mad.h"
#include "osm_pi_config.h"

static void update_config(struct ibssa_plugin *pi)
{
	pi->conf = read_config();
	osm_log_set_level(&pi->log, pi->conf->log_level);
}

static void ibssa_main(IN void * context)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)context;
	/* Note this thread can't do anything until the SM has reported SUBNET
	 * up.  This is because the plugins are loaded before the SM port has
	 * been chosen.  So we wait for SUBNET up so that we know that a port
	 * guid has been chosen.  Then we can bind and start our services.
	 * Connections arriving before we are bound will just fail...  :-(  It
	 * seems that the port could have been chosen before the plugins are
	 * loaded but that is an OpenSM issue...
	 */
	PI_LOG(pi, PI_LOG_INFO, "thread started\n");

	while (pi->th_run) {
		/* wait for signals from OpenSM to collect data */
		cl_event_wait_on(&pi->wake_up, EVENT_NO_TIMEOUT, TRUE);
		if (!pi->th_run)
			break;
		update_config(pi);
	}
}

static void set_up_service_trees(struct ibssa_plugin *pi)
{
#if 0
	/* Set up our service tress for the service guids we support. */
	foreach sg in sgs: {
		struct ibssa_tree *tree = calloc(1, sizeof(*tree));
		if (!tree) {
			PI_LOG(pi, PI_LOG_ERROR,
				"Failed to allocate tree for service guid 0x"PRIx64"\n",
				sg);
			continue;
		}

		cl_qlist_init(&tree->conn_req);

		/* set up our "self" for tree head */
		tree->self.primary = NULL;
		tree->self.secondary = NULL;
		cl_qlist_init(&tree->self.children);
		tree->self.port_gid.global.subnet_prefix = cl_ntohll(pi->osm->subn.opt.subnet_prefix);
		tree->self.port_gid.global.interface_id = cl_ntohll(pi->osm->subn.opt.port_guid);
		/* FIXME we need to get a service id from the ibcm */
		tree->self.service_id = 0;
		/* FIXME need to get a pkey set up */
		/* FIXME worse yet do we need multiple trees for each partition ? */
		tree->self.pkey = 0x0000;
		tree->self.node_type = SSA_NODE_MASTER;
		tree->self.ssa_version = IBSSA_VERSION;
		tree->self.node_state = IBSSA_STATE_PARENTED;

		cl_qmap_insert(&pi.service_trees, sg, (cl_map_item_t *)tree);
	}
#endif
}

static ib_api_status_t ibssa_plugin_bind(struct ibssa_plugin *pi)
{
	ib_api_status_t rc = ibssa_plugin_mad_bind(pi);
	if (rc == IB_SUCCESS) {
		set_up_service_trees(pi); /* FIXME what happens if this fails */
	} else {
		PI_LOG(pi, PI_LOG_ERROR, "ERR IBSSA: Could not "
			"bind; Waiting for next SUBNET UP event?!?!?!?\n");
		/* FIXME
		 * We don't want to wait for the next SUBNET up
		 * event...  Probably need to start a timer or something.
		 * OpenSM is such a pain...  :-(
		 * Anyway for now we will just wait for the next SUBNET_UP
		 * event and will try to bind again...
		 */
	}
	return (rc);
}

/** =========================================================================
 */
static void report(void *plugin_data, osm_epi_event_id_t event_id, void *event_data)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)plugin_data;

	/* Wait for SUBNET up to bind and start our services. */
	if (event_id == OSM_EVENT_ID_SUBNET_UP) {
		if (pi->qp1_handle == OSM_BIND_INVALID_HANDLE) {
			if (ibssa_plugin_bind(pi) != IB_SUCCESS)
				return;
		}
		/* Wake up worker thread */
		cl_event_signal(&pi->wake_up);
	}
}

/** =========================================================================
 */
static void *construct(osm_opensm_t *osm)
{
	cl_status_t st = CL_SUCCESS;
	struct ibssa_plugin *pi = calloc(1, sizeof(*pi));
	if (!pi)
		return (NULL);

	pi->osm = osm;

	/* make sure we have our config */
	pi->conf = read_config();

	/* create our own log file to support our own log parameters (ie level) */
	osm_log_construct(&(pi->log));
	if (osm_log_init(&(pi->log), DEF_FLUSH, pi->conf->log_level,
			pi->conf->log_file, DEF_APPEND) != IB_SUCCESS)
	{
		osm_log(&pi->osm->log, OSM_LOG_ERROR,
			"opensmssa Exiting: Failed to initialize log file: %s\n",
			pi->conf->log_file);
		return (NULL);
	}

	/* Set up our thread, we could delay this but we should do everything
	 * we can here so that we can fail the load if something goes wrong.
	 * It would be nice if we could bind to the port as well but...
	 */
	pi->th_run = 1;
	cl_thread_construct(&pi->thread);
	cl_event_init(&pi->wake_up, FALSE);
	st = cl_thread_init(&pi->thread, ibssa_main, (void *)pi, "ibssa thread");
	if (st != CL_SUCCESS) {
		free(pi);
		pi = NULL;
		goto except;
	}

	PI_LOG(pi, PI_LOG_INFO, "plugin loaded\n");
except:
	return (pi);
}

/** =========================================================================
 */
static void destroy(void *plugin)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)plugin;
	pi->th_run = 0;
	cl_event_signal(&pi->wake_up);
	cl_thread_destroy(&pi->thread); /* join */
	free(pi);
}

#if OSM_EVENT_PLUGIN_INTERFACE_VER != 2
#error OpenSM plugin interface version missmatch
#endif
osm_event_plugin_t osm_event_plugin = {
      osm_version:OSM_VERSION,
      create:construct,
      delete:destroy,
      report:report
};

