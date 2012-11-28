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


#include <opensm/osm_version.h>
#include <opensm/osm_opensm.h>
#include <opensm/osm_log.h>

#include <complib/cl_thread.h>
#include <complib/cl_event.h>

#include "ibssa_osm_plugin.h"

void ibssa_main(IN void * context)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)context;
	while (pi->th_run) {
		/* initially just wait for requests and connect them */

		/* eventually we will want to start our DB management */
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

	/* Set up our thread */
	pi->th_run = 1;
	cl_thread_construct(&pi->thread);
	st = cl_thread_init(&pi->thread, ibssa_main, (void *)pi, "ibssa thread");
	if (st != CL_SUCCESS) {
		free(pi);
		pi = NULL;
		goto except;
	}

except:
	return (pi);
}

/** =========================================================================
 */
static void destroy(void *plugin)
{
	struct ibssa_plugin *pi = (struct ibssa_plugin *)plugin;
	pi->th_run = 0;
	cl_thread_destroy(&pi->thread);
	free(pi);
}

#if OSM_EVENT_PLUGIN_INTERFACE_VER != 2
#error OpenSM plugin interface version missmatch
#endif
osm_event_plugin_t osm_event_plugin = {
      osm_version:OSM_VERSION,
      create:construct,
      delete:destroy
};

