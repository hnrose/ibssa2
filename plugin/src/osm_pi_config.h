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


#ifndef __OSM_PLUGIN_CONFIG__
#define __OSM_PLUGIN_CONFIG__

#include "config.h"
#include "osd.h"
#include "osm_pi_log.h"

#define DEF_FLUSH 1
#define DEF_APPEND 1
#define DEF_LOG_LEVEL (PI_LOG_ERROR | PI_LOG_INFO | PI_LOG_SYS)
#define DEF_LOG_FILE "/var/log/opensmssa.log"
#define DEF_CONFIG_FILE RDMA_CONF_DIR "/opensmssa.conf"

struct opensmssa_config {
	/* [Logging] */
	char * log_file;
	int    log_level;
	/* internal details */
	time_t timestamp;
};

/**
 * singleton object
 *
 * read will update the config object from the file
 * get will simply return the pointer.
 */
struct opensmssa_config * read_config(void);
struct opensmssa_config * get_config(void);

#endif /* __OSM_PLUGIN_CONFIG__ */
