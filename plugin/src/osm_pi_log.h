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
 *        copyright notice, this list of conditions and the following *        disclaimer.
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

#ifndef __OSM_PLUGIN_LOG_H__
#define __OSM_PLUGIN_LOG_H__

#include "osm_headers.h"

/* Wrap the OSM_LOG with generics for our purposes */
#define PI_LOG_NONE	OSM_LOG_NONE
#define PI_LOG_ERROR	OSM_LOG_ERROR
#define PI_LOG_INFO	OSM_LOG_INFO
#define PI_LOG_VERBOSE	OSM_LOG_VERBOSE
#define PI_LOG_DEBUG	OSM_LOG_DEBUG
#define PI_LOG_FUNCS	OSM_LOG_FUNCS
#define PI_LOG_FRAMES	OSM_LOG_FRAMES
#define PI_LOG_ROUTING	OSM_LOG_ROUTING
#define PI_LOG_ALL	OSM_LOG_ALL
#define PI_LOG_SYS	OSM_LOG_SYS

#define PI_LOG(pi, level, fmt, ...) \
	do { \
		osm_log(&(pi->log), level, fmt, ## __VA_ARGS__); \
		osm_log(&pi->osm->log, level, "opensmssa: " fmt, ## __VA_ARGS__); \
	} while (0)
#define PI_LOG_ENTER(pi) PI_LOG(pi, PI_LOG_FUNCS, "%s: [\n", __func__)
#define PI_LOG_EXIT(pi) PI_LOG(pi, PI_LOG_FUNCS, "%s: ]\n", __func__)

#endif /* __OSM_PLUGIN_LOG_H__ */
