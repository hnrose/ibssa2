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


#ifndef __IBSSA_HELPER_H__
#define __IBSSA_HELPER_H__

#include <infiniband/verbs.h>
#include <arpa/inet.h>
#include "ibssa_umad.h"

inline static const char *gid_2_str(union ibv_gid *gid, char *buf, size_t s)
{
	union ibv_gid g;
	g.global.subnet_prefix = gid->global.subnet_prefix;
	g.global.interface_id = gid->global.interface_id;
	return (inet_ntop(AF_INET6, g.raw, buf, s));
}

inline static const char *net_gid_2_str(union ibv_gid *net_gid, char *buf, size_t s)
{
	union ibv_gid g;
	g.global.subnet_prefix = ntohll(net_gid->global.subnet_prefix);
	g.global.interface_id = ntohll(net_gid->global.interface_id);
	return (inet_ntop(AF_INET6, g.raw, buf, s));
}

#endif /* __IBSSA_HELPER_H__ */
