/*
 * Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <inttypes.h>
#include <infiniband/ssa_mad.h>
#include <common.h>
#ifdef SSA_ADMIN_DEBUG
#include <ssa_admin.h>
#endif

const char *month_str[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

void ssa_write_date(FILE *stream, time_t tim, unsigned int usec)
{
	struct tm result;

	localtime_r(&tim, &result);
	fprintf(stream, "%s %02d %02d:%02d:%02d %06d",
		(result.tm_mon < 12 ? month_str[result.tm_mon] : "???"),
		result.tm_mday, result.tm_hour, result.tm_min,
		result.tm_sec, usec);
}

const char *ssa_node_type_str(int node_type)
{
	switch (node_type) {
	case SSA_NODE_CORE:
		return "Core";
	case (SSA_NODE_CORE | SSA_NODE_ACCESS):
		return "Core + Access";
	case (SSA_NODE_DISTRIBUTION | SSA_NODE_ACCESS):
		return "Distribution + Access";
	case SSA_NODE_DISTRIBUTION:
		return "Distribution";
	case SSA_NODE_ACCESS:
		return "Access";
	case SSA_NODE_CONSUMER:
		return "Consumer";
	default:
		return "Other";
	}
}

void ssa_format_addr(char *str, size_t str_size,
		     enum ssa_addr_type addr_type, const uint8_t *addr, size_t addr_size)
{
	struct ibv_path_record *path;

	switch (addr_type) {
	case SSA_ADDR_NAME:
		memcpy(str, addr, addr_size);
		break;
	case SSA_ADDR_IP:
		inet_ntop(AF_INET, addr, str, str_size);
		break;
	case SSA_ADDR_IP6:
	case SSA_ADDR_GID:
		inet_ntop(AF_INET6, addr, str, str_size);
		break;
	case SSA_ADDR_PATH:
		path = (struct ibv_path_record *) addr;
		if (path->dlid) {
			snprintf(str, str_size, "SLID(%u) DLID(%u)",
				ntohs(path->slid), ntohs(path->dlid));
		} else {
			ssa_format_addr(str, str_size, SSA_ADDR_GID,
					path->dgid.raw, sizeof path->dgid);
		}
		break;
	case SSA_ADDR_LID:
		snprintf(str, str_size, "LID(%u)", ntohs(*((uint16_t *) addr)));
		break;
	default:
		strcpy(str, "Unknown");
		break;
	}
}

struct poll_event {
	int val;
	const char *name;
};

static const struct poll_event poll_events[] = {
	{POLLHUP, "POLLHUP"},
	{POLLERR, "POLLERR"},
	{POLLNVAL, "POLLNVAL"},
	{POLLIN, "POLLIN"},
	{POLLPRI, "POLLPRI"},
	{POLLOUT, "POLLOUT"},
	{POLLRDHUP ,"POLLRDHUP"},
	{POLLRDBAND ,"POLLRDBAND"},
	{POLLWRBAND ,"POLLWRBAND"}
};

void ssa_format_event(char *str,const size_t str_size, const int event)
{
	unsigned int i, n = 0;
	int ret;

	for (i = 0; n < str_size && i < sizeof(poll_events) / sizeof(poll_events[0]); ++i) {
		if (event & poll_events[i].val) {
			ret = snprintf(str + n, str_size - n, "%s|", poll_events[i].name);
			if (ret > 0)
				n += ret;
		}
	}
	n = strlen(str);
	if (n && str[n - 1] == '|')
		str[n -1] = '\0';
}

#ifdef SSA_ADMIN_DEBUG
static const char *admin_msg_status_name[] = {
	[SSA_ADMIN_STATUS_SUCCESS] = "SUCCESS",
	[SSA_ADMIN_STATUS_FAILURE] = "FAILURE"
};

static const char *admin_msg_method_name[] = {
	[SSA_ADMIN_METHOD_GET] = "GET",
	[SSA_ADMIN_METHOD_SET] = "SET",
	[SSA_ADMIN_METHOD_RESP] = "RESP"
};

static const char *admin_msg_operation_name[] = {
	[SSA_ADMIN_CMD_NONE] = "NONE",
	[SSA_ADMIN_CMD_COUNTER] = "COUNTER",
	[SSA_ADMIN_CMD_PING] = "PING",
	[SSA_ADMIN_CMD_NODE_INFO] = "NODEINFO"
};

void ssa_format_admin_msg(char *buf, size_t size, const struct ssa_admin_msg *msg)
{
	int len = ntohs(msg->hdr.len);

	if (msg->hdr.status >=
	    sizeof(admin_msg_status_name) / sizeof(admin_msg_status_name[0])) {
			snprintf(buf, size, "Wrong status %d", msg->hdr.status);
			return;
	} else if (msg->hdr.method >=
		   sizeof(admin_msg_method_name) / sizeof(admin_msg_method_name[0])) {
			snprintf(buf, size, "Wrong method %d", msg->hdr.method);
			return;
	} else if (ntohs(msg->hdr.opcode) >= SSA_ADMIN_CMD_MAX) {
			snprintf(buf, size, "Wrong operation %d", ntohs(msg->hdr.opcode));
			return;
	} else {
		snprintf(buf, size,
			 "Version: %d Status: %s Method: %s Op: %s Flags: %d Len: %d ",
			 msg->hdr.version, admin_msg_status_name[msg->hdr.status],
			 admin_msg_method_name[msg->hdr.method],
			 admin_msg_operation_name[ntohs(msg->hdr.opcode)],
			 ntohs(msg->hdr.flags), len);
	}

	if (len <= sizeof(msg->hdr))
		return;


	snprintf(buf + strlen(buf), size - strlen(buf), "Payload: ");

	switch (ntohs(msg->hdr.opcode)) {
	case SSA_ADMIN_CMD_PING:
		return;
	case SSA_ADMIN_CMD_COUNTER:
		{
		const struct ssa_admin_counter *payload = &msg->data.counter;

		snprintf(buf + strlen(buf), size - strlen(buf), " N: %d", ntohs(payload->n));
		}
		break;
	case SSA_ADMIN_CMD_NODE_INFO:
		{
		const struct ssa_admin_node_info *payload = &msg->data.node_info;

		snprintf(buf + strlen(buf), size - strlen(buf),
			 "Type: %d Version %s N: %d",
			 payload->type, payload->version,
			 ntohs(payload->connections_num));
		}
		break;
	case SSA_ADMIN_CMD_NONE:
	default:
		snprintf(buf + strlen(buf), size - strlen(buf), "Unknown message");
	};
}
#endif
