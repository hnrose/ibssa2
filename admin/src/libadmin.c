/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

#include <stdio.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <rdma/rsocket.h>
#include <infiniband/ib.h>
#include <infiniband/umad.h>
#include <infiniband/umad_sm.h>

#include "libadmin.h"
#include <osd.h>
#include <ssa_admin.h>
#include <infiniband/ssa_mad.h>


#define MAX_COMMAND_OPTS 20

struct admin_context {
	uint64_t stime, etime;
};

struct cmd_struct_impl;
struct admin_count_command {
};

struct admin_command {
	const struct cmd_struct_impl *impl;
	const struct cmd_struct *cmd;
	union {
		struct admin_count_command count_cmd;
	} data;
};

struct cmd_struct_impl {
	struct admin_command *(*init)(int cmd_id, struct admin_context *ctx,
				      int argc, char **argv);
	void (*destroy)(struct admin_command *admin_cmd);
	int (*create_request)(struct admin_command *admin_cmd,
			      struct admin_context *ctx,
			      struct ssa_admin_msg *msg);
	void (*handle_response)(struct admin_command *cmd,
				struct admin_context *ctx,
				const struct ssa_admin_msg *msg);
	struct cmd_opts opts[MAX_COMMAND_OPTS];
	struct cmd_help help;
};


static void default_destroy(struct admin_command *cmd);
static void default_print_usage(FILE *stream);
static struct admin_command *default_init(int cmd_id, struct admin_context *ctx,
					  int argc, char **argv);
static int default_create_msg(struct admin_command *cmd,
			      struct admin_context *ctx,
			      struct ssa_admin_msg *msg);
static void ping_command_output(struct admin_command *cmd,
				struct admin_context *ctx,
				const struct ssa_admin_msg *msg);
static void counter_print_help(FILE *stream);
static int counter_command_create_msg(struct admin_command *cmd,
				      struct admin_context *ctx,
				      struct ssa_admin_msg *msg);
static void counter_command_output(struct admin_command *cmd,
				   struct admin_context *ctx,
				   const struct ssa_admin_msg *msg);

static struct cmd_struct_impl admin_cmd_command_impls[] = {
	[SSA_ADMIN_CMD_COUNTER] = {
		default_init,
		default_destroy,
		counter_command_create_msg,
		counter_command_output,
		{},
		{ counter_print_help, default_print_usage,
		  "Retrieve specific counter" },
	},
	[SSA_ADMIN_CMD_PING]	= {
		default_init,
		default_destroy,
		default_create_msg,
		ping_command_output,
		{},
		{ NULL, default_print_usage,
		  "Test ping between local node and SSA service on a specified target node" }
	}
};

static int rsock = -1;
static int loopback;
static atomic_t tid;
static short admin_port = 7477;
static uint16_t pkey_default = 0xffff;
static char dest_addr[64];
static const char *local_gid = "::1";

static const char *short_opts_to_skip;
static struct option *long_opts_to_skip;
static int long_opts_num;

static uint64_t get_timestamp()
{
	uint64_t tstamp;
	struct timeval tv;

	gettimeofday(&tv ,0);

	/* Convert the time of day into a microsecond timestamp. */
	tstamp = ((uint64_t) tv.tv_sec * 1000000) + (uint64_t) tv.tv_usec;

	return tstamp;
}

int admin_init(const char *short_opts, struct option *long_opts)
{
	int i = 0;

	srand(time(NULL));

	atomic_init(&tid);
	atomic_set(&tid, rand());

	short_opts_to_skip = short_opts;
	long_opts_to_skip = long_opts;

	while (long_opts_to_skip[i++].name)
		long_opts_num++;

	return 0;
}

void admin_cleanup()
{
	return;
}

static int open_port(const char *dev, int port)
{
	int port_id;

	if (umad_init() < 0) {
		fprintf(stderr, "ERROR - unable to init UMAD library\n");
		return -1;
	}

	if ((port_id = umad_open_port(dev, (port < 0) ? 0 : port)) < 0) {
		fprintf(stderr, "ERROR - can't open UMAD port\n");
		return -1;
	}

	return port_id;
}

static void close_port(int port_id)
{
	umad_close_port(port_id);
	umad_done();
}

/*
 * If no port specified (port is -1), first physical port in active
 * state is queried for sm lid and sm sl.
 */
static int get_sm_info(const char *ca_name, int port,
		       uint16_t *sm_lid, uint8_t *sm_sl)
{
	struct ibv_device **dev_arr, *dev;
	struct ibv_context *verbs;
	struct ibv_port_attr port_attr;
	struct ibv_device_attr attr;
	int  d, p, ret, status = -1;
	int dev_cnt, port_cnt;

	dev_arr = ibv_get_device_list(&dev_cnt);
	if (!dev_arr) {
		fprintf(stderr, "ERROR - unable to get device list\n");
		return -1;
	}

	for (d = 0; d < dev_cnt; d++) {
		dev = dev_arr[d];

		if (ca_name && strncmp(ca_name, dev->name, IBV_SYSFS_NAME_MAX))
			continue;

		if (dev->transport_type != IBV_TRANSPORT_IB ||
		    dev->node_type != IBV_NODE_CA) {
			if (ca_name) {
				fprintf(stderr, "ERROR - invalid device (%s)\n",
					dev->name);
				goto out;
			} else {
				continue;
			}
		}

		verbs = ibv_open_device(dev);
		if (!verbs) {
			fprintf(stderr, "ERROR - unable to open device (%s)\n",
				dev->name);
			goto out;
		}

		ret = ibv_query_device(verbs, &attr);
		if (ret) {
			fprintf(stderr, "ERROR - ibv_query_device (%s) %d\n",
				dev->name, ret);
			goto out;
		}

		port_cnt = attr.phys_port_cnt;

		for (p = 1; p <= port_cnt; p++) {
			if (port >= 0 && port != p)
				continue;

			ret = ibv_query_port(verbs, p, &port_attr);
			if (ret) {
				fprintf(stderr, "ERROR - ibv_query_port (%s) %d\n",
					dev->name, ret);
				goto out;
			}

			if (port_attr.link_layer != IBV_LINK_LAYER_INFINIBAND ||
			    port_attr.state != IBV_PORT_ACTIVE) {
				if (port >= 0) {
					fprintf(stderr, "ERROR - invalid port %s:%d\n",
						dev->name, port);
					goto out;
				} else {
					continue;
				}
			}

			*sm_lid = port_attr.sm_lid;
			*sm_sl = port_attr.sm_sl;
			break;
		}

		if (p <= port_cnt)
			break;

		if (ca_name) {
			fprintf(stderr, "ERROR - no active port found for %s device\n",
				dev->name);
			goto out;
		}
	}

	if (d == dev_cnt)
		fprintf(stderr, "ERROR - no proper device with active port found\n");
	else
		status = 0;

out:
	ibv_free_device_list(dev_arr);

	return status;
}

static int get_gid(const char *dev, int port, int port_id,
		   uint16_t dlid, union ibv_gid *dgid)
{
	struct sa_path_record *mad;
	struct ibv_path_record *path;
	int ret, len, status = 0;
	int agent_id = -1;
	struct sa_umad umad;
	uint16_t sm_lid = 0;
	uint8_t sm_sl = 0;

	agent_id = umad_register(port_id, UMAD_CLASS_SUBN_ADM,
				 UMAD_SA_CLASS_VERSION, 0, NULL);
	if (agent_id < 0) {
		fprintf(stderr, "ERROR - unable to register SSA class on local port\n");
		status = -1;
		goto err;
	}

	if (get_sm_info(dev, port, &sm_lid, &sm_sl)) {
		status = -1;
		goto err;
	}

	memset(&umad, 0, sizeof umad);
	umad_set_addr(&umad.umad, sm_lid, 1, sm_sl, UMAD_QKEY);
	mad = &umad.sa_mad.path_rec;

	mad->mad_hdr.base_version	= UMAD_BASE_VERSION;
	mad->mad_hdr.mgmt_class		= UMAD_CLASS_SUBN_ADM;
	mad->mad_hdr.class_version	= UMAD_SA_CLASS_VERSION;
	mad->mad_hdr.method		= UMAD_METHOD_GET;
	mad->mad_hdr.tid		= htonll((uint64_t) atomic_inc(&tid));
	mad->mad_hdr.attr_id		= htons(UMAD_SA_ATTR_PATH_REC);

	mad->comp_mask = htonll(((uint64_t)1) << 4 |    /* DLID */
				((uint64_t)1) << 11 |   /* Reversible */
				((uint64_t)1) << 13);   /* P_Key */

	path = &mad->path;
	path->dlid = htons(dlid);
	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
	path->pkey = 0xFFFF;    /* default partition */

	ret = umad_send(port_id, agent_id, (void *) &umad,
			sizeof umad.sa_mad.packet, -1 /* timeout */, 0);
	if (ret) {
		fprintf(stderr, "ERROR - failed to send path query to SA\n");
		status = -1;
		goto err;
	}

	len = sizeof umad.sa_mad.packet;
	ret = umad_recv(port_id, (void *) &umad, &len, -1 /* timeout */);
	if (ret < 0 || ret != agent_id) {
		fprintf(stderr, "ERROR - failed to receive path record from SA\n");
		status = -1;
		goto err;
	}

	if (umad.sa_mad.path_rec.mad_hdr.status == UMAD_SA_STATUS_SUCCESS) {
		path = &umad.sa_mad.path_rec.path;
		memcpy(dgid->raw, path->dgid.raw, 16);
	} else {
		fprintf(stderr, "ERROR - specified LID (%u) doesn't exist\n", dlid);
		status = -1;
	}

err:
	if (agent_id >= 0)
		umad_unregister(port_id, agent_id);

	return status;
}

int admin_connect(void *dest, int type, struct admin_opts *opts)
{
	struct sockaddr_ib dst_addr;
	union ibv_gid dgid;
	int ret, val, port_id;
	int port = opts->admin_port ? opts->admin_port : admin_port;
	uint16_t pkey = opts->pkey ? opts->pkey : pkey_default;

	rsock = rsocket(AF_IB, SOCK_STREAM, 0);
	if (rsock < 0) {
		fprintf(stderr, "rsocket ERROR %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	val = 1;
	ret = rsetsockopt(rsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof val);
	if (ret) {
		fprintf(stderr, "rsetsockopt rsock %d SO_REUSEADDR ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	ret = rsetsockopt(rsock, IPPROTO_TCP, TCP_NODELAY,
			  (void *) &val, sizeof(val));
	if (ret) {
		fprintf(stderr, "rsetsockopt rsock %d TCP_NODELAY ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	dst_addr.sib_family	= AF_IB;
	dst_addr.sib_pkey	= htons(pkey);
	dst_addr.sib_flowinfo	= 0;
	dst_addr.sib_sid	=
		htonll(((uint64_t) RDMA_PS_TCP << 16) + port);
	dst_addr.sib_sid_mask	= htonll(RDMA_IB_IP_PS_MASK);
	dst_addr.sib_scope_id	= 0;

	if (type == ADMIN_ADDR_TYPE_GID) {
		if (!strncmp((char *) dest, local_gid, strlen(local_gid))) {
			snprintf(dest_addr, 10, "localhost");
			loopback = 1;
		} else {
			snprintf(dest_addr, max(64, strlen((char *) dest)),
				 "GID %s", (char *) dest);
		}

		ret = inet_pton(AF_INET6, dest ? (char *) dest : local_gid, &dgid);
		if (!ret)
			fprintf(stderr, "ERROR - wrong server GID specified\n");
		else if (ret < 0)
			fprintf(stderr, "ERROR - not supported address family\n");

		if (ret <= 0)
			goto err;
	} else if (type == ADMIN_ADDR_TYPE_LID) {
		port_id = open_port(opts->dev, opts->src_port);
		if (port_id < 0)
			goto err;

		ret = get_gid(opts->dev, opts->src_port,
			      port_id, *(uint16_t *) dest, &dgid);
		if (ret) {
			fprintf(stderr, "ERROR - unable to get GID for LID %u\n",
				*(uint16_t *) dest);
			close_port(port_id);
			goto err;
		}
		close_port(port_id);

		sprintf(dest_addr, "LID %u", *(uint16_t *) dest);
	}

	memcpy(&dst_addr.sib_addr, &dgid, sizeof(dgid));

	ret = rconnect(rsock, (const struct sockaddr *) &dst_addr,
		       sizeof(dst_addr));
	if (ret && (errno != EINPROGRESS)) {
		fprintf(stderr, "rconnect rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	return 0;

err:
	rclose(rsock);
	rsock = -1;
	return -1;
}

void admin_disconnect()
{
	if (rsock == -1)
		return;

	rclose(rsock);
}

static int get_cmd_opts(struct cmd_opts *cmd_opts, struct option *long_opts,
			char *short_opts)
{
	int i = 0, j = 0, n = 0;

	while (cmd_opts[j].op.name) {
		long_opts[i] = cmd_opts[j].op;
		n += sprintf(short_opts + n, "%c",
			     cmd_opts[j].op.val);

		if (cmd_opts[j].op.has_arg)
			n += sprintf(short_opts + n, ":");
		i++;
		j++;
	}

	sprintf(short_opts + n, "%s", short_opts_to_skip);

	j = 0;
	while(long_opts_to_skip[j].name)
		long_opts[i++] = long_opts_to_skip[j++];

	/* copy last terminating record: { 0, 0, 0, 0} */
	long_opts[i] = long_opts_to_skip[j];

	return 0;
}

#if 0
static void do_poll(int rsock)
{
	struct pollfd fds[1];
	int ret;
	static int status = 0;
	fds[0].fd	= rsock;
	fds[0].events	= POLLIN;
	fds[0].revents	= 0;
	for (;;) {
		ret = rpoll(fds, 1, -1);
		if (ret < 0) {
			printf("polling fds %d (%s)\n",
			       errno, strerror(errno));
			continue;
		}
		if (fds[0].revents) {
			fds[0].events = 0;
			return;
		}
	}
}
#endif

static void default_destroy(struct admin_command *cmd)
{
}

static void default_print_usage(FILE *stream)
{
	(void)(stream);
}

static struct admin_command *default_init(int cmd_id, struct admin_context *ctx,
					  int argc, char **argv)
{
	struct option *long_opts;
	char short_opts[256];
	int option, n;
	struct cmd_opts *opts;
	struct cmd_struct *cmd;
	struct cmd_struct_impl *impl;
	struct admin_command *admin_cmd;

	if (cmd_id <= SSA_ADMIN_CMD_NONE || cmd_id >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd_id);
		return NULL;
	}

	cmd = &admin_cmds[cmd_id];
	impl = &admin_cmd_command_impls[cmd_id];
	opts = impl->opts;
	if (!opts)
		return NULL;

	admin_cmd = (struct admin_command *) malloc(sizeof(*admin_cmd));
	if (!admin_cmd)
		return NULL;

	admin_cmd->impl = impl;
	admin_cmd->cmd = cmd;

	n = ARRAY_SIZE(impl->opts) + long_opts_num;
	long_opts = calloc(1, n * sizeof(*long_opts));
	if (!long_opts) {
		fprintf(stderr,
			"ERROR - unable to allocate memory for %s command\n",
			cmd->cmd);
		free(admin_cmd);
		return NULL;
	}

	get_cmd_opts(opts, long_opts, short_opts);

	do {
		option = getopt_long(argc, argv, short_opts,
				     long_opts, NULL);
		switch (option) {
		case '?':
			free(long_opts);
			return NULL;
		default:
			break;
		}
	} while (option != -1);

	free(long_opts);

	return admin_cmd;
}

static int default_create_msg(struct admin_command *cmd,
			      struct admin_context *ctx,
			      struct ssa_admin_msg *msg)
{
	return 0;
}

enum ssa_counter_type {
	ssa_counter_obsolete = 0,
	ssa_counter_numeric,
	ssa_counter_timestamp
};

struct ssa_admin_counter_descr {
	uint8_t type;
	const char *name;
	const char *description;
};

static void ping_command_output(struct admin_command *cmd,
				struct admin_context *ctx,
				const struct ssa_admin_msg *msg)
{
	printf("%lu bytes from \033[1m%s\033[0m : time=%g ms\n",
	       sizeof(msg), dest_addr, 1e-3 * (ctx->etime - ctx->stime));
}

static const char *ssa_counter_type_names[] = {
	[ssa_counter_obsolete] = "Obsolete",
	[ssa_counter_numeric] = "Numeric",
	[ssa_counter_timestamp] = "Timestamp"
};

static struct ssa_admin_counter_descr counters_descr[] = {
	[COUNTER_ID_NODE_START_TIME] = { ssa_counter_timestamp, "NODE_START_TIME", "Starting time of the node" },
	[COUNTER_ID_DB_UPDATES_NUM] = { ssa_counter_numeric, "DB_UPDATES_NUM", "Number of databases updates passed the node" },
	[COUNTER_ID_DB_LAST_UPDATE_TIME] = { ssa_counter_timestamp, "LAST_UPDATE_TIME", "Time of last database update" },
	[COUNTER_ID_DB_FIRST_UPDATE_TIME] = { ssa_counter_timestamp, "FIRST_UPDATE_TIME", "Time of first database update" },
	[COUNTER_ID_NUM_CHILDREN] = { ssa_counter_numeric, "NUM_CHILDREN", "Number of connected downstream nodes" },
	[COUNTER_ID_NUM_ACCESS_TASKS] = { ssa_counter_numeric, "NUM_ACCESS_TASKS", "Number of unprocessed Access tasks" },
	[COUNTER_ID_NUM_ERR] = { ssa_counter_numeric, "NUM_ERR", "Number of errors" },
	[COUNTER_ID_TIME_LAST_UPSTR_CONN] = { ssa_counter_timestamp, "TIME_LAST_UPSTR_CONN", "Time of last upstream connect" },
	[COUNTER_ID_TIME_LAST_DOWNSTR_CONN] = { ssa_counter_timestamp, "TIME_LAST_DOWNSTR_CONN", "Time of last downstream connect" },
	[COUNTER_ID_TIME_LAST_SSA_MAD_RCV] = { ssa_counter_timestamp, "TIME_LAST_SSA_MAD_RCV", "Time of last MAD received" },
	[COUNTER_ID_TIME_LAST_ERR] = { ssa_counter_timestamp, "TIME_LAST_ERR", "Time of last error" },
};


static void counter_print_help(FILE *stream)
{
	int i;

	printf("counter is a command for gathering runtime information from a SSA node.\n");
	printf("Supported counters:\n");

	for (i = 0; i < ARRAY_SIZE(counters_descr); ++i) {
		if (counters_descr[i].type != ssa_counter_obsolete)
			printf("%-25s %-10s %s\n",
			       counters_descr[i].name,
			       ssa_counter_type_names[counters_descr[i].type],
			       counters_descr[i].description);
	}

	printf("\n\n");
}

int counter_command_create_msg(struct admin_command *cmd,
			       struct admin_context *ctx,
			       struct ssa_admin_msg *msg)
{
	struct ssa_admin_counter *counter_msg = &msg->data.counter;
	uint16_t n;

	counter_msg->n = htons(COUNTER_ID_LAST);
	n = ntohs(msg->hdr.len) + sizeof(*counter_msg);
	msg->hdr.len = htons(n);

	return 0;
}

static void counter_command_output(struct admin_command *cmd,
				   struct admin_context *ctx,
				   const struct ssa_admin_msg *msg)
{
	int i, n;
	struct ssa_admin_counter *counter_msg = (struct ssa_admin_counter *)&msg->data.counter;
	struct timeval epoch, timestamp;
	time_t timestamp_time;
	struct tm *timestamp_tm;
	char tm_buf[64], buf[64];
	long val;

	n = min(COUNTER_ID_LAST, ntohs(counter_msg->n));

	epoch.tv_sec = ntohll(counter_msg->epoch_tv_sec);
	epoch.tv_usec = ntohll(counter_msg->epoch_tv_usec);

	for (i = 0; i < n; ++i) {
		val = ntohll(counter_msg->vals[i]);

		if (val >= 0) {
			switch (counters_descr[i].type) {
				case ssa_counter_obsolete:
					continue;
					break;
				case ssa_counter_numeric:
					printf("%s %ld\n", counters_descr[i].name, val);
					break;
				case ssa_counter_timestamp:
					timestamp.tv_sec = epoch.tv_sec + val / 1000;
					timestamp.tv_usec = epoch.tv_usec + (val % 1000) * 1000;
					timestamp_time =  timestamp.tv_sec;
					timestamp_tm = localtime(&timestamp_time);
					strftime(tm_buf, sizeof tm_buf, "%Y-%m-%d %H:%M:%S", timestamp_tm);
					snprintf(buf, sizeof buf, "%s.%06d", tm_buf, (int) timestamp.tv_usec);
					printf("%s %s\n", counters_descr[i].name, buf);
					break;
				default:
					continue;
			};
		}
	}
}

struct cmd_opts *admin_get_cmd_opts(int cmd)
{
	struct cmd_struct_impl *impl;

	if (cmd <= SSA_ADMIN_CMD_NONE || cmd >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd);
		return NULL;
	}

	impl = &admin_cmd_command_impls[cmd];

	return impl->opts;
}

const struct cmd_help *admin_cmd_help(int cmd)
{
	struct cmd_struct_impl *impl;

	if (cmd <= SSA_ADMIN_CMD_NONE || cmd >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd);
		return NULL;
	}

	impl = &admin_cmd_command_impls[cmd];

	return &impl->help;
}

int admin_exec(int cmd, int argc, char **argv)
{
	struct ssa_admin_msg msg;
	struct admin_command *admin_cmd;
	struct cmd_struct_impl *cmd_impl;
	struct admin_context context;
	int ret, len;
	struct pollfd fds[1];

	if (cmd <= SSA_ADMIN_CMD_NONE || cmd >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd);
		return -1;
	}

	if (rsock < 0) {
		fprintf(stderr, "WARNING - no connection was established\n");
		return -1;
	}

	cmd_impl = &admin_cmd_command_impls[cmd];

	if (!cmd_impl->init || !cmd_impl->destroy ||
	    !cmd_impl->create_request || !cmd_impl->handle_response)
		return -1;

	admin_cmd = cmd_impl->init(cmd, &context, argc, argv);
	if (!admin_cmd)
		return -1;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.version	= SSA_ADMIN_PROTOCOL_VERSION;
	msg.hdr.method	= SSA_ADMIN_METHOD_GET;
	msg.hdr.opcode	= htons(admin_cmd->cmd->id);
	msg.hdr.len	= htons(sizeof(msg.hdr));

	ret = admin_cmd->impl->create_request(admin_cmd, &context, &msg);
	if (ret < 0) {
		fprintf(stderr, "message creation error\n");
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	context.stime = get_timestamp();

	ret = rsend(rsock, &msg, sizeof(msg), 0);
	if (ret < 0 || ret != sizeof(msg)) {
		fprintf(stderr, "rsend rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	fds[0].fd = rsock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
#if 0
recv:
#endif
	ret = rpoll(&fds[0], 1, 1000);
	if (ret < 0) {
		fprintf(stderr, "rpoll rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		cmd_impl->destroy(admin_cmd);
		return -1;

	} else if (ret == 0) {
		fprintf(stderr, "timeout expired\n");
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	if (fds[0].revents & (POLLERR | /*POLLHUP |*/ POLLNVAL)) {
		fprintf(stderr, "error event 0x%x on rsock %d\n",
			fds[0].revents, fds[0].fd);
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	ret = rrecv(rsock, &msg, sizeof(msg.hdr), 0);
	if (ret != sizeof(msg.hdr)) {
#if 0
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			do_poll(rsock);
			goto recv;
		}
#endif
		fprintf(stderr, "rrecv rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	len = ntohs(msg.hdr.len);
	if (len > sizeof(msg.hdr)) {
		ret += rrecv(rsock, (char *) &msg.data, len - sizeof(msg.hdr), 0);
		if (ret != len) {
			fprintf(stderr, "%d out of %d bytes read from SSA node\n",
				ret, len);
			cmd_impl->destroy(admin_cmd);
			return -1;
		}
	}

	context.etime = get_timestamp();

	if (msg.hdr.status != SSA_ADMIN_STATUS_SUCCESS) {
		fprintf(stderr, "ERROR - target SSA node failed to process request\n");
		ret = -1;
	} else if (msg.hdr.method != SSA_ADMIN_METHOD_RESP) {
		fprintf(stderr, "ERROR - response has wrong method\n");
		ret = -1;
	} else {
		cmd_impl->handle_response(admin_cmd, &context, &msg);
		ret = 0;
	}

	cmd_impl->destroy(admin_cmd);

	return ret;
}
