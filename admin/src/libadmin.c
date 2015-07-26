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
#include <common.h>
#include <infiniband/ssa_mad.h>


#define MAX_COMMAND_OPTS 20

struct cmd_exec_info {
	uint64_t stime, etime;
};

struct cmd_struct_impl;
struct admin_count_command {
	short include_list[COUNTER_ID_LAST];
};

struct admin_command {
	const struct cmd_struct_impl *impl;
	const struct cmd_struct *cmd;
	union {
		struct admin_count_command count_cmd;
	} data;
	short recursive;
};

struct cmd_struct_impl {
	struct admin_command *(*init)(int cmd_id,
				      int argc, char **argv);
	void (*destroy)(struct admin_command *admin_cmd);
	int (*create_request)(struct admin_command *admin_cmd,
			      struct ssa_admin_msg *msg);
	void (*handle_response)(struct admin_command *cmd,
				struct cmd_exec_info *exec_info,
				union ibv_gid remote_gid,
				const struct ssa_admin_msg *msg);
	struct cmd_opts opts[MAX_COMMAND_OPTS];
	struct cmd_help help;
};


static void default_destroy(struct admin_command *cmd);
static void default_print_usage(FILE *stream);
static struct admin_command *default_init(int cmd_id,
					  int argc, char **argv);
static int default_create_msg(struct admin_command *cmd,
			      struct ssa_admin_msg *msg);
static void ping_command_output(struct admin_command *cmd,
				struct cmd_exec_info *exec_info,
				union ibv_gid remote_gid,
				const struct ssa_admin_msg *msg);
static struct admin_command *counter_init(int cmd_id,
					  int argc, char **argv);
static void counter_print_help(FILE *stream);
static int counter_command_create_msg(struct admin_command *cmd,
				      struct ssa_admin_msg *msg);
static void counter_command_output(struct admin_command *cmd,
				   struct cmd_exec_info *exec_info,
				   union ibv_gid remote_gid,
				   const struct ssa_admin_msg *msg);
static int node_info_command_create_msg(struct admin_command *cmd,
					struct ssa_admin_msg *msg);
static void node_info_command_output(struct admin_command *cmd,
				     struct cmd_exec_info *exec_info,
				     union ibv_gid remote_gid,
				     const struct ssa_admin_msg *msg);

static struct cmd_struct_impl admin_cmd_command_impls[] = {
	[SSA_ADMIN_CMD_COUNTER] = {
		counter_init,
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
	},
	[SSA_ADMIN_CMD_NODE_INFO] = {
		default_init,
		default_destroy,
		node_info_command_create_msg,
		node_info_command_output,
		{},
		{ NULL, default_print_usage,
		  "Retrieve basic node info" }
	}
};

static atomic_t tid;
static short admin_port = 7477;
static uint16_t pkey_default = 0xffff;
static const char *local_gid = "::1";
static int timeout = 1000;
static  struct admin_opts global_opts;

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

	if ((port_id = umad_open_port((char *) dev, (port < 0) ? 0 : port)) < 0) {
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


static int admin_connect_init(void *dest, int type, struct admin_opts *opts)
{
	struct sockaddr_ib dst_addr;
	union ibv_gid dgid;
	int ret, val, port_id;
	int port = opts->admin_port ? opts->admin_port : admin_port;
	uint16_t pkey = opts->pkey ? opts->pkey : pkey_default;
	int rsock = -1;
	char dest_addr[64];

	timeout = opts->timeout;
	global_opts = *opts;

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

	ret = rfcntl(rsock, F_SETFL, O_NONBLOCK);
	if (ret) {
		fprintf(stderr, "rfcntl F_SETFL rsock %d ERROR %d (%s)\n",
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
		fprintf(stderr, "ERROR - rconnect rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	return rsock;

err:
	rclose(rsock);
	rsock = -1;
	return -1;
}

int admin_connect(void *dest, int type, struct admin_opts *opts)
{
	int ret, val, err;
	unsigned int len;
	struct pollfd fds;
	int rsock = -1;

	timeout = opts->timeout;
	global_opts = *opts;

	rsock = admin_connect_init(dest, type, opts);
	if (rsock < 0)
		return -1;

	if (rsock && (errno == EINPROGRESS)) {
		fds.fd = rsock;
		fds.events = POLLOUT;
		fds.revents = 0;
		ret = rpoll(&fds, 1, timeout);
		if (ret < 0) {
			fprintf(stderr, "ERROR - rpoll rsock %d ERROR %d (%s)\n",
				rsock, errno, strerror(errno));
			goto err;
		} else if (ret == 0) {
			fprintf(stderr, "ERROR - rconnect rsock %d timeout expired\n",
				rsock);
			goto err;
		}

		len = sizeof(err);
		ret = rgetsockopt(rsock, SOL_SOCKET, SO_ERROR, &err, &len);
		if (ret) {
			fprintf(stderr, "rgetsockopt rsock %d ERROR %d (%s)\n",
				rsock, errno, strerror(errno));
			goto err;
		}
		if (err) {
			ret = -1;
			errno = err;
			fprintf(stderr, "ERROR - async rconnect rsock %d ERROR %d (%s)\n",
				rsock, errno, strerror(errno));
			goto err;
		}
	}

	val = rfcntl(rsock, F_GETFL, O_NONBLOCK);
	if (val < 0) {
		fprintf(stderr, "ERROR - rfcntl F_GETFL rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	val = val & (~O_NONBLOCK);
	ret = rfcntl(rsock, F_SETFL, val);
	if (ret) {
		fprintf(stderr, "ERROR - rfcntl second F_SETFL rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	return rsock;

err:
	rclose(rsock);
	rsock = -1;
	return -1;
}

void admin_disconnect(int rsock)
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

static struct admin_command *default_init(int cmd_id, int argc, char **argv)
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
	admin_cmd->recursive = 0;

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
			      struct ssa_admin_msg *msg)
{
	return 0;
}


struct ssa_admin_counter_descr {
	const char *name;
	const char *description;
};

static void ping_command_output(struct admin_command *cmd,
				struct cmd_exec_info *exec_info,
				union ibv_gid remote_gid,
				const struct ssa_admin_msg *msg)
{
	char addr_buf[128];

	ssa_format_addr(addr_buf, sizeof addr_buf, SSA_ADDR_GID,
			remote_gid.raw, sizeof remote_gid.raw);
	printf("%lu bytes from \033[1m%s\033[0m : time=%g ms\n",
	       sizeof(*msg), addr_buf, 1e-3 * (exec_info->etime - exec_info->stime));
}

static const char *ssa_counter_type_names[] = {
	[ssa_counter_obsolete] = "Obsolete",
	[ssa_counter_numeric] = "Numeric",
	[ssa_counter_timestamp] = "Timestamp"
};

static struct ssa_admin_counter_descr counters_descr[] = {
	[COUNTER_ID_NODE_START_TIME] = {"NODE_START_TIME", "Starting time of the node" },
	[COUNTER_ID_DB_UPDATES_NUM] = {"DB_UPDATES_NUM", "Number of databases updates passed the node" },
	[COUNTER_ID_DB_LAST_UPDATE_TIME] = {"LAST_UPDATE_TIME", "Time of last database update" },
	[COUNTER_ID_DB_FIRST_UPDATE_TIME] = {"FIRST_UPDATE_TIME", "Time of first database update" },
	[COUNTER_ID_NUM_CHILDREN] = {"NUM_CHILDREN", "Number of connected downstream nodes" },
	[COUNTER_ID_NUM_ACCESS_TASKS] = {"NUM_ACCESS_TASKS", "Number of unprocessed Access tasks" },
	[COUNTER_ID_NUM_ERR] = {"NUM_ERR", "Number of errors" },
	[COUNTER_ID_LAST_ERR] = {"LAST_ERR", "Last error ID" },
	[COUNTER_ID_TIME_LAST_UPSTR_CONN] = {"TIME_LAST_UPSTR_CONN", "Time of last upstream connect" },
	[COUNTER_ID_TIME_LAST_DOWNSTR_CONN] = {"TIME_LAST_DOWNSTR_CONN", "Time of last downstream connect" },
	[COUNTER_ID_TIME_LAST_SSA_MAD_RCV] = {"TIME_LAST_SSA_MAD_RCV", "Time of last MAD received" },
	[COUNTER_ID_TIME_LAST_ERR] = {"TIME_LAST_ERR", "Time of last error" },
};


static struct admin_command *counter_init(int cmd_id, int argc, char **argv)
{
	struct admin_command *cmd = default_init(cmd_id, argc, argv);
	struct admin_count_command *count_cmd;
	int i, j;

	if (!cmd)
		return NULL;

	count_cmd = (struct admin_count_command *) &cmd->data.count_cmd;

	optind++;

	for(j = 0; j < COUNTER_ID_LAST; ++j)
		count_cmd->include_list[j] = optind == argc;

	for (i = optind; i < argc; ++i) {
		for (j = 0; j < COUNTER_ID_LAST; ++j) {
			if (!strcmp(argv[i], counters_descr[j].name)) {
				count_cmd->include_list[j] = 1;
				break;
			}
		}
		if (j == COUNTER_ID_LAST) {
			fprintf(stderr, "ERROR - Name %s isn't found in the counters list\n", argv[i]);
			cmd->impl->destroy(cmd);
			return NULL;
		}
	}

	return cmd;
}
static void counter_print_help(FILE *stream)
{
	int i;

	printf("counter is a command for gathering runtime information from a SSA node.\n");
	printf("Supported counters:\n");

	for (i = 0; i < ARRAY_SIZE(counters_descr); ++i) {
		if (ssa_admin_counters_type[i] != ssa_counter_obsolete)
			printf("%-25s %-10s %s\n",
			       counters_descr[i].name,
			       ssa_counter_type_names[ssa_admin_counters_type[i]],
			       counters_descr[i].description);
	}

	printf("\n\n");
}

int counter_command_create_msg(struct admin_command *cmd,
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
				   struct cmd_exec_info *exec_info,
				   union ibv_gid remote_gid,
				   const struct ssa_admin_msg *msg)
{
	int i, n;
	struct ssa_admin_counter *counter_msg = (struct ssa_admin_counter *) &msg->data.counter;
	struct admin_count_command *count_cmd = (struct admin_count_command *) &cmd->data.count_cmd;
	struct timeval epoch, timestamp;
	time_t timestamp_time;
	struct tm *timestamp_tm;
	long val;
	char addr_buf[128];

	n = min(COUNTER_ID_LAST, ntohs(counter_msg->n));

	epoch.tv_sec = ntohll(counter_msg->epoch_tv_sec);
	epoch.tv_usec = ntohll(counter_msg->epoch_tv_usec);

	for (i = 0; i < n; ++i) {
		if (!count_cmd->include_list[i])
			continue;

		val = ntohll(counter_msg->vals[i]);

		if (val < 0 && ssa_admin_counters_type[i] != ssa_counter_signed_numeric)
			continue;

		if (cmd->recursive && ssa_admin_counters_type[i] != ssa_counter_obsolete) {
			ssa_format_addr(addr_buf, sizeof addr_buf, SSA_ADDR_GID,
					remote_gid.raw, sizeof remote_gid.raw);
			printf("%s: ", addr_buf);
		}

		switch (ssa_admin_counters_type[i]) {
			case ssa_counter_obsolete:
				continue;
				break;
			case ssa_counter_numeric:
			case ssa_counter_signed_numeric:
				printf("%s %ld\n", counters_descr[i].name, val);
				break;
			case ssa_counter_timestamp:
				timestamp.tv_sec = epoch.tv_sec + val / 1000;
				timestamp.tv_usec = epoch.tv_usec + (val % 1000) * 1000;
				timestamp_time =  timestamp.tv_sec;
				timestamp_tm = localtime(&timestamp_time);
				printf("%s ", counters_descr[i].name);
				ssa_write_date(stdout, timestamp_time, timestamp.tv_usec);
				printf("\n");
				break;
			default:
				continue;
		};
	}
}

static int node_info_command_create_msg(struct admin_command *cmd,
					struct ssa_admin_msg *msg)
{
	struct ssa_admin_node_info *node_info_msg = (struct ssa_admin_node_info *) &msg->data.node_info;
	uint16_t n;

	n = ntohs(msg->hdr.len) + sizeof(*node_info_msg);
	msg->hdr.len = htons(n);

	return 0;
}

static const char *ssa_connection_type_names[] = {
	[SSA_CONN_TYPE_UPSTREAM] = "Upstream",
	[SSA_CONN_TYPE_DOWNSTREAM] = "Downstream",
	[SSA_CONN_TYPE_LISTEN] = "Listen"
};

static const char *ssa_database_type_names[] = {
	[SSA_CONN_NODB_TYPE] = "NODB",
	[SSA_CONN_SMDB_TYPE] = "SMDB",
	[SSA_CONN_PRDB_TYPE] = "PRDB",
};

static void node_info_command_output(struct admin_command *cmd,
				     struct cmd_exec_info *exec_info,
				     union ibv_gid remote_gid,
				     const struct ssa_admin_msg *msg)
{
	int i, n;
	char addr_buf[128];
	char node_addr_buf[128];
	struct ssa_admin_node_info *node_info_msg = (struct ssa_admin_node_info *) &msg->data.node_info;
	struct ssa_admin_connection_info *connections =
		(struct ssa_admin_connection_info *) node_info_msg->connections;
	struct timeval timestamp;
	time_t timestamp_time;
	struct tm *timestamp_tm;

	if (cmd->recursive) {
		ssa_format_addr(node_addr_buf, sizeof node_addr_buf, SSA_ADDR_GID,
				remote_gid.raw, sizeof remote_gid.raw);
		printf("%s: ", node_addr_buf);
	}

	printf("%s %s\n", ssa_node_type_str(node_info_msg->type),
	       node_info_msg->version);
	n = ntohs(node_info_msg->connections_num);

	for (i = 0; i < n; ++i) {
		ssa_format_addr(addr_buf, sizeof addr_buf, SSA_ADDR_GID,
				connections[i].remote_gid,
				sizeof connections[i].remote_gid);
		if (connections[i].connection_type < 0 ||
		    connections[i].connection_type >= ARRAY_SIZE(ssa_connection_type_names)) {
			fprintf(stderr, "ERROR - Unknown connection type \n");
			continue;
		}
		if (connections[i].dbtype < 0 ||
		    connections[i].dbtype >= ARRAY_SIZE(ssa_database_type_names)) {
			fprintf(stderr, "ERROR - Unknown database type \n");
			continue;
		}
		timestamp.tv_sec = ntohll(connections[i].connection_tv_sec);
		timestamp.tv_usec = ntohll(connections[i].connection_tv_usec);

		timestamp_time = timestamp.tv_sec;
		timestamp_tm = localtime(&timestamp_time);

		if (cmd->recursive)
			printf("%s: ", node_addr_buf);

		printf("%s %u %s %s %s ", addr_buf, ntohs(connections[i].remote_lid),
		       ssa_connection_type_names[connections[i].connection_type],
		       ssa_database_type_names[connections[i].dbtype],
		       ssa_node_type_str(connections[i].remote_type));
		ssa_write_date(stdout, timestamp_time, timestamp.tv_usec);
		printf("\n");
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

static struct ssa_admin_msg *admin_read_response(int rsock)
{
	int ret, len;
	struct ssa_admin_msg *response;

	response = (struct ssa_admin_msg *) malloc(sizeof(*response));
	if (!response) {
		fprintf(stderr, "ERROR - response allocation failed\n");
		return NULL;
	}

	ret = rrecv(rsock, response, sizeof(response->hdr), 0);
	if (ret != sizeof(response->hdr)) {
#if 0
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			do_poll(rsock);
			goto recv;
		}
#endif
		fprintf(stderr, "ERROR - rrecv rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		free(response);
		return NULL;
	}

	len = ntohs(response->hdr.len);
	if (len > sizeof(response->hdr)) {
		if (len > sizeof(*response)) {
			struct ssa_admin_msg *tmp;
			tmp = (struct ssa_admin_msg *) realloc(response, len);
			if (!tmp) {
				fprintf(stderr, "ERROR - response allocation failed\n");
				free(response);
				return NULL;
			} else {
				response = tmp;
			}
		}

		ret += rrecv(rsock, (char *) &response->data, len - sizeof(response->hdr), 0);
		if (ret != len) {
			fprintf(stderr, "ERROR - %d out of %d bytes read from SSA node\n",
				ret, len);
			free(response);
			return NULL;
		}
	}

	return response;
}

int admin_exec(int rsock, int cmd, int argc, char **argv)
{
	struct ssa_admin_msg msg;
	struct ssa_admin_msg *response;
	struct admin_command *admin_cmd;
	struct cmd_struct_impl *cmd_impl;
	struct cmd_exec_info exec_info;
	int ret;
	struct pollfd fds[1];
	struct sockaddr_ib peer_addr;
	socklen_t peer_len;
	union ibv_gid remote_gid;

	if (cmd <= SSA_ADMIN_CMD_NONE || cmd >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd);
		return -1;
	}

	if (rsock < 0) {
		fprintf(stderr, "ERROR - no connection was established\n");
		return -1;
	}

	peer_len = sizeof(peer_addr);
	if (!rgetpeername(rsock, (struct sockaddr *) &peer_addr, &peer_len)) {
		if (peer_addr.sib_family == AF_IB) {
			memcpy(&remote_gid.raw, &peer_addr.sib_addr, sizeof(union ibv_gid));
		} else {
			fprintf(stderr, "ERROR - "
				"rgetpeername fd %d family %d not AF_IB\n",
				rsock, peer_addr.sib_family);
			return -1;
		}
	} else {
		fprintf(stderr, "ERROR - "
			"rgetpeername rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		return -1;
	}

	cmd_impl = &admin_cmd_command_impls[cmd];

	if (!cmd_impl->init || !cmd_impl->destroy ||
	    !cmd_impl->create_request || !cmd_impl->handle_response) {
		fprintf(stderr, "ERROR - command creation failed\n");
		return -1;
	}

	admin_cmd = cmd_impl->init(cmd, argc, argv);
	if (!admin_cmd) {
		fprintf(stderr, "ERROR - command creation failed\n");
		return -1;
	}
	admin_cmd->recursive = 0;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.version	= SSA_ADMIN_PROTOCOL_VERSION;
	msg.hdr.method	= SSA_ADMIN_METHOD_GET;
	msg.hdr.opcode	= htons(admin_cmd->cmd->id);
	msg.hdr.len	= htons(sizeof(msg.hdr));

	ret = admin_cmd->impl->create_request(admin_cmd, &msg);
	if (ret < 0) {
		fprintf(stderr, "ERROR - message creation error\n");
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	exec_info.stime = get_timestamp();

	ret = rsend(rsock, &msg, ntohs(msg.hdr.len), 0);
	if (ret < 0 || ret != ntohs(msg.hdr.len)) {
		fprintf(stderr, "ERROR - rsend rsock %d ERROR %d (%s)\n",
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
	ret = rpoll(&fds[0], 1, timeout);
	if (ret < 0) {
		fprintf(stderr, "ERROR - rpoll rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		cmd_impl->destroy(admin_cmd);
		return -1;

	} else if (ret == 0) {
		fprintf(stderr, "ERROR - timeout expired\n");
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	if (fds[0].revents & (POLLERR | /*POLLHUP |*/ POLLNVAL)) {
		fprintf(stderr, "ERROR - error event 0x%x on rsock %d\n",
			fds[0].revents, fds[0].fd);
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	response = admin_read_response(rsock);
	if (!response) {
		cmd_impl->destroy(admin_cmd);
		return -1;
	}

	exec_info.etime = get_timestamp();

	if (response->hdr.status != SSA_ADMIN_STATUS_SUCCESS) {
		fprintf(stderr, "ERROR - target SSA node failed to process request\n");
		ret = -1;
	} else if (response->hdr.method != SSA_ADMIN_METHOD_RESP) {
		fprintf(stderr, "ERROR - response has wrong method\n");
		ret = -1;
	} else {
		cmd_impl->handle_response(admin_cmd, &exec_info, remote_gid, response);
		ret = 0;
	}

	free(response);
	cmd_impl->destroy(admin_cmd);

	return ret;
}

enum admin_connection_state {
	ADM_CONN_CONNECTING,
	ADM_CONN_NODEINFO,
	ADM_CONN_COMMAND,
};

struct admin_connection {
	union ibv_gid remote_gid;
	uint16_t remote_lid;
	enum admin_connection_state state;
	time_t epoch;
	int slen, sleft;
	struct ssa_admin_msg *smsg;
	int rlen, rcount;
	struct ssa_admin_msg *rmsg;
	struct ssa_admin_msg_hdr rhdr;
	struct cmd_exec_info exec_info;
};

static int admin_recv_buff(int rsock, char *buf, int *rcount, int rlen)
{
	int n;

	while (*rcount < rlen) {
		n = rrecv(rsock, buf + *rcount, rlen - *rcount, MSG_DONTWAIT);
		if (n > 0)
			*rcount += n;
		else if (!n)
			return -ECONNRESET;
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
			return *rcount;
		else
			return n;
	}
	return 0;
}

static int admin_recv_msg(struct pollfd *pfd, struct admin_connection *conn)
{
	int ret;

	if (conn->rcount < sizeof(conn->rhdr)) {
		ret = admin_recv_buff(pfd->fd, (char *) &conn->rhdr,
				      &conn->rcount, sizeof(conn->rhdr));
		if (ret == -ECONNRESET) {
			fprintf(stderr, "ERROR - SSA node closed admin connection\n");
			return -1;
		} else if (ret < 0) {
			fprintf(stderr,
				"ERROR - rrecv failed: %d (%s) on rsock %d\n",
				errno, strerror(errno), pfd->fd);
			return ret;
		}
		if (conn->rcount < sizeof(conn->rhdr))
			return 0;
	}

	if (conn->rcount == sizeof(conn->rhdr)) {
		if (conn->rhdr.status != SSA_ADMIN_STATUS_SUCCESS) {
			fprintf(stderr, "ERROR - target SSA node failed to process request\n");
			return -1;
		} else if (conn->rhdr.method != SSA_ADMIN_METHOD_RESP) {
			fprintf(stderr, "ERROR - response has wrong method\n");
			return -1;
		}

		conn->rlen = ntohs(conn->rhdr.len);
		conn->rmsg = (struct ssa_admin_msg *) malloc(max(sizeof(conn->rmsg),
							     conn->rlen));
		if (!conn->rmsg) {
			fprintf(stderr, "ERROR - failed allocate message buffer\n");
			return -1;
		}

		conn->rmsg->hdr = conn->rhdr;
	}

	ret = admin_recv_buff(pfd->fd, (char *) conn->rmsg,
			      &conn->rcount, conn->rlen);
	if (ret == -ECONNRESET) {
		fprintf(stderr, "ERROR - SSA node closed admin connection\n");
		return -1;
	} else if (ret < 0) {
		fprintf(stderr, "ERROR - rrecv failed: %d (%s) on rsock %d\n",
			errno, strerror(errno), pfd->fd);
		return ret;
	}

	return 0;
}

static int admin_send_msg(struct pollfd *pfd, struct admin_connection *conn)
{
	int sent = conn->slen - conn->sleft;
	int n;

	while (conn->sleft) {
		n  = rsend(pfd->fd, (char *) conn->smsg + sent, conn->sleft, MSG_DONTWAIT);
		if (n < 0)
			break;
		conn->sleft -= n;
		sent += n;
	}

	if (!conn->sleft) {
		return 0;
	} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return 0;
	} else if (n < 0)
		return n;

	return 0;
}

static void admin_update_connection_state(struct admin_connection *conn,
					  enum admin_connection_state state,
					  struct ssa_admin_msg *msg)
{
	conn->state = state;
	conn->epoch  = time(NULL);

	free(conn->rmsg);
	conn->rmsg = NULL;
	conn->rlen = 0;
	conn->rcount = 0;

	if (state == ADM_CONN_CONNECTING) {
		conn->smsg = NULL;
		conn->slen = 0;
		conn->sleft = 0;
	} else {
		conn->smsg = msg;
		conn->slen = ntohs(msg->hdr.len);
		conn->sleft = conn->slen;
	}

	conn->exec_info.stime = get_timestamp();
}

static void admin_close_connection(struct pollfd *pfd,
				   struct admin_connection *conn)
{
	if (pfd->fd > 0)
		rclose(pfd->fd);
	pfd->fd = -1;
	pfd->events = 0;
	pfd->revents = 0;

	free(conn->rmsg);
	conn->rmsg = NULL;
}

static int admin_connect_new_nodes(struct pollfd **fds,
				   struct admin_connection **admin_conns,
				   int *admin_conns_num,
				   const struct ssa_admin_msg *rmsg)
{
	int i, slot, node_conns_num, rsock;
	char addr_buf[128];
	struct ssa_admin_node_info *node_info = (struct ssa_admin_node_info *) &rmsg->data.node_info;
	struct ssa_admin_connection_info *node_conns =
		(struct ssa_admin_connection_info *) node_info->connections;
	void *tmp;

	node_conns_num = ntohs(node_info->connections_num);
	if (node_conns_num < 0) {
		fprintf(stderr, "ERROR - Negative number of SSA node's connections\n");
		return -1;
	} else if (node_conns_num  == 0) {
		return 0;
	}

	slot = 0;
	for (i = 0; i < node_conns_num; ++i) {
		if (node_conns[i].connection_type == SSA_CONN_TYPE_DOWNSTREAM) {
			for (; slot < *admin_conns_num && (*fds)[slot].fd > 0; slot++);

			if (slot == *admin_conns_num) {
				tmp = realloc(*fds, 2 * *admin_conns_num * sizeof(**fds));
				if (!tmp) {
					fprintf(stderr, "ERROR - failed reallocate pfds array\n");
					return -1;
				}

				*fds = (struct pollfd *) tmp;

				tmp = realloc(*admin_conns, 2 * *admin_conns_num * sizeof(**admin_conns));
				if (!tmp) {
					fprintf(stderr, "ERROR - failed reallocate connections array\n");
					return -1;
				}

				*admin_conns_num *= 2;
			}

			ssa_format_addr(addr_buf, sizeof addr_buf, SSA_ADDR_GID,
					node_conns[i].remote_gid,
					sizeof node_conns[i].remote_gid);
			rsock = admin_connect_init(addr_buf, ADMIN_ADDR_TYPE_GID, &global_opts);
			if (rsock < 0 && (errno != EINPROGRESS)) {
				fprintf(stderr, "ERROR - Unable connect to %s\n", addr_buf);
				continue;
			}

			(*fds)[slot].fd = rsock;
			(*fds)[slot].events = POLLOUT;
			(*fds)[slot].revents = 0;

			admin_update_connection_state(*admin_conns + slot, ADM_CONN_CONNECTING, NULL);
			(*admin_conns)[slot].remote_lid = ntohs(node_conns[i].remote_lid);
			memcpy((*admin_conns)[slot].remote_gid.raw,
			       &node_conns[i].remote_gid,
			       sizeof((*admin_conns)[slot].remote_gid.raw));
		}
	}
	return 0;
}

int admin_exec_recursive(int rsock, int cmd, int argc, char **argv)
{
	struct cmd_struct_impl *nodeinfo_impl;
	struct admin_command *nodeinfo_cmd;
	struct ssa_admin_msg nodeinfo_msg, msg;
	struct admin_command *admin_cmd = NULL;
	struct cmd_struct_impl *cmd_impl = NULL;
	int n = 1024, ret, i, revents, err;
	struct pollfd *fds;
	unsigned int len;
	struct admin_connection *connections;
	struct sockaddr_ib peer_addr;
	socklen_t peer_len;

	if (cmd <= SSA_ADMIN_CMD_NONE || cmd >= SSA_ADMIN_CMD_MAX) {
		fprintf(stderr, "ERROR - command index %d is out of range\n", cmd);
		return -1;
	}

	fds = (struct pollfd *) malloc(n * sizeof(*fds));
	if (!fds) {
		fprintf(stderr, "ERROR - failed to allocate pollfd array\n");
		return -1;
	}

	for (i = 0; i < n; ++i) {
		fds[i].fd = -1;
		fds[i].events = 0;
		fds[i].revents = 0;
	}

	connections = (struct admin_connection *) malloc(n * sizeof(*connections));
	if (!connections) {
		fprintf(stderr, "ERROR - failed to allocate admin connections array\n");
		free(fds);
		return -1;
	}

	memset(connections, 0, n * sizeof(*connections));

	nodeinfo_impl = &admin_cmd_command_impls[SSA_ADMIN_CMD_NODE_INFO];
	nodeinfo_cmd = nodeinfo_impl->init(SSA_ADMIN_CMD_NODE_INFO, 0, NULL);
	if (!nodeinfo_cmd) {
		fprintf(stderr, "ERROR - failed to create nodeinfo command\n");
		free(connections);
		free(fds);
		return -1;
	}

	memset(&nodeinfo_msg, 0, sizeof(nodeinfo_msg));
	nodeinfo_msg.hdr.version= SSA_ADMIN_PROTOCOL_VERSION;
	nodeinfo_msg.hdr.method	= SSA_ADMIN_METHOD_GET;
	nodeinfo_msg.hdr.opcode	= htons(SSA_ADMIN_CMD_NODE_INFO);
	nodeinfo_msg.hdr.len	= htons(sizeof(nodeinfo_msg.hdr));

	ret = nodeinfo_impl->create_request(nodeinfo_cmd, &nodeinfo_msg);
	if (ret < 0) {
		fprintf(stderr, "ERROR - message creation error\n");
		goto err;
	}
	cmd_impl = &admin_cmd_command_impls[cmd];

	if (!cmd_impl->init || !cmd_impl->destroy ||
	    !cmd_impl->create_request || !cmd_impl->handle_response) {
		fprintf(stderr, "ERROR - command creation error\n");
		goto err;
	}

	admin_cmd = cmd_impl->init(cmd, argc, argv);
	if (!admin_cmd) {
		fprintf(stderr, "ERROR - command creation error\n");
		goto err;
	}

	memset(&msg, 0, sizeof(msg));
	msg.hdr.version	= SSA_ADMIN_PROTOCOL_VERSION;
	msg.hdr.method	= SSA_ADMIN_METHOD_GET;
	msg.hdr.opcode	= htons(admin_cmd->cmd->id);
	msg.hdr.len	= htons(sizeof(msg.hdr));

	ret = admin_cmd->impl->create_request(admin_cmd, &msg);
	if (ret < 0) {
		fprintf(stderr, "ERROR - message creation error\n");
		goto err;
	}
	admin_cmd->recursive = 1;

	fds[0].fd = rsock;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	admin_update_connection_state(&connections[0], ADM_CONN_NODEINFO, &nodeinfo_msg);

	peer_len = sizeof(peer_addr);
	if (!rgetpeername(rsock, (struct sockaddr *) &peer_addr, &peer_len)) {
		if (peer_addr.sib_family == AF_IB) {
			memcpy(&connections[0].remote_gid, &peer_addr.sib_addr, sizeof(union ibv_gid));
		} else {
			fprintf(stderr, "ERROR - "
				"rgetpeername fd %d family %d not AF_IB\n",
				rsock, peer_addr.sib_family);
			return -1;
			goto err;
		}
	} else {
		fprintf(stderr, "ERROR - "
			"rgetpeername rsock %d ERROR %d (%s)\n",
			rsock, errno, strerror(errno));
		goto err;
	}

	for(;;) {
		for (i = 0; i < n && fds[i].fd < 0; ++i);
		if (i == n)
			break;

		ret = rpoll(fds, n, timeout);
		if (ret < 0) {
			fprintf(stderr, "ERROR - rpoll rsock %d ERROR %d (%s)\n",
				rsock, errno, strerror(errno));
			goto err;

		} else if (ret == 0) {
			time_t now_epoch = time(NULL);

			for (i = 0; i < n; ++i) {
				if (fds[i].fd >= 0 && connections[i].epoch - now_epoch >= timeout) {
					fprintf(stderr, "ERROR - timeout expired\n");
					admin_close_connection(&fds[i], &connections[i]);
				}
			}
			continue;
		}

		for (i = 0; i < n; ++i) {
			if (fds[i].fd < 0 || !fds[i].revents)
				continue;

			revents = fds[i].revents;
			fds[i].revents = 0;

			connections[i].epoch = time(NULL);

			if (revents & (POLLERR /*| POLLHUP */| POLLNVAL)) {
				fprintf(stderr,
					"ERROR - error event 0x%x on rsock %d\n",
					fds[i].revents, fds[i].fd);
				admin_close_connection(&fds[i], &connections[i]);
				continue;
			}

			if (revents & POLLIN) {
				ret = admin_recv_msg(&fds[i], &connections[i]);
				if (ret) {
					admin_close_connection(&fds[i], &connections[i]);
					continue;
				} else if (connections[i].rcount != connections[i].rlen) {
					continue;
				}

				ret = 0;
				connections[i].exec_info.etime = get_timestamp();
				if (ntohs(connections[i].rmsg->hdr.opcode) == SSA_ADMIN_CMD_NODE_INFO &&
				    connections[i].state == ADM_CONN_NODEINFO) {
					ret = admin_connect_new_nodes(&fds, &connections, &n, connections[i].rmsg);
					if (ret) {
						fprintf(stderr, "WARNING - failed connect downstream nodes\n");
						continue;
					}
					if (cmd != SSA_ADMIN_CMD_NODE_INFO) {
						admin_update_connection_state(&connections[i], ADM_CONN_COMMAND, &msg);
						fds[i].events = POLLOUT;
						continue;
					}
				}
				cmd_impl->handle_response(admin_cmd, &connections[i].exec_info,
						connections[i].remote_gid, connections[i].rmsg);
				admin_close_connection(&fds[i], &connections[i]);
				continue;
			}
			if (revents & POLLOUT) {
				if (connections[i].state == ADM_CONN_CONNECTING) {
					len = sizeof(err);
					ret = rgetsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &err, &len);
					if (ret) {
						fprintf(stderr,
							"rgetsockopt rsock %d ERROR %d (%s)\n",
							fds[i].fd, errno,
							strerror(errno));
						admin_close_connection(&fds[i], &connections[i]);
						continue;
					}
					if (err) {
						ret = -1;
						errno = err;
						fprintf(stderr,
							"ERROR - async rconnect rsock %d ERROR %d (%s)\n",
							fds[i].fd, errno,
							strerror(errno));
						admin_close_connection(&fds[i], &connections[i]);
						continue;
					}

					admin_update_connection_state(&connections[i], ADM_CONN_NODEINFO, &nodeinfo_msg);
				}

				ret = admin_send_msg(&fds[i], &connections[i]);
				if (ret) {
					fprintf(stderr, "ERROR - response has wrong method\n");
					admin_close_connection(&fds[i],  &connections[i]);
				}

				if (!connections[i].sleft)
					fds[i].events = POLLIN;
			}
		}
	}
err:
	cmd_impl->destroy(admin_cmd);
	nodeinfo_impl->destroy(nodeinfo_cmd);
	free(connections);
	free(fds);

	return ret;
}
