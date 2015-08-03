/*
 * Copyright (c) 2012-2015 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2012-2013 Intel Corporation. All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <syslog.h>
#include <search.h>
#include <common.h>
#include <inttypes.h>
#include <ssa_log.h>
#include <infiniband/ssa_mad.h>
#include <infiniband/ssa_db_helper.h>
#include <ssa_ctrl.h>

/*
 * Service options - may be set through ibssa_opts.cfg file.
 */
static char *opts_file = RDMA_CONF_DIR "/" SSA_OPTS_FILE;
static int node_type = SSA_NODE_ACCESS;
static char log_file[128] = "/var/log/ibssa.log";
static char lock_file[128] = "/var/run/ibssa.pid";

extern int log_flush;
extern int accum_log_file;
extern int smdb_dump;
extern int err_smdb_dump;
extern int prdb_dump;
extern char smdb_dump_dir[128];
extern char prdb_dump_dir[128];
extern short smdb_port;
extern short prdb_port;
extern short admin_port;
extern int keepalive;
#ifdef SIM_SUPPORT_FAKE_ACM
extern int fake_acm_num;
#endif
extern int reconnect_timeout;
extern int reconnect_max_count;
extern int rejoin_timeout;

struct ssa_distrib {
	struct ssa_svc			svc;
};

static struct ssa_class ssa;
pthread_t ctrl_thread;


static void distrib_process_parent_set(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	/* First, handle set of parent in SSA */
	ssa_upstream_mad(svc, msg);

	/* Now, initiate rsocket client connection to parent */
	if (svc->state == SSA_STATE_HAVE_PARENT)
		ssa_ctrl_conn(svc->port->dev->ssa, svc);
}

static int distrib_process_ssa_mad(struct ssa_svc *svc,
				   struct ssa_ctrl_msg_buf *msg)
{
	struct ssa_umad *umad;

	umad = &msg->data.umad;
	if (umad->umad.status) {
		ssa_log(SSA_LOG_DEFAULT,
			"SSA MAD method 0x%x (%s) attribute 0x%x (%s) received with status 0x%x\n",
			umad->packet.mad_hdr.method,
			ssa_method_str(umad->packet.mad_hdr.method),
			ntohs(umad->packet.mad_hdr.attr_id),
			ssa_attribute_str(umad->packet.mad_hdr.attr_id),
			umad->umad.status);
		return 0;
	}

	switch (umad->packet.mad_hdr.method) {
	case UMAD_METHOD_SET:
		if (ntohs(umad->packet.mad_hdr.attr_id) == SSA_ATTR_INFO_REC) {
			distrib_process_parent_set(svc, msg);
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int distrib_process_msg(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg)
{
	ssa_log(SSA_LOG_VERBOSE | SSA_LOG_CTRL, "%s\n", svc->name);
	switch(msg->hdr.type) {
	case SSA_CTRL_MAD:
		return distrib_process_ssa_mad(svc, msg);
	case SSA_DB_UPDATE:
		ssa_log(SSA_LOG_DEFAULT, "SSA DB update ssa_db %p epoch 0x%" PRIx64 "\n", ((struct ssa_db_update_msg *)msg)->db_upd.db, ((struct ssa_db_update_msg *)msg)->db_upd.epoch);
		if (smdb_dump)
			ssa_db_save(smdb_dump_dir,
				    (struct ssa_db *)(((struct ssa_db_update_msg *)msg)->db_upd.db),
				    smdb_dump);
		return 1;
	case SSA_CTRL_DEV_EVENT:
	case SSA_CONN_REQ:
	case SSA_CONN_DONE:
	case SSA_CONN_GONE:
		break;
	default:
		ssa_log_warn(SSA_LOG_CTRL,
			     "ignoring unexpected message type %d\n",
			     msg->hdr.type);
		break;
	}
	return 0;
}

static int distrib_init_svc(struct ssa_svc *svc)
{
	return 0;
}

static void distrib_destroy_svc(struct ssa_svc *svc)
{
}

static void *distrib_ctrl_handler(void *context)
{
	struct ssa_svc *svc;
	struct ssa_port *port;
	int ret, d, p;

	SET_THREAD_NAME(ctrl_thread, "CTRL");

	ssa_log(SSA_LOG_VERBOSE, "starting SSA framework\n");
	ret = ssa_open_devices(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR opening devices\n");
		return NULL;
	}

	for (d = 0; d < ssa.dev_cnt; d++) {
		for (p = 1; p <= ssa_dev(&ssa, d)->port_cnt; p++) {
			port = ssa_dev_port(ssa_dev(&ssa, d), p);
			if (port->link_layer != IBV_LINK_LAYER_INFINIBAND)
				continue;

			svc = ssa_start_svc(port, SSA_DB_PATH_DATA,
					    sizeof(struct ssa_distrib),
					    distrib_process_msg,
					    distrib_init_svc,
					    distrib_destroy_svc);
			if (!svc) {
				ssa_log(SSA_LOG_DEFAULT, "ERROR starting service\n");
				goto close;
			}
		}
	}

	ret = ssa_start_access(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR starting access thread\n");
		goto close;
	}

	ret = ssa_start_admin(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR starting admin thread\n");
		goto close;
	}

	ret = ssa_ctrl_run(&ssa);
	if (ret) {
		ssa_log(SSA_LOG_DEFAULT, "ERROR processing control\n");
		ssa_stop_access(&ssa);
		goto close;
	}
close:
	ssa_log(SSA_LOG_VERBOSE, "closing SSA framework\n");
	ssa_stop_admin();
	ssa_close_devices(&ssa);
	return context;
}

static int distrib_convert_node_type(const char *node_type_string)
{
	int node_type = SSA_NODE_ACCESS;

	if (!strcasecmp("distrib", node_type_string))
		node_type = SSA_NODE_DISTRIBUTION;
	if (!strcasecmp("combined", node_type_string))
		node_type |= SSA_NODE_DISTRIBUTION;
	return node_type;
}

static void distrib_set_options(void)
{
	FILE *f;
	char s[160];
	char opt[32], value[128];

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%31s%127s", opt, value) != 2)
			continue;

		if (!strcasecmp("log_file", opt))
			strcpy(log_file, value);
		else if (!strcasecmp("log_level", opt))
			ssa_set_log_level(atoi(value));
		else if (!strcasecmp("log_flush", opt))
			log_flush = atoi(value);
		else if (!strcasecmp("accum_log_file", opt))
			accum_log_file = atoi(value);
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("smdb_dump_dir", opt))
			strcpy(smdb_dump_dir, value);
		else if (!strcasecmp("prdb_dump_dir", opt))
			strcpy(prdb_dump_dir, value);
		else if (!strcasecmp("node_type", opt))
			node_type = distrib_convert_node_type(value);
		else if (!strcasecmp("smdb_dump", opt))
			smdb_dump = atoi(value);
		else if (!strcasecmp("err_smdb_dump", opt))
			err_smdb_dump = atoi(value);
		else if (!strcasecmp("prdb_dump", opt))
			prdb_dump = atoi(value);
		else if (!strcasecmp("smdb_port", opt))
			smdb_port = (short) atoi(value);
		else if (!strcasecmp("prdb_port", opt))
			prdb_port = (short) atoi(value);
		else if (!strcasecmp("keepalive", opt))
			keepalive = atoi(value);
#ifdef SIM_SUPPORT_FAKE_ACM
		else if (!strcasecmp("fake_acm_num", opt))
			fake_acm_num = atoi(value);
#endif
		else if (!strcasecmp("reconnect_max_count", opt))
			 reconnect_max_count = atoi(value);
		else if (!strcasecmp("reconnect_timeout", opt))
			 reconnect_timeout = atoi(value);
		else if (!strcasecmp("rejoin_timeout", opt))
			 rejoin_timeout = atoi(value);
	}

	fclose(f);
}

static void distrib_log_options(void)
{
	ssa_log_options();
	ssa_log(SSA_LOG_DEFAULT, "config file %s\n", opts_file);
	ssa_log(SSA_LOG_DEFAULT, "lock file %s\n", lock_file);
	ssa_log(SSA_LOG_DEFAULT, "node type %d (%s)\n", node_type,
		ssa_node_type_str(node_type));
	ssa_log(SSA_LOG_DEFAULT, "smdb dump %d\n", smdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "err smdb dump %d\n", err_smdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "smdb dump dir %s\n", smdb_dump_dir);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump %d\n", prdb_dump);
	ssa_log(SSA_LOG_DEFAULT, "prdb dump dir %s\n", prdb_dump_dir);
	ssa_log(SSA_LOG_DEFAULT, "smdb port %u\n", smdb_port);
	ssa_log(SSA_LOG_DEFAULT, "prdb port %u\n", prdb_port);
	ssa_log(SSA_LOG_DEFAULT, "admin port %u\n", admin_port);
	ssa_log(SSA_LOG_DEFAULT, "keepalive time %d\n", keepalive);
#ifdef SIM_SUPPORT_FAKE_ACM
	if (node_type & SSA_NODE_ACCESS) {
		ssa_log(SSA_LOG_DEFAULT, "running in ACM clients simulated mode\n");
		if (fake_acm_num >= 0)
			ssa_log(SSA_LOG_DEFAULT, "Max. number of simulated"
				" clients is %d\n", fake_acm_num);
		else
			ssa_log(SSA_LOG_DEFAULT, "Max. number of simulated"
				" clients is unlimited\n");
	}
#endif
	if (reconnect_max_count < 0 || reconnect_timeout < 0) {
		ssa_log(SSA_LOG_DEFAULT, "reconnection to upstream node disabled\n");
	} else {
		ssa_log(SSA_LOG_DEFAULT, "max. number of reconnections to upstream node %d\n", reconnect_max_count);

		ssa_log(SSA_LOG_DEFAULT, "timeout between reconnections (in sec.) %d\n", reconnect_timeout);
	}

	if (rejoin_timeout < 0)
		ssa_log(SSA_LOG_DEFAULT, "rejoin to distribution tree after previous request failure disabled\n");
	else
		ssa_log(SSA_LOG_DEFAULT, "timeout before next join request (in sec.) %d\n", rejoin_timeout );
}

static void *distrib_construct(int node_type, unsigned short daemon)
{
	int ret;
	char msg[1024] = {};

	ret = ssa_open_lock_file(lock_file, msg, sizeof msg);
	if (ret) {
		if (!daemon)
			fprintf(stderr, "%s\n", msg);
		openlog("ibssa", LOG_PERROR | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "%s", msg);
		closelog();
		return NULL;
	}

	ret = ssa_open_log(log_file);
	if (ret) {
		ssa_close_lock_file();
		return NULL;
	}
	ssa_set_ssa_signal_handler();
	ssa_log(SSA_LOG_DEFAULT, "Scalable SA Distribution/Access\n");
	distrib_log_options();

	ret = ssa_init(&ssa, node_type, sizeof(struct ssa_device),
		       sizeof(struct ssa_port));
	if (ret) {
		ssa_close_log();
		ssa_close_lock_file();
		return NULL;
	}

	return &ssa;
}

static void distrib_destroy()
{
	ssa_log(SSA_LOG_DEFAULT, "shutting down\n");
	ssa_ctrl_stop(&ssa);
	ssa_log(SSA_LOG_CTRL, "shutting down access thread\n");
	ssa_stop_access(&ssa);
	ssa_log(SSA_LOG_CTRL, "closing devices\n");
	ssa_close_devices(&ssa);
	ssa_log(SSA_LOG_VERBOSE, "that's all folks!\n");
	ssa_cleanup(&ssa);
	ssa_close_log();
	ssa_close_lock_file();
}

static void show_usage(char *program)
{
	printf("usage: %s\n", program);
	printf("   [-P]             - run as a standard process\n");
	printf("   [-O option_file] - option configuration file\n");
	printf("                      (default %s/%s)\n", RDMA_CONF_DIR, SSA_OPTS_FILE);
	printf("   [-v]             - print ibssa version\n");
}

int main(int argc, char **argv)
{
	int op, daemon = 1;
	struct ssa_class *ssa;

	while ((op = getopt(argc, argv, "vPO:")) != -1) {
		switch (op) {
		case 'P':
			daemon = 0;
			break;
		case 'O':
			opts_file = optarg;
			break;
		case 'v':
			printf("ibssa version %s\n", IB_SSA_VERSION);
			exit(0);
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}

	if (daemon)
		ssa_daemonize();

	srand(time(NULL));

	distrib_set_options();
	ssa = distrib_construct(node_type, daemon);
	if (!ssa)
		return -1;

	pthread_create(&ctrl_thread, NULL, distrib_ctrl_handler, NULL);
	pthread_join(ctrl_thread, NULL);

	distrib_destroy();
	return 0;
}
