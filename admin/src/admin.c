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

#include <config.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#include "libadmin.h"
#include <osd.h>
#include <ssa_admin.h>

static int src_port = -1;
static int admin_port;
static const char *ca_name;
static char *dest_gid;
static uint16_t dest_lid;
static uint16_t pkey;
static int timeout = 1000;
static short recursive = ADMIN_RECURSION_NONE;

struct cmd_struct admin_cmds[] = {
	[SSA_ADMIN_CMD_STATS]= { "stats",     SSA_ADMIN_CMD_STATS,     CMD_TYPE_MONITOR },
	[SSA_ADMIN_CMD_PING] = { "ping",        SSA_ADMIN_CMD_PING,        CMD_TYPE_DEBUG   },
	[SSA_ADMIN_CMD_NONE] = { "help",        SSA_ADMIN_CMD_NONE,        CMD_TYPE_NONE    },
	[SSA_ADMIN_CMD_NODEINFO] = { "nodeinfo",        SSA_ADMIN_CMD_NODEINFO, CMD_TYPE_MONITOR },
	[SSA_ADMIN_CMD_DISCONNECT] = { "disconnect", SSA_ADMIN_CMD_DISCONNECT, CMD_TYPE_DEBUG },
};

static const char *const short_option = "rl:g:d:P:p:a:t:vh?";
static struct option long_option[] = {
	{"lid",          required_argument, 0, 'l'},
	{"gid",          required_argument, 0, 'g'},
	{"device",       required_argument, 0, 'd'},
	{"Port",         required_argument, 0, 'P'},
	{"pkey",         required_argument, 0, 'p'},
	{"admin_port",   required_argument, 0, 'a'},
	{"version",      no_argument,       0, 'v'},
	{"help",         no_argument,       0, 'h'},
	{"recursive",    optional_argument, 0, 'r'},
	{"timeout",      required_argument, 0, 't'},
	{0, 0, 0, 0}	/* Required at the end of the array */
};

static const char admin_usage_string[] =
	"ssadmin  [-v | --version] [-h | --help] [[-l | --lid] <dlid>] [[-g | --gid] <dgid>]\n"
	"\t\t[[-d | --device] <device name>] [[-P | --Port] <CA port>] \n"
	"\t\t[[-p | --pkey] <partition key>] [[-a | --admin_port] <admin server port>]\n"
	"\t\t[[-t | --timeout] <operation timeout>] [-r | --recursive=[d|u]]";

static const char admin_more_info_string[] =
	"'ssadmin help <command>' shows specific subcommand "
	"concept and usage.";

static void show_version()
{
	printf("SSA Admin version " IB_SSA_VERSION "\n");
}

static void show_usage()
{
	struct cmd_struct *cmd;
	unsigned int i;

	printf("usage: %s\n\t\t<command> [<command args>]\n\n",
	       admin_usage_string);

	printf("Monitoring commands:\n");
	for (i = 0; i < ARRAY_SIZE(admin_cmds); i++) {
		cmd = admin_cmds + i;
		if (cmd->type != CMD_TYPE_MONITOR)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("Management commands:\n");
	for (i = 0; i < ARRAY_SIZE(admin_cmds); i++) {
		cmd = admin_cmds + i;
		if (cmd->type != CMD_TYPE_MANAGEMENT)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("Debug and verification commands:\n");
	for (i = 0; i < ARRAY_SIZE(admin_cmds); i++) {
		cmd = admin_cmds + i;
		if (cmd->type != CMD_TYPE_DEBUG)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("%s\n", admin_more_info_string);
	printf("--version, -v\n\tDisplay version.\n");
	printf("--help, -h, -?\n\tDisplay this usage info then exit.\n");
}

static void show_cmd_usage(const char *cmd_name,
			   const struct cmd_help *help_funcs,
			   struct cmd_opts *opts)
{
	char buf[256];
	int i = 0, n = 0;

	if (!opts || !help_funcs)
		return;

	memset(buf, 0, sizeof(buf));

	if (help_funcs->print_help)
		help_funcs->print_help(stdout);
	else
		printf("%s\n", help_funcs->desc);

	while (opts[i].op.name && n < 256) {
		if (opts[i].op.has_arg) {
			n += sprintf(buf + n, " [-%c|--%s=<%s>]",
				     opts[i].op.val,
				     opts[i].op.name,
				     opts[i].desc);
		} else {
			n += sprintf(buf + n, " [-%c|--%s]",
				     opts[i].op.val,
				     opts[i].op.name);
		}

		i++;
	}

	if (help_funcs->print_usage) {
		printf("usage: %s\n"
		       "\t\t%s %s\n\n",
		       admin_usage_string, cmd_name, buf);
		help_funcs->print_usage(stdout);
	}
}

static int get_opt_num()
{
	struct cmd_opts *opts;
	unsigned int i, j = 0;
	int opt_num = 0;

	for (i = 0; i < ARRAY_SIZE(admin_cmds); j = 0, i++) {
		if (admin_cmds[i].id <= SSA_ADMIN_CMD_NONE ||
		    admin_cmds[i].id >= SSA_ADMIN_CMD_MAX)
			continue;

		opts = admin_get_cmd_opts(admin_cmds[i].id);
		while (opts[j++].op.name)
			opt_num++;
	}

	return opt_num;
}

static int get_long_opts(struct option *opts_arr, int len)
{
	struct cmd_opts *opts;
	unsigned int i, j = 0;
	int n = 0;

	for (i = 0; i < ARRAY_SIZE(admin_cmds); j = 0, i++) {
		if (admin_cmds[i].id <= SSA_ADMIN_CMD_NONE ||
		    admin_cmds[i].id >= SSA_ADMIN_CMD_MAX)
			continue;

		opts = admin_get_cmd_opts(admin_cmds[i].id);
		while (opts[j].op.name && n < len)
			opts_arr[n++] = opts[j++].op;
	}

	return n;
}

static int get_short_opts(char *buf, int len)
{
	struct cmd_opts *opts;
	unsigned int i, j = 0;
	int n = 0;

	for (i = 0; i < ARRAY_SIZE(admin_cmds); j = 0, i++) {
		if (admin_cmds[i].id <= SSA_ADMIN_CMD_NONE ||
		    admin_cmds[i].id >= SSA_ADMIN_CMD_MAX)
			continue;

		opts = admin_get_cmd_opts(admin_cmds[i].id);
		while (opts[j].op.name && n < len) {
			n += sprintf(buf + n, "%c",
				     opts[j].op.val);

			if (opts[j].op.has_arg && n < len)
				n += sprintf(buf + n, ":");

			j++;
		}
	}

	return 0;
}

static int parse_opts(int argc, char **argv, int *status)
{
	struct option *long_option_arr = NULL;
	int option, opt_num, n, i = 0, ret = 0;
	char buf[256] = { 0 };
	char *endptr;
	long int tmp;

	if (argc <= 1) {
		show_usage();
		*status = -1;
		ret = 1;
		goto out;
	}

	get_short_opts(buf, 256 - strlen(short_option));
	sprintf(buf + strlen(buf), "%s", short_option);

	opt_num = get_opt_num() + ARRAY_SIZE(long_option);
	long_option_arr = calloc(1, opt_num * sizeof(*long_option_arr));
	if (!long_option_arr) {
		fprintf(stderr, "ERROR - unable to allocate memory for parser\n");
		*status = -1;
		ret = 1;
		goto out;
	}

	n = get_long_opts(long_option_arr, opt_num);
	while (long_option[i].name && n + i < opt_num) {
		long_option_arr[n + i] = long_option[i];
		i++;
	}

	do {
		option = getopt_long(argc, argv, buf,
				     long_option_arr, NULL);
		switch (option) {
		case 'l':
			tmp = strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "ERROR - no digits were found in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (errno == ERANGE &&
			    (tmp == LONG_MAX || tmp == LONG_MIN)) {
				fprintf(stderr, "ERROR - out of range in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (tmp < 0 || tmp >= IB_LID_MCAST_START) {
				fprintf(stderr, "ERROR - invalid lid %ld in option -l\n", tmp);
				ret = 1;
				goto out;
			}

			dest_lid = tmp;

			break;
		case 'g':
			dest_gid = optarg;
			break;
		case 'v':
			show_version();
			*status = 0;
			ret = 1;
			goto out;
		case 'd':
			ca_name = optarg;
			break;
		case 'P':
			tmp = strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "ERROR - no digits were found in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (errno == ERANGE &&
			    (tmp == LONG_MAX || tmp == LONG_MIN)) {
				fprintf(stderr, "ERROR - out of range in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (tmp < 0) {
				fprintf(stderr, "ERROR - invalid value %ld in option -%c\n", tmp, option);
				ret = 1;
				goto out;
			}
			src_port = tmp;
			break;
		case 't':
			tmp = strtol(optarg, &endptr, 10);
			if (endptr == optarg) {
				fprintf(stderr, "ERROR - no digits were found in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (errno == ERANGE &&
			    (tmp = LONG_MAX || tmp == LONG_MIN)) {
				fprintf(stderr, "ERROR - out of range in option -%c\n", option);
				ret = 1;
				goto out;
			}
			if (tmp < 0)
				fprintf(stderr, "WARNING - infinite timeout is used\n");
			else if (tmp == 0)
				fprintf(stderr, "WARNING - operation timeout is 0\n");

			timeout = tmp;
			break;
		case 'p':
			pkey = (uint16_t) strtoul(optarg, NULL, 0);
			break;
		case 'a':
			admin_port = atoi(optarg);
			break;
		case 'r':
			if (!optarg || !strcmp(optarg, "d")) {
				recursive = ADMIN_RECURSION_DOWN;
			} else if (!strcmp(optarg, "u")) {
				recursive = ADMIN_RECURSION_UP;
			} else {
				fprintf(stderr, "ERROR - out of range in option -%c\n", option);
				ret = 1;
				goto out;
			}
			break;
		case '?':
		case 'h':
			show_usage();
			*status = 0;
			ret = 1;
			goto out;
		default:
			break;
		}
	} while (option != -1);

	if (dest_lid && dest_gid) {
		fprintf(stderr, "Destination address ambiguity: "
			"both GID and LID are specified\n");
		*status = -1;
		ret = 1;
		goto out;
	}

	if (optind == argc) {
		fprintf(stderr, "No command specified\n");
		show_usage();
		*status = -1;
		ret = 1;
		goto out;
	}
out:
	if (long_option_arr)
		free(long_option_arr);
	return ret;
}

int main(int argc, char **argv)
{
	void *dest_addr;
	struct cmd_struct *cmd;
	struct admin_opts opts;
	int i, ret, addr_type, status = 0;
	int cmd_num = ARRAY_SIZE(admin_cmds);
	int rsock;

	ret = parse_opts(argc, argv, &status);
	if (ret)
		exit(status);

	for (i = 0; i < cmd_num; i++) {
		cmd = admin_cmds + i;
		if (!strncmp(argv[optind], cmd->cmd, strlen(cmd->cmd)))
			break;
	}

	if (i == cmd_num) {
		fprintf(stderr, "Non-existing command specified\n");
		show_usage();
		exit(-1);
	}

	if (!strncmp(cmd->cmd, "help", 4)) {
		if (argc - optind <= 1) {
			fprintf(stderr, "No command was specified\n");
			exit(-1);
		}

		for (i = 0; i < cmd_num; i++) {
			cmd = admin_cmds + i;
			if (!strncmp(argv[optind + 1], cmd->cmd,
				     strlen(cmd->cmd)))
				break;
		}

		if (i == cmd_num) {
			fprintf(stderr, "Non-existing command specified\n");
			show_usage();
			exit(-1);
		}

		if (cmd)
			show_cmd_usage(cmd->cmd, admin_cmd_help(cmd->id),
				       admin_get_cmd_opts(cmd->id));

		exit(0);
	}

	if (dest_lid) {
		dest_addr = &dest_lid;
		addr_type = ADMIN_ADDR_TYPE_LID;
	} else {
		if (!dest_gid)
			dest_gid = "::1"; /* local host GID */
		dest_addr = dest_gid;
		addr_type = ADMIN_ADDR_TYPE_GID;
	}

	if (admin_init(short_option, long_option) < 0) {
		fprintf(stderr, "ERROR - unable to init admin client\n");
		exit(-1);
	}

	opts.dev = ca_name;
	opts.src_port = src_port;
	opts.admin_port = admin_port;
	opts.pkey = pkey;
	opts.timeout = timeout;

	rsock = admin_connect(dest_addr, addr_type, &opts);
	if (rsock < 0) {
		fprintf(stderr, "ERROR - unable to connect\n");
		exit(-1);
	}

	optind = 1;
	ret = admin_exec_recursive(rsock, cmd->id, recursive, argc, argv);
	if (ret) {
		fprintf(stderr, "Failed executing '%s' command (%s)\n",
		       cmd->cmd, admin_cmd_help(cmd->id)->desc);
		exit(-1);
	}

	admin_disconnect(rsock);
	admin_cleanup();

	return 0;
}
