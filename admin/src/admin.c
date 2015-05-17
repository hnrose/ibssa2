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
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "libadmin.h"
#include <ssa_admin.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static char *dest_gid;
static uint16_t dest_lid;

enum cmd_type {
	CMD_TYPE_NONE = 1,
	CMD_TYPE_MONITOR,
	CMD_TYPE_MANAGEMENT,
	CMD_TYPE_DEBUG
};

struct cmd_struct {
	const char	*cmd;
	int		id;
	int		type;
};

static struct cmd_struct commands[] = {
	{ "counter",     SSA_ADMIN_CMD_COUNTER,     CMD_TYPE_MONITOR },
	{ "ping",        SSA_ADMIN_CMD_PING,        CMD_TYPE_DEBUG   },
	{ "help",        SSA_ADMIN_CMD_NONE,        CMD_TYPE_NONE    },
};

static void show_version()
{
	printf("SSA Admin version "SSA_ADMIN_VERSION"\n");
}

static void show_usage(char *program)
{
	struct cmd_struct *cmd;
	int i;

	printf("usage: %s [-v|--version] [--help] <command> "
	       "[-l|--lid=<dlid>] [-g|--gid=<dgid>] [<args>]\n\n", program);

	printf("Monitoring commands:\n");
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		cmd = commands + i;
		if (cmd->type != CMD_TYPE_MONITOR)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("Management commands:\n");
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		cmd = commands + i;
		if (cmd->type != CMD_TYPE_MANAGEMENT)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("Debug and verification commands:\n");
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		cmd = commands + i;
		if (cmd->type != CMD_TYPE_DEBUG)
			continue;
		printf("\t%-15s\n", cmd->cmd);
	}
	printf("\n");

	printf("'%s help <command>' shows specific subcommand "
	       "concept and usage.\n\n", program);
	printf("--version, -v\n\tDisplay version.\n");
	printf("--help, -h, -?\n\tDisplay this usage info then exit.\n");
}

static int parse_opts(int argc, char **argv, int *status)
{
	int option;
	const char *const short_option = "l:g:vh?";

	const struct option long_option[] = {
		{"lid",     required_argument, 0, 'l'},
		{"gid",     required_argument, 0, 'g'},
		{"version", no_argument,       0, 'v'},
		{"help",    no_argument,       0, 'h'},
		{0, 0, 0, 0}	/* Required at the end of the array */
	};

	if (argc <= 1) {
		show_usage(argv[0]);
		*status = -1;
		return 1;
	}

	do {
		option = getopt_long(argc, argv, short_option,
				     long_option, NULL);
		switch (option) {
		case 'l':
			dest_lid = atoi(optarg);
			break;
		case 'g':
			dest_gid = optarg;
			break;
		case 'v':
			show_version();
			*status = 0;
			return 1;
		case 'h':
			show_usage(argv[0]);
			*status = 0;
			return 1;
		case '?':
		default:
			break;
		}
	} while (option != -1);

	if (dest_lid && dest_gid) {
		printf("Destination address ambiguity: "
		       "both GID and LID are specified\n");
		*status = -1;
		return 1;
	}

	if (optind == argc) {
		printf("No command specified\n");
		show_usage(argv[0]);
		*status = -1;
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	void *dest_addr;
	struct cmd_struct *cmd;
	int i, ret, addr_type, status = 0;
	int cmd_num = ARRAY_SIZE(commands);

	ret = parse_opts(argc, argv, &status);
	if (ret)
		exit(status);

	for (i = 0; i < cmd_num; i++) {
		cmd = commands + i;
		if (!strncmp(argv[optind], cmd->cmd, strlen(cmd->cmd)))
			break;
	}

	if (i == cmd_num) {
		printf("Non-existing command specified\n");
		show_usage(argv[0]);
		exit(-1);
	}

	if (!strncmp(cmd->cmd, "help", 4)) {
		if (argc - optind <= 1) {
			printf("No command was specified\n");
			exit(-1);
		}

		for (i = 0; i < cmd_num; i++) {
			cmd = commands + i;
			if (!strncmp(argv[optind + 1], cmd->cmd,
				     strlen(cmd->cmd)))
				break;
		}

		if (i == cmd_num) {
			printf("Non-existing command specified\n");
			show_usage(argv[0]);
			exit(-1);
		}

		/* TODO: display command specific usage */

		exit(0);
	}

	if (argc - optind >= 2) {
		printf("Wrong number of arguments specified\n");
		exit(-1);
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

	if (admin_connect(dest_addr, addr_type) != 0) {
		printf("ERROR - unable to connect\n");
		exit(-1);
	}

	/* TODO: execute specified command */

	admin_disconnect();

	return 0;
}
