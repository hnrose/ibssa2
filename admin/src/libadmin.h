/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LIB_ADMIN_H
#define _LIB_ADMIN_H

#include <stdio.h>
#include <getopt.h>

enum {
	ADMIN_ADDR_TYPE_GID,
	ADMIN_ADDR_TYPE_LID
};

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

extern struct cmd_struct admin_cmds[];

struct admin_opts {
	const char	*dev;
	int		src_port;
	int		admin_port;
	uint16_t	pkey;
	int		timeout;
};

struct cmd_opts {
	struct option	op;
	char		*desc;
};

struct cmd_help {
	void (*print_help)(FILE *stream);
	void (*print_usage)(FILE *stream);
	const char *const desc;
};

int admin_init(const char *short_opts, struct option *long_opts);
void admin_cleanup();

int admin_connect(void *dest_addr, int type, struct admin_opts *opts);
void admin_disconnect();

struct cmd_opts *admin_get_cmd_opts(int cmd);
const struct cmd_help *admin_cmd_help(int cmd);
int admin_exec(int cmd, int argc, char **argv);

#endif /* _LIB_ADMIN_H */
