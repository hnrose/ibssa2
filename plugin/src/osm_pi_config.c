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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "osm_pi_config.h"

/**
 * return 1 if config updated
 */
static int load_config(const char * conf_file, struct ibssa_config * conf)
{
	char buf[1024];
	FILE *config_fd = NULL;
	char *p_prefix, *p_last;
	char *name;
	char *val_str;
	struct stat statbuf;

	/* silently ignore missing config or old config file */
	if (stat(conf_file, &statbuf))
		return 0;
	if (conf->timestamp && conf->timestamp >= statbuf.st_mtime)
		return 0;

	config_fd = fopen(conf_file, "r");
	if (!config_fd)
		return 0;

	while (fgets(buf, sizeof buf, config_fd) != NULL) {
		p_prefix = strtok_r(buf, "\n", &p_last);
		if (!p_prefix)
			continue; /* ignore blank lines */

		if (*p_prefix == '#')
			continue; /* ignore comment lines */

		name = strtok_r(p_prefix, "=", &p_last);
		val_str = strtok_r(NULL, "\n", &p_last);

		if (strncmp(name, "log_file", strlen("log_file")) == 0) {
			free(conf->log_file);
			conf->log_file = strdup(val_str);
		} else if (strncmp(name, "log_level", strlen("log_level")) == 0) {
			conf->log_level = (int)strtoul(val_str, NULL, 0);
		}
	}

	conf->timestamp = time(NULL);

	fclose(config_fd);
	return 1;
}

static struct ibssa_config config = {
	timestamp : 0,
	log_file : DEF_LOG_FILE,
	log_level : DEF_LOG_LEVEL,
};

struct ibssa_config * read_config(void)
{
	load_config(DEF_CONFIG_FILE, &config);
	return (&config);
}

struct ibssa_config * get_config(void)
{
	return (&config);
}

