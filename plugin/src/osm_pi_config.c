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
#include <errno.h>

#include <glib.h>
#include "osm_pi_config.h"

/**
 * Wrap g_key_file_get_* to provide static defaults if not configured
 */


static void pi_key_file_get_string(GKeyFile * key_file,
				const gchar * group_name,
				const gchar *key,
				const char * const def_value,
				char ** value)
{
	char * tmp_char = g_key_file_get_string(key_file, group_name, key, NULL);
	if (!tmp_char) {
		tmp_char = def_value;
	}

	if (*value != def_value)
		free(*value);
	*value = tmp_char;
}

static void pi_key_file_get_integer(GKeyFile * key_file,
				const gchar * group_name,
				const gchar *key,
				const int def_value,
				int * value)
{
	/* note g_key_file_get_integer does not support specifying hex etc
	 * do strtol here
	 */
	char * tmp = g_key_file_get_string(key_file, group_name, key, NULL);
	if (!tmp) {
		*value = def_value;
	} else {
		errno = 0;
		*value = (int)strtol(tmp, NULL, 0);
		if (errno)
			*value = def_value;
	}
}

/**
 * return 1 if config updated
 */
static int load_config(const char * conf_file, struct opensmssa_config * conf)
{
	GKeyFile * key_file = NULL;
	struct stat statbuf;

	/* silently ignore missing or old config file */
	if (stat(conf_file, &statbuf))
		return 0;
	if (conf->timestamp && conf->timestamp >= statbuf.st_mtime)
		return 0;

	key_file = g_key_file_new();

	if (g_key_file_load_from_file(key_file, conf_file,
				G_KEY_FILE_NONE, NULL) != TRUE)
		/* FIXME: ignore malformed config file as well */
		return 0;

	/* "Logging" group */
	pi_key_file_get_string(key_file, "Logging", "log_file",
				DEF_LOG_FILE, &conf->log_file);
	pi_key_file_get_integer(key_file, "Logging", "log_level",
				DEF_LOG_LEVEL, &conf->log_level);

	g_key_file_free(key_file);

	conf->timestamp = time(NULL);

	return 1;
}

static struct opensmssa_config config = {
	timestamp : 0,
	log_file : DEF_LOG_FILE,
	log_level : DEF_LOG_LEVEL,
};

struct opensmssa_config * read_config(void)
{
	load_config(DEF_CONFIG_FILE, &config);
	return (&config);
}

struct opensmssa_config * get_config(void)
{
	return (&config);
}

