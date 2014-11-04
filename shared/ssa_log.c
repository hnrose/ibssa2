/*
 * Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013 Lawrence Livermore National Securities.  All rights reserved.
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

#include <infiniband/sa.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <ssa_log.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

void get_thread_id(char *buff, int size)
{
	int ret = 1;
	pthread_t self;

	self = pthread_self();
#ifdef HAVE_PTHREAD_SET_NAME_NP
	ret = pthread_getname_np(self, buff, size);
	if (!ret && !strncmp(buff, program_invocation_short_name, size))
		ret = 1;
#endif
	if (ret || !buff[0])
		ret = snprintf(buff, size, "%04X", (unsigned) self);
}


/* TODO: make static after access layer integration */
FILE *flog;
int accum_log_file = 0;
int log_flush = 1;
static int log_level = SSA_LOG_DEFAULT;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static const char * month_str[] = {
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

void ssa_set_log_level(int level)
{
	log_level = level;
}

int ssa_get_log_level()
{
	return log_level;
}

int ssa_open_log(char *log_file)
{
	if (!strcasecmp(log_file, "stdout")) {
		flog = stdout;
		return 0;
	}

	if (!strcasecmp(log_file, "stderr")) {
		flog = stderr;
		return 0;
	}

	if (accum_log_file)
		flog = fopen(log_file, "a");
	else
		flog = fopen(log_file, "w");

	if (flog)
		return 0;

	syslog(LOG_WARNING, "Failed to open log file %s ERROR %d (%s)\n",
	       log_file, errno, strerror(errno));
	flog = stderr;
	return -1;
}

void ssa_close_log()
{
	if (flog != stdout && flog != stderr)
		fclose(flog);
	flog = NULL;
}

void ssa_write_log(int level, const char *format, ...)
{
	va_list args;
	char tid[16] = {};
	struct timeval tv;
	time_t tim;
	struct tm result;

	if (!flog)
		return;

	if (!(level & log_level))
		return;

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec;
	localtime_r(&tim, &result);
	get_thread_id(tid, sizeof tid);
	va_start(args, format);
	pthread_mutex_lock(&log_lock);
	fprintf(flog, "%s %02d %02d:%02d:%02d %06d [%.16s]: ",
		(result.tm_mon < 12 ? month_str[result.tm_mon] : "???"),
		result.tm_mday, result.tm_hour, result.tm_min,
		result.tm_sec, (unsigned int)tv.tv_usec, tid);
	vfprintf(flog, format, args);
	if (log_flush)
		fflush(flog);
	pthread_mutex_unlock(&log_lock);
	va_end(args);
}

void ssa_sprint_addr(int level, char *str, size_t str_size,
		     enum ssa_addr_type addr_type, uint8_t *addr, size_t addr_size)
{
	struct ibv_path_record *path;

	if (!(level & log_level))
		return;

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
			ssa_sprint_addr(level, str, str_size, SSA_ADDR_GID,
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

void ssa_log_options()
{
	char hostname[HOST_NAME_MAX];

	gethostname(hostname, HOST_NAME_MAX);
	ssa_log(SSA_LOG_DEFAULT, "SSA version %s\n", IB_SSA_VERSION);
	ssa_log(SSA_LOG_DEFAULT, "host name %s\n", hostname);
	ssa_log(SSA_LOG_DEFAULT, "log level 0x%x\n", log_level);
	ssa_log(SSA_LOG_DEFAULT, "accumulate log file: %s (%d)\n", accum_log_file ? "true" : "false", accum_log_file);
}
