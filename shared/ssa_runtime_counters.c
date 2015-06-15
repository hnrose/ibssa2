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
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <common.h>
#include <ssa_admin.h>

struct ssa_runtime_statistics {
	atomic_t counters[SSA_RUNTIME_COUNTERS_NUM];
	struct timeval start_time;
};

static struct ssa_runtime_statistics ssa_runtime_stat;

inline static long ssa_runtime_shift(const struct timeval tm)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return  (now.tv_sec - tm.tv_sec) * 1000 + (now.tv_usec - tm.tv_usec) / 1000;
}

void ssa_init_runtime_statistics()
{
	int i;

	for (i = 0; i < SSA_RUNTIME_COUNTERS_NUM; ++i)
	       atomic_init(&ssa_runtime_stat.counters[i]);
	for (i = 0; i < ARRAY_SIZE(ssa_admin_time_counter_ids); ++i)
		ssa_set_runtime_counter(ssa_admin_time_counter_ids[i], -1);

	gettimeofday(&ssa_runtime_stat.start_time, NULL);
	ssa_set_runtime_counter_time(COUNTER_ID_NODE_START_TIME);
}

void ssa_set_runtime_counter(int id, long val)
{
	atomic_set(&ssa_runtime_stat.counters[id], val);
}

long  ssa_get_runtime_counter(int id)
{
	return atomic_get(&ssa_runtime_stat.counters[id]);
}

long  ssa_inc_runtime_counter(int id)
{
	return atomic_inc(&ssa_runtime_stat.counters[id]);
}

void ssa_set_runtime_counter_time(int id)
{
	ssa_set_runtime_counter(id, ssa_runtime_shift(ssa_runtime_stat.start_time));
}

int ssa_get_runtime_counter_time(int id, struct timeval *time_stamp)
{
	long milliseconds;

	milliseconds = ssa_get_runtime_counter(id);
	if (milliseconds < 0)
		return -1;

	time_stamp->tv_sec = ssa_runtime_stat.start_time.tv_sec + milliseconds / 1000;;
	time_stamp->tv_usec = ssa_runtime_stat.start_time.tv_usec + (milliseconds % 1000) * 1000;
	return 0;

}
