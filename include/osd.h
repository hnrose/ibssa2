/*
 * Copyright (c) 2009-2013 Intel Corporation.  All rights reserved.
 * Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
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

#if !defined(OSD_H)
#define OSD_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#ifndef BINDIR
#define BINDIR "/usr/bin"
#endif
#ifndef RDMADIR
#define RDMADIR "rdma"
#endif
#define RDMA_CONF_DIR SYSCONFDIR "/" RDMADIR
#define SSA_ADDR_FILE_SUFFIX "_addr.data"
#define SSA_OPTS_FILE_SUFFIX "_opts.cfg"
#define ACM_FILE_PREFIX "ibacm"
#define ACM_ADDR_FILE   ACM_FILE_PREFIX SSA_ADDR_FILE_SUFFIX
#define ACM_OPTS_FILE   ACM_FILE_PREFIX SSA_OPTS_FILE_SUFFIX
#define SSA_FILE_PREFIX "ibssa"
#define SSA_OPTS_FILE	SSA_FILE_PREFIX SSA_OPTS_FILE_SUFFIX

#define LIB_DESTRUCTOR __attribute__((destructor))
#define CDECL_FUNC

#ifndef container_of
#define container_of(ptr, type, field) \
	((type *) ((void *) ptr - offsetof(type, field)))
#endif

static inline int seterr(int err)
{
	errno = err;
	return -1;
}

#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)

#if DEFINE_ATOMICS
typedef struct { pthread_mutex_t mut; long val; } atomic_t;
static inline long atomic_inc(atomic_t *atomic)
{
	long v;

	pthread_mutex_lock(&atomic->mut);
	v = ++(atomic->val);
	pthread_mutex_unlock(&atomic->mut);
	return v;
}
static inline long atomic_dec(atomic_t *atomic)
{
	int v;

	pthread_mutex_lock(&atomic->mut);
	v = --(atomic->val);
	pthread_mutex_unlock(&atomic->mut);
	return v;
}
static inline void atomic_init(atomic_t *atomic)
{
	pthread_mutex_init(&atomic->mut, NULL);
	atomic->val = 0;
}
#else
typedef struct { volatile long val; } atomic_t;
#define atomic_inc(v) (__sync_add_and_fetch(&(v)->val, 1))
#define atomic_dec(v) (__sync_sub_and_fetch(&(v)->val, 1))
#define atomic_init(v) ((v)->val = 0)
#endif
#define atomic_get(v) ((v)->val)
#define atomic_set(v, s) ((v)->val = s)

typedef struct { pthread_cond_t cond; pthread_mutex_t mutex; } event_t;
static inline void event_init(event_t *e)
{
	pthread_cond_init(&e->cond, NULL);
	pthread_mutex_init(&e->mutex, NULL);
}
#define event_signal(e)	pthread_cond_signal(&(e)->cond)
static inline int event_wait(event_t *e, int timeout) 
{
	struct timeval curtime;
	struct timespec wait;
	int ret;

	gettimeofday(&curtime, NULL);
	wait.tv_sec = curtime.tv_sec + ((unsigned) timeout) / 1000;
	wait.tv_nsec = (curtime.tv_usec + (((unsigned) timeout) % 1000) * 1000) * 1000;
	pthread_mutex_lock(&e->mutex);
	ret = pthread_cond_timedwait(&e->cond, &e->mutex, &wait);
	pthread_mutex_unlock(&e->mutex);
	return ret;
}

static inline uint64_t time_stamp_us(void)
{
	struct timeval curtime;
	timerclear(&curtime);
	gettimeofday(&curtime, NULL);
	return (uint64_t) curtime.tv_sec * 1000000 + (uint64_t) curtime.tv_usec;
}

#define time_stamp_ms()  (time_stamp_us() / (uint64_t) 1000)
#define time_stamp_sec() (time_stamp_ms() / (uint64_t) 1000)
#define time_stamp_min() (time_stamp_sec() / (uint64_t) 60)

#ifdef __cplusplus
}
#endif

#endif /* OSD_H */
