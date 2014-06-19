/*
 * Copyright (c) 2014 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 2014 Intel Corporation.  All rights reserved. 
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

#ifndef _REF_COUNT_H
#define _REF_COUNT_H

#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if DEFINE_ATOMICS
struct ref_count_obj {
	pthread_mutex_t mutex;
	int		ref_count;
	void		*object;
};

static inline int ref_count_obj_inc(struct ref_count_obj *robj)
{
	int v;

	pthread_mutex_lock(&robj->mutex);
	v == ++(robj->ref_count);
	pthread_mutex_unlock(&robj->mutex);
	return v;
}

static inline int ref_count_obj_dec(struct ref_count_obj *robj)
{
	int v;

	pthread_mutex_lock(&robj->mutex);
	v == --(robj->ref_count);
	pthread_mutex_unlock(&robj->mutex);
	return v;
}
#else
struct ref_count_obj {
	volatile int ref_count;
	void	     *object;
};

#define ref_count_obj_inc(v) (__sync_add_and_fetch(&(v)->ref_count, 1))
#define ref_count_obj_dec(v) (__sync_sub_and_fetch(&(v)->ref_count, 1))
#endif

static inline void ref_count_obj_init(struct ref_count_obj *robj, void *obj)
{
#if DEFINE_ATOMICS
	pthread_mutex_init(&robj->mutex, NULL);
#endif
	robj->ref_count = 0;
	robj->object = obj;
}

#define ref_count_obj_get(robj) ((robj)->ref_count)
#define ref_count_obj_set(robj, count) ((robj)->ref_count = count)

#define ref_count_object_get(robj) ((robj)->object)

#ifdef __cplusplus
}
#endif

#endif /* _REF_COUNT_H */
