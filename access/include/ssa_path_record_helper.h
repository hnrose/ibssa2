/*
 * Copyright 2004-2015 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the terms of the
 * OpenIB.org BSD license included below:
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

#ifndef __SSA_PATH_RECORD_HELPER_H__
#define __SSA_PATH_RECORD_HELPER_H__

/*
 * The file contains SSA Access Layer helper functions
 */

#include <stdio.h>
#include <ssa_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined (_DEBUG_)
#define SSA_ASSERT	assert
#else				/* _DEBUG_ */
#define SSA_ASSERT( __exp__ )
#endif				/* _DEBUG_ */

#define ERROR_TAG "ERR"
#define INFO_TAG "INFO"
#define DEBUG_TAG "DEBUG"

extern const char *get_time();

extern int rates_cmp_table[19][19];
/*
 * According to profiling results, ib_path_compare_rates takes about
 * 7% of the overall path record computation time.
 * ib_path_compare_rates_fast is a fast version of ib_path_compare_rates that uses a static lookup
 * table with precomputed results. It is used as a performance optimization in
 * the path records algorithm.
 */
static inline int ib_path_compare_rates_fast(const int rate1, const int rate2)
{
	return rates_cmp_table[rate1][rate2];
}

#define SSA_PR_LOG_ERROR(message, args...) { ssa_log_err(SSA_LOG_CTRL, message "\n", ##args); }
#define SSA_PR_LOG_INFO(message, args...) { ssa_log(SSA_LOG_CTRL|SSA_LOG_PR, message "\n", ##args); }
#define SSA_PR_LOG_DEBUG(message, args...) { ssa_log(SSA_LOG_PR, message "\n", ##args); }
#ifdef __cplusplus
}
#endif

#endif /* __SSA_PATH_RECORD_HELPER_H__ */
