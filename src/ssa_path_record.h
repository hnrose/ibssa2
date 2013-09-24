/*
 * Copyright 2004-2013 Mellanox Technologies LTD. All rights reserved.
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
#ifndef __SSA_PATH_RECORD_H__
#define __SSA_PATH_RECORD_H__

/*
 * The file contains SSA Access Layer API. 
 */

#include <stdint.h>
#include <byteswap.h>
#include <infiniband/umad.h>

#define SSA_ACCESS_LAYER_OUTPUT_FILE "ssa_access_layer.log"

#if defined (_DEBUG_)
#define SSA_ASSERT	assert
#else				/* _DEBUG_ */
#define SSA_ASSERT( __exp__ )
#endif				/* _DEBUG_ */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _ssa_pr_status_t {
    SSA_PR_SUCCESS,
    SSA_PR_ERROR,
	SSA_PR_NO_PATH
} ssa_pr_status_t;

typedef struct ssa_path_parms {
	be64_t from_guid;
	be64_t to_guid;
	be16_t from_lid;
	be16_t to_lid;
	be16_t pkey;
	uint8_t mtu;
	uint8_t rate;
	uint8_t sl;
	uint8_t pkt_life;
	uint8_t reversible;
	uint8_t hops;
} ssa_path_parms_t;


typedef void (*ssa_pr_path_dump_t)(const ssa_path_parms_t*,void*);

ssa_pr_status_t ssa_pr_half_world(struct ssa_db_smdb* p_ssa_db_smdb, 
		be64_t port_guid,
		ssa_pr_path_dump_t dump_clbk,
		void* clbk_prm);

/* TODO: remove after migration with SSA framework */
enum {
	SSA_LOG_DEFAULT     = 1 << 0,
	SSA_LOG_VERBOSE     = 1 << 1,
	SSA_LOG_CTRL        = 1 << 2,
	SSA_LOG_DB      = 1 << 3,
	SSA_LOG_COMM        = 1 << 4,
	SSA_LOG_ALL     = 0xFFFFFFFF,
};

enum {
	SSA_PR_NO_LOG = 0,
	SSA_PR_EEROR_LEVEL = 1,
	SSA_PR_INFO_LEVEL = 2,
	SSA_PR_DEBUG_LEVEL = 3
};

#define ERROR_TAG "ERR"
#define INFO_TAG "INFO"
#define DEBUG_TAG "DEBUG"


extern int ssa_pr_log_level;
extern const char* get_time();

#define _FILE strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#define SSA_PR_LOG_FORMAT "%s | %-7s | %-15s | %s:%d |"
#define SSA_PR_LOG_PREFIX_ARGS(tag) get_time(), tag ,_FILE,__func__,__LINE__ 
#define SSA_PR_LOG_PRINT_FUNCTION(format,...) fprintf(stderr,format,__VA_ARGS__)


#define SSA_PR_LOG_ERROR(message,args...) {if(ssa_pr_log_level>=SSA_PR_EEROR_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(ERROR_TAG), ##args);}
#define SSA_PR_LOG_INFO(message,args...) {if(ssa_pr_log_level>=SSA_PR_INFO_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(INFO_TAG), ##args);}
#define SSA_PR_LOG_DEBUG(message,args...) {if(ssa_pr_log_level>=SSA_PR_DEBUG_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(DEBUG_TAG), ##args);}

#ifdef __cplusplus
}
#endif

#endif /* __SSA_PATH_RECORD_H__ */
