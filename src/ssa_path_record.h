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


extern FILE *flog1;
int  ssa_open_log1(char *log_file);
void ssa_close_log1(void);
void ssa_write_log1(int level, const char *format, ...);
#define ssa_log(level, format, ...) \
	ssa_write_log1(level, "%s: "format, __func__, ## __VA_ARGS__)


#ifdef __cplusplus
}
#endif

#endif /* __SSA_PATH_RECORD_H__ */
