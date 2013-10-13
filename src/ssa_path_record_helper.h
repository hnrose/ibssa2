
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
#ifndef __SSA_PATH_RECORD_HELPER_H__
#define __SSA_PATH_RECORD_HELPER_H__

/*
 * The file contains SSA Access Layer helper functions
 */

#include<stdio.h>

#if defined (_DEBUG_)
#define SSA_ASSERT	assert
#else				/* _DEBUG_ */
#define SSA_ASSERT( __exp__ )
#endif				/* _DEBUG_ */


#define ERROR_TAG "ERR"
#define INFO_TAG "INFO"
#define DEBUG_TAG "DEBUG"


enum {
	SSA_PR_NO_LOG = 0,
	SSA_PR_EEROR_LEVEL = 1,
	SSA_PR_INFO_LEVEL = 2,
	SSA_PR_DEBUG_LEVEL = 3
};

extern int ssa_pr_log_level;
extern FILE *ssa_pr_log_fd;
extern const char* get_time();

extern  int rates_cmp_table[19][19];

#define _FILE strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#define SSA_PR_LOG_FORMAT "%s | %-7s | %-15s:%d | %s |"
#define SSA_PR_LOG_PREFIX_ARGS(tag) get_time(), tag ,_FILE,__LINE__,__func__ 
#define SSA_PR_LOG_PRINT_FUNCTION(format,...) fprintf(ssa_pr_log_fd,format,__VA_ARGS__)


#define SSA_PR_LOG_ERROR(message,args...) {if(ssa_pr_log_level>=SSA_PR_EEROR_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(ERROR_TAG), ##args);}
#define SSA_PR_LOG_INFO(message,args...) {if(ssa_pr_log_level>=SSA_PR_INFO_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(INFO_TAG), ##args);}
#define SSA_PR_LOG_DEBUG(message,args...) {if(ssa_pr_log_level>=SSA_PR_DEBUG_LEVEL) SSA_PR_LOG_PRINT_FUNCTION(SSA_PR_LOG_FORMAT message "\n",SSA_PR_LOG_PREFIX_ARGS(DEBUG_TAG), ##args);}

#endif /* __SSA_PATH_RECORD_HELPER_H__ */
