/*
 * Copyright (c) 2009-2013 Intel Corporation. All rights reserved.
 * Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
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

#ifndef _SSA_LOG_H
#define _SSA_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ssa_addr_type {
	SSA_ADDR_NAME,
	SSA_ADDR_IP,
	SSA_ADDR_IP6,
	SSA_ADDR_PATH,
	SSA_ADDR_GID,
	SSA_ADDR_LID
};

enum {
	SSA_LOG_DEFAULT		= 1 << 0,
	SSA_LOG_VERBOSE		= 1 << 1,
	SSA_LOG_CTRL		= 1 << 2,
	SSA_LOG_DB		= 1 << 3,
	SSA_LOG_COMM		= 1 << 4,
	SSA_LOG_ALL		= 0xFFFFFFFF,
};

void ssa_set_log_level(int level);
int  ssa_open_log(char *log_file);
void ssa_close_log(void);
void ssa_write_log(int level, const char *format, ...);
#define ssa_log(level, format, ...) \
	ssa_write_log(level, "%s: "format, __func__, ## __VA_ARGS__)
#define ssa_log_func(level) ssa_log(level, "\n");
#define ssa_log_err(level, format, ...) \
	ssa_write_log(level | SSA_LOG_DEFAULT, "%s: ERROR - "format, __func__, ## __VA_ARGS__)
#define ssa_log_warn(level, format, ...) \
	ssa_write_log(level | SSA_LOG_DEFAULT, "%s: WARNING - "format, __func__, ## __VA_ARGS__)
void ssa_sprint_addr(int level, char *str, size_t str_size,
		     enum ssa_addr_type addr_type, uint8_t *addr, size_t addr_size);
void ssa_log_options(void);

#ifdef __cplusplus
}
#endif

#endif /* _SSA_LOG_H */
