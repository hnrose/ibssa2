/*
 * Copyright (c) 2009-2013 Intel Corporation. All rights reserved.
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

#ifndef _SSA_COMMON_H
#define _SSA_COMMON_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <osd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <infiniband/acm.h>
#include <infiniband/umad.h>
#include <infiniband/verbs.h>
#include <ssa_ctrl.h>
#include <dlist.h>
#include <search.h>

#ifdef __cplusplus
extern "C" {
#endif

void ssa_daemonize(void);
int ssa_open_lock_file(char *lock_file);

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

extern __thread char log_data[128];

void ssa_set_log_level(int level);
int  ssa_open_log(char *log_file);
void ssa_close_log(void);
void ssa_write_log(int level, const char *format, ...);
#define ssa_log(level, format, ...) \
	ssa_write_log(level, "%s: "format, __func__, ## __VA_ARGS__)
void ssa_sprint_addr(int level, char *str, size_t str_size,
		     enum ssa_addr_type addr_type, uint8_t *addr, size_t addr_size);
void ssa_log_options(void);


struct ssa_class;
struct ssa_device;
struct ssa_port;
struct ssa_svc;

enum ssa_obj_type {
	SSA_OBJ_CLASS,
	SSA_OBJ_DEVICE,
	SSA_OBJ_PORT,
	SSA_OBJ_SVC
};

struct ssa_obj {
	enum ssa_obj_type		type;
	union {
		struct ssa_device	*dev;
		struct ssa_port		*port;
		struct ssa_svc		*svc;
	};
};

struct ssa_class {
	struct ssa_device	*dev;
	int			dev_cnt;
	size_t			dev_size;
	size_t			port_size;
	int			sock[2];
	struct ssa_obj		*fds_obj;
	struct pollfd		*fds;
	nfds_t			nfds;
	uint8_t			node_type;
};

struct ssa_device {
	struct ssa_class	*ssa;
	struct ibv_context      *verbs;
	uint64_t                guid;
	size_t			port_size;
	int                     port_cnt;
	struct ssa_port         *port;
};

struct ssa_port {
	struct ssa_device	*dev;
	int			mad_portid;
	int			mad_agentid;
	//pthread_mutex_t		lock;
	union ibv_gid		gid;		// set
	uint16_t		sm_lid;		// set
	uint8_t			sm_sl;		// set
	uint8_t			port_num;
	uint16_t		svc_cnt;
	struct ssa_svc		**svc;
};

enum ssa_svc_state {
	SSA_STATE_IDLE,
	SSA_STATE_JOINING,
	SSA_STATE_FATAL_ERROR,
	SSA_STATE_ORPHAN,
	SSA_STATE_HAVE_PARENT,
	SSA_STATE_CONNECTING,
	SSA_STATE_CONNECTED,
	SSA_STATE_NO_BACKUP,
	SSA_STATE_HAVE_BACKUP
};

struct ssa_svc {
	struct ssa_port		*port;
	uint64_t		database_id;
	int			(*process_msg)(struct ssa_svc *svc,
					       struct ssa_ctrl_msg_buf *msg);
	int			sock[2];
	int			rsock;
	uint16_t		index;
	uint16_t		tid;
	pthread_t		upstream;
	//pthread_mutex_t		lock;
	int			timeout;
	enum ssa_svc_state	state;
};

int ssa_open_devices(struct ssa_class *ssa);
void ssa_close_devices(struct ssa_class *ssa);

struct ssa_svc *ssa_start_svc(struct ssa_port *port, uint64_t database_id,
			      size_t svc_size,
			      int (*process_msg)(struct ssa_svc *svc,
					         struct ssa_ctrl_msg_buf *msg));
int ssa_ctrl_run(struct ssa_class *ssa);
void ssa_ctrl_stop(struct ssa_class *ssa);

int ssa_compare_gid(const void *gid1, const void *gid2);


static inline struct ssa_device *ssa_dev(struct ssa_class *ssa, int index)
{
	return (struct ssa_device *) ((void *) ssa->dev + ssa->dev_size * index);
}

static inline struct ssa_port *ssa_dev_port(struct ssa_device *dev, int port_num)
{
	return (struct ssa_port *)
		((void *) dev->port + dev->port_size * (port_num - 1));
}


static inline char *ssa_dev_name(struct ssa_device *dev)
{
	return dev->verbs->device->name;
}

int ssa_init(struct ssa_class *ssa, uint8_t node_type,
	     size_t dev_size, size_t port_size);
void ssa_cleanup(struct ssa_class *ssa);

#ifdef __cplusplus
}
#endif

#endif /* _SSA_COMMON_H */
