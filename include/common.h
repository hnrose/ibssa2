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
#include <infiniband/umad.h>
#include <infiniband/verbs.h>
#include <ssa_ctrl.h>
#include <dlist.h>
#include <search.h>
#ifdef ACM
#include <acm_shared.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SSA_NAME_SIZE 32

#ifdef HAVE_PTHREAD_SET_NAME_NP
	#define SET_THREAD_NAME(thread, ...) { char buf[16] = {}; \
		snprintf(buf, sizeof buf, __VA_ARGS__); \
		pthread_setname_np(thread, buf); }
#else
	#define SET_THREAD_NAME(thread, ...)
#endif

void ssa_daemonize(void);
int ssa_open_lock_file(char *lock_file, char *msg, int n);

extern __thread char log_data[128];
extern __thread char log_data1[128];

struct ssa_class;
struct ssa_device;
struct ssa_port;
struct ssa_svc;

enum ssa_obj_type {
	SSA_OBJ_CLASS,
	SSA_OBJ_DEVICE,
	SSA_OBJ_PORT
};

struct ssa_obj {
	enum ssa_obj_type		type;
	union {
		struct ssa_device	*dev;
		struct ssa_port		*port;
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
	nfds_t			nsfds;
	uint8_t			node_type;
};

struct ssa_device {
	struct ssa_class	*ssa;
	struct ibv_context      *verbs;
	uint64_t                guid;
	char			name[SSA_NAME_SIZE];
	size_t			port_size;
	int                     port_cnt;
	struct ssa_port         *port;
#ifdef ACM
	struct ibv_comp_channel *channel;
	struct ibv_pd		*pd;
#endif
};

struct ssa_port {
	struct ssa_device	*dev;
	char			name[SSA_NAME_SIZE];
	int			mad_portid;
	int			mad_agentid;
	int			sa_agentid;
	pthread_mutex_t		lock;
	enum ibv_port_state	state;
	union ibv_gid		gid;
	uint16_t		sm_lid;
	uint8_t			sm_sl;
	uint8_t			port_num;
	uint16_t		svc_cnt;
	struct ssa_svc		**svc;
#ifdef ACM
	DLIST_ENTRY		ep_list;
	struct acm_dest		sa_dest;
	enum ibv_mtu		mtu;
	enum ibv_rate		rate;
	int			subnet_timeout;
	int			gid_cnt;
	uint16_t		pkey_cnt;
	uint16_t		lid;
	uint16_t		lid_mask;
#endif
};

enum ssa_conn_type {
	SSA_CONN_TYPE_UPSTREAM,
	SSA_CONN_TYPE_DOWNSTREAM,
	SSA_CONN_TYPE_LISTEN		/* downstream */
};

enum ssa_conn_dbtype {
	SSA_CONN_NODB_TYPE,
	SSA_CONN_SMDB_TYPE,
	SSA_CONN_PRDB_TYPE
};

enum ssa_conn_state {
	SSA_CONN_IDLE,
	SSA_CONN_LISTENING,
	SSA_CONN_CONNECTING,
	SSA_CONN_CONNECTED
};

enum ssa_db_phase {
	SSA_DB_IDLE,
	SSA_DB_DEFS,
	SSA_DB_TBL_DEFS,
	SSA_DB_FIELD_DEFS,
	SSA_DB_DATA
};

struct ssa_conn {
	int			rsock;
	enum ssa_conn_type	type;
	enum ssa_conn_dbtype	dbtype;
	enum ssa_conn_state	state;
	enum ssa_db_phase	phase;
	union ibv_gid		remote_gid;
	void			*rbuf;
	int			rsize;
	int			roffset;
	uint32_t		rid;
	int			rindex;
	void			*rhdr;
	void			*sbuf;
	int			ssize;
	int			soffset;
	uint32_t		sid;
	int			sindex;
	void			*sbuf2;
	int			ssize2;
	int			rdma_write;
	struct ssa_db		*ssa_db;
	uint64_t		epoch;
	volatile be64_t		prdb_epoch;
	uint32_t		epoch_len;
	uint16_t		remote_lid;
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
	char			name[SSA_NAME_SIZE];
	uint64_t		database_id;
	int			(*process_msg)(struct ssa_svc *svc,
					       struct ssa_ctrl_msg_buf *msg);
	int			sock_upctrl[2];
	int			sock_downctrl[2];
	int			sock_upmain[2];
	int			sock_accessup[2];
	int			sock_accessdown[2];
	int			sock_updown[2];
	int			sock_extractdown[2];
	struct ssa_conn		conn_listen_smdb;
	struct ssa_conn		conn_listen_prdb;
	struct ssa_conn		conn_dataup;
	struct ssa_conn		*fd_to_conn[FD_SETSIZE];
	uint16_t		index;
	uint16_t		tid;
	pthread_t		upstream;
	pthread_t		downstream;
	//pthread_mutex_t		lock;
	int			timeout;
	enum ssa_svc_state	state;
	struct ibv_path_data	primary;	/* parent */
	struct ibv_path_data	secondary;	/* parent */
#ifdef ACCESS
	void			*access_map;
#endif
};

int ssa_open_devices(struct ssa_class *ssa);
void ssa_close_devices(struct ssa_class *ssa);

void ssa_upstream_mad(struct ssa_svc *svc, struct ssa_ctrl_msg_buf *msg);
struct ssa_svc *ssa_start_svc(struct ssa_port *port, uint64_t database_id,
			      size_t svc_size,
			      int (*process_msg)(struct ssa_svc *svc,
					         struct ssa_ctrl_msg_buf *msg));
int ssa_start_access(struct ssa_class *ssa);
void ssa_stop_access(struct ssa_class *ssa);
int ssa_ctrl_run(struct ssa_class *ssa);
void ssa_ctrl_conn(struct ssa_class *ssa, struct ssa_svc *svc);
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


int ssa_init(struct ssa_class *ssa, uint8_t node_type,
	     size_t dev_size, size_t port_size);
void ssa_cleanup(struct ssa_class *ssa);

void ssa_init_mad_hdr(struct ssa_svc *svc, struct umad_hdr *hdr,
		      uint8_t method, uint16_t attr_id);
int ssa_svc_query_path(struct ssa_svc *svc, union ibv_gid *dgid,
		       union ibv_gid *sgid);
#ifdef ACM
int ssa_upstream_query_db(struct ssa_svc *svc);
int ssa_get_svc_cnt(struct ssa_port *port);
struct ssa_svc *ssa_get_svc(struct ssa_port *port, int index);
#endif

int ssa_set_ssa_signal_handler();

#ifdef __cplusplus
}
#endif

#endif /* _SSA_COMMON_H */
