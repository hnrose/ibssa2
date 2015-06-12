/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <acm_neigh.h>
#include <ssa_log.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* NDA_RTA and NLMSG_TAIL should come from rtnetlink.h */
#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define EVENTS (POLLIN | POLLPRI | POLLERR | POLLHUP)

static uint32_t sequence_number;

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		     int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		ssa_log(SSA_LOG_DEFAULT,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

/* Add operation is done with replace flag so replacement can be done in 1 operation rather than delete followed by add */
int ipv4_neighbor_add(int neighsock, int ifindex, in_addr_t ipaddr,
		      char *lla, int llalen)
{
	struct {
		struct nlmsghdr		n;
		struct ndmsg		ndm;
		char			buf[256];
	} req;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
#if 1
	req.n.nlmsg_flags = NLM_F_REQUEST;
#else
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
#endif
	req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_NEWNEIGH;
	req.n.nlmsg_seq = ++sequence_number;
	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req), NDA_DST, &ipaddr, sizeof(ipaddr));
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

	return send(neighsock, &req, req.n.nlmsg_len, 0) <= 0;
}

int ipv4_neighbor_delete(int neighsock, int ifindex, in_addr_t ipaddr)
{
	struct {
		struct nlmsghdr		n;
		struct ndmsg		ndm;
		char			buf[256];
	} req;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
#if 1
	req.n.nlmsg_flags = NLM_F_REQUEST;
#else
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
#endif
	req.n.nlmsg_type = RTM_DELNEIGH;
	req.n.nlmsg_seq = ++sequence_number;
	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req), NDA_DST, &ipaddr, sizeof(ipaddr));

	return send(neighsock, &req, req.n.nlmsg_len, 0) <= 0;
}

int ipv6_neighbor_add(int neighsock, int ifindex, struct in6_addr *ipaddr,
		      char *lla, int llalen)
{
	struct {
		struct nlmsghdr		n;
		struct ndmsg		ndm;
		char			buf[256];
	} req;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
#if 1
	req.n.nlmsg_flags = NLM_F_REQUEST;
#else
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
#endif
	req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_NEWNEIGH;
	req.n.nlmsg_seq = ++sequence_number;
	req.ndm.ndm_family = AF_INET6;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req), NDA_DST, &ipaddr, sizeof(ipaddr));
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

	return send(neighsock, &req, req.n.nlmsg_len, 0) <= 0;
}

int ipv6_neighbor_delete(int neighsock, int ifindex, struct in6_addr *ipaddr)
{
	struct {
		struct nlmsghdr		n;
		struct ndmsg		ndm;
		char			buf[256];
	} req;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
#if 1
	req.n.nlmsg_flags = NLM_F_REQUEST;
#else
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
#endif
	req.n.nlmsg_type = RTM_DELNEIGH;
	req.n.nlmsg_seq = ++sequence_number;
	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req), NDA_DST, &ipaddr, sizeof(ipaddr));

	return send(neighsock, &req, req.n.nlmsg_len, 0) <= 0;
}

int open_neighsock()
{
	int neighsock;
	struct sockaddr_nl local;

	neighsock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (neighsock < 0) {
		ssa_log(SSA_LOG_DEFAULT,
			"Cannot open netlink socket for RTMGRP_NEIGH");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_NEIGH;
	if (bind(neighsock, (struct sockaddr *) &local, sizeof(local)) < 0) {
		ssa_log(SSA_LOG_DEFAULT,
			"Cannot bind netlink socket for RTMGRP_NEIGH");
		close(neighsock);
		return -1;
	}

	return neighsock;
}

void close_neighsock(int neighsock)
{
	if (neighsock != -1)
		close(neighsock);
}

static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
			      int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) *(max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		ssa_log(SSA_LOG_DEFAULT, "!!!Deficit %d, rta_len = %d\n",
			len, rta->rta_len);
	return 0;
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

static int handle_intf(uint32_t ifindex)
{
	/* Handle IB interfaces only */

	/* !!! */
#if 0

#else
	return 1;
#endif
}

static int handle_request(int neighsock, struct nlmsghdr *n)
{
	struct ndmsg *ndm = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[NDA_MAX + 1];
	uint32_t ifindex;
	struct in_addr ipaddr;
	struct in6_addr ip6addr;
	char ip6addr_str[INET6_ADDRSTRLEN];

	if (n->nlmsg_type == NLMSG_DONE)
		return 0;

	if (n->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *p_err;

		p_err = (struct nlmsgerr *) ndm;
		/* Error number 0 is an acknowledgement and not an error */
		if (p_err->error == 0)
			ssa_log(SSA_LOG_DEFAULT,
				"NLMSG_ERROR 0 (ACK) seq 0x%x\n",
				p_err->msg.nlmsg_seq);
		else
			ssa_log(SSA_LOG_DEFAULT,
				"NLMSG_ERROR %d seq 0x%x len %d type %d flags 0x%x\n",
				p_err->error, p_err->msg.nlmsg_seq,
				p_err->msg.nlmsg_len, p_err->msg.nlmsg_type,
				p_err->msg.nlmsg_flags);
		return 0;
	}

	if (n->nlmsg_type != RTM_GETNEIGH &&
	    n->nlmsg_type != RTM_NEWNEIGH &&
	    n->nlmsg_type != RTM_DELNEIGH)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ndm));
	if (len < 0)
		return -1;

	ifindex = ndm->ndm_ifindex;

	if ((ndm->ndm_family != AF_INET &&
	     ndm->ndm_family != AF_INET6) ||
	    !handle_intf(ifindex) ||
	    ndm->ndm_flags ||
	    ndm->ndm_type != RTN_UNICAST ||
	    !(ndm->ndm_state & ~NUD_NOARP))
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_DST])
		return 0;

	if (n->nlmsg_type == RTM_GETNEIGH) {
		if (ndm->ndm_family == AF_INET) {
			memcpy(&ipaddr, RTA_DATA(tb[NDA_DST]), sizeof(ipaddr));
			ssa_log(SSA_LOG_CTRL,
				"RTM_GETNEIGH ifIndex %d IP %-15s\n",
				ifindex, inet_ntoa(ipaddr));
		} else {
			memcpy(&ip6addr, RTA_DATA(tb[NDA_DST]), sizeof(ip6addr));
			ssa_log(SSA_LOG_CTRL,
				"RTM_GETNEIGH ifIndex %d IP %s\n", ifindex,
				inet_ntop(AF_INET6, &ip6addr, ip6addr_str,
					  sizeof(ip6addr_str)));
		}
	}

	return 0;
}

static void get_message(int neighsock)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	char   buf[8192];
	struct msghdr msg = {
		(void *) &nladdr, sizeof(nladdr),
		&iov,	 1,
		NULL,	 0,
		0
	};

	memset(&nladdr, 0, sizeof(nladdr));

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	status = recvmsg(neighsock, &msg, MSG_DONTWAIT);

	if (status <= 0)
		return;

	if (nladdr.nl_pid)
		return;

	for (h = (struct nlmsghdr *) buf; status >= sizeof(*h); ) {
		int len = h->nlmsg_len;
		int l = len - sizeof(*h);

		if (l < 0 || len > status)
			return;

		if (handle_request(neighsock, h) < 0)
			return;

		status -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr *)((char *) h + NLMSG_ALIGN(len));
	}
}

void poll_neighsock(int neighsock, int poll_timeout)
{
	struct pollfd pset[1];

	pset[0].fd = neighsock;
	pset[0].events = EVENTS;
	pset[0].revents = 0;

	for (;;) {
		if (poll(pset, 1, poll_timeout) > 0) {
			if (pset[0].revents & EVENTS)
				get_message(neighsock);
		}
	}
}
