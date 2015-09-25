/*
 * Copyright (c) 2014 Intel Corporation.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#include <infiniband/acm.h>
#include <osd.h>
#include <ssa_log.h>
#include "acm_shared.h"
#include "acm_util.h"

#define MAX_IPOIB_IFS 16
struct ipoib_intf {
	uint32_t ifindex;
	char ifname[IFNAMSIZ];
};

int acm_if_get_pkey(char *ifname, uint16_t *pkey)
{
	char buf[128], *end;
	FILE *f;
	int ret;

	snprintf(buf, sizeof buf, "//sys//class//net//%s//pkey", ifname);
	f = fopen(buf, "r");
	if (!f) {
		ssa_log_err(0, "failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		*pkey = strtol(buf, &end, 16);
		ret = 0;
	} else {
		ssa_log_err(0, "failed to read pkey for interface %s\n", ifname);
		ret = -1;
	}

	fclose(f);
	return ret;
}

int acm_if_get_sgid(char *ifname, union ibv_gid *sgid)
{
	char buf[128], *end;
	FILE *f;
	int i, p, ret;

	snprintf(buf, sizeof buf, "//sys//class//net//%s//address", ifname);
	f = fopen(buf, "r");
	if (!f) {
		ssa_log_err(0, "failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		for (i = 0, p = 12; i < 16; i++, p += 3) {
			buf[p + 2] = '\0';
			sgid->raw[i] = (uint8_t) strtol(buf + p, &end, 16);
		}
		ret = 0;
	} else {
		ssa_log_err(0, "failed to read sgid for interface %s\n", ifname);
		ret = -1;
	}

	fclose(f);
	return ret;
}

static int find_first_avail_ipoib_index(struct ipoib_intf ipoib_intfs[])
{
	int i;

	for (i = 0; i < MAX_IPOIB_IFS; i++) {
		if (ipoib_intfs[i].ifindex == -1)
			return i;
	}
	return -1;
}

static int ipoib_intf_index(struct ipoib_intf ipoib_intfs[], uint32_t ifindex)
{
	int i;

	for (i = 0; i < MAX_IPOIB_IFS; i++) {
		if (ipoib_intfs[i].ifindex == -1)
			return -1;
		if (ipoib_intfs[i].ifindex == ifindex)
			return i;
	}
	return -1;
}

void acm_get_ipoib_links(struct nlmsghdr *hdr, struct ipoib_intf ipoib_intfs[])
{
	struct ifinfomsg *intf;
	struct rtattr *attr;
	int attr_len, i;

	intf = NLMSG_DATA(hdr);
	attr_len = IFLA_PAYLOAD(hdr);
	for (attr = IFLA_RTA(intf); RTA_OK(attr, attr_len);
	     attr = RTA_NEXT(attr, attr_len)) {
		if (attr->rta_type == IFLA_IFNAME &&
		    intf->ifi_type == ARPHRD_INFINIBAND) {
			i = find_first_avail_ipoib_index(ipoib_intfs);
			if (i != -1) {
				ipoib_intfs[i].ifindex = intf->ifi_index;
				strncpy(ipoib_intfs[i].ifname, RTA_DATA(attr),
					sizeof(ipoib_intfs[i].ifname));
			} else
				ssa_log_err(0, "ipoib_intfs table is full\n");
		}
	}
}

void acm_get_ipaddrs(struct nlmsghdr *hdr, struct ipoib_intf ipoib_intfs[],
		     acm_if_iter_cb cb, void *ctx)
{
	struct ifaddrmsg *addr;
	struct rtattr *attr;
	char *alias_sep;
	int attr_len, index, ret;
	size_t addr_len;
	uint16_t pkey;
	union ibv_gid sgid;
	char ipaddr[INET6_ADDRSTRLEN];
	uint8_t ip_addr[ACM_MAX_ADDRESS];
	uint8_t addr_type;

	addr = NLMSG_DATA(hdr);
	attr_len = IFA_PAYLOAD(hdr);
	for (attr = IFA_RTA(addr); RTA_OK(attr, attr_len);
	     attr = RTA_NEXT(attr, attr_len)) {
		if (attr->rta_type == IFA_ADDRESS) {
			index = ipoib_intf_index(ipoib_intfs, addr->ifa_index);
			if (index != -1) {
				if (addr->ifa_family == AF_INET6) {
					addr_type = ACM_ADDRESS_IP6;
					addr_len = 16;
					memcpy(&ip_addr,
					       ((struct sockaddr_in6 *) RTA_DATA(attr)),
					       addr_len);
					inet_ntop(AF_INET6, RTA_DATA(attr),
						  ipaddr, sizeof(ipaddr));
					addr_len = 16;
				} else {
					addr_type = ACM_ADDRESS_IP;
					addr_len = 4;
					memcpy(&ip_addr,
					       ((struct sockaddr_in *) RTA_DATA(attr)),
					       addr_len);
					inet_ntop(AF_INET, RTA_DATA(attr),
						  ipaddr, sizeof(ipaddr));
				}
				ssa_log(SSA_LOG_CTRL, "interface %s index %u\n",
					ipoib_intfs[index].ifname, addr->ifa_index);

				alias_sep = strchr(ipoib_intfs[index].ifname, ':');
				if (alias_sep)
					*alias_sep = '\0';

				ret = acm_if_get_sgid(ipoib_intfs[index].ifname, &sgid);
				if (ret)
					continue;

				ret = acm_if_get_pkey(ipoib_intfs[index].ifname, &pkey);
				if (ret)
					continue;

				cb(ipoib_intfs[index].ifname, addr->ifa_index,
				   &sgid, pkey, addr_type, ip_addr, addr_len,
				   ipaddr, ctx);
			}
		}
	}
}

int acm_if_iter_sys(acm_if_iter_cb cb, void *ctx)
{
	static uint32_t sequence = 0;
	int s, ret = -1, i, len, end = 0;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg gen;
	} request;
	struct {
		struct nlmsghdr hdr;
		struct ifaddrmsg addr;
	} addr_request;
	struct {
		struct nlmsghdr hdr;
		char buf[4096];
	} *response;
	struct ipoib_intf ipoib_intfs[MAX_IPOIB_IFS];

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (!s)
		return -1;

	response = malloc(sizeof(*response));
	if (!response)
		goto out;

	for (i = 0; i < MAX_IPOIB_IFS; i++) {
		ipoib_intfs[i].ifindex = -1;
		memset(ipoib_intfs[i].ifname, 0, sizeof(ipoib_intfs[i].ifname)) ;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	if (ret < 0) {
		ssa_log_err(0, "failed to bind netlink socket: %s\n", strerror(errno));
		goto out;
	}

	/* First, get all IPoIB interfaces (links) */
	memset(&msg, 0, sizeof(msg));
	memset(&request, 0, sizeof(request));

	request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.gen));
	request.hdr.nlmsg_type = RTM_GETLINK;
	request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.hdr.nlmsg_seq = ++sequence;
	request.hdr.nlmsg_pid = getpid();
	request.gen.rtgen_family = AF_PACKET;

	iov.iov_base = &request;
	iov.iov_len = request.hdr.nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);

	ret = sendmsg(s, (struct msghdr *) &msg, 0);
	if (ret < 0) {
		ssa_log_err(0, "sendmsg RTM_GETLINK failed: %s\n", strerror(errno));
		goto out;
	}

	while (!end) {
		iov.iov_base = response;
		iov.iov_len = sizeof(*response);

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);

		len = recvmsg(s, &msg, 0);
		if (len < 0) {
			ssa_log_err(0, "recvmsg RTM_GETLINK failed: %s\n",
				    strerror(errno));
			ret = len;
			goto out;
		}

		for (nh = &response->hdr; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			/* End of multipart message */
			if (nh->nlmsg_type == NLMSG_DONE) {
				end = 1;
				break;
			}

			if (nh->nlmsg_type == NLMSG_ERROR) {
				err = NLMSG_DATA(nh);
				ssa_log_err(0, "NLMSG_ERROR %d while handling RTM_GETLINK response\n",
					    err->error);
				end = 1;
				break;
			}

			if (nh->nlmsg_type == RTM_NEWLINK) {
				acm_get_ipoib_links(nh, ipoib_intfs);
			} else {
				ssa_log_err(0, "unexpected message type %d length %d\n",
					    nh->nlmsg_type, nh->nlmsg_len);
			}
		}
	}

	/* Now, get IPv4 and IPv6 addresses for the IPoIB interfaces (links) */
	for (i = 0; i < 2; i++) {

		memset(&msg, 0, sizeof(msg));
		memset(&addr_request, 0, sizeof(addr_request));

		addr_request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(addr_request.addr));
		addr_request.hdr.nlmsg_type = RTM_GETADDR;
		addr_request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
		addr_request.hdr.nlmsg_seq = ++sequence;
		addr_request.hdr.nlmsg_pid = getpid();
		addr_request.addr.ifa_family = (i == 0) ? AF_INET : AF_INET6;
		iov.iov_base = &addr_request;
		iov.iov_len = addr_request.hdr.nlmsg_len;

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);

		ret = sendmsg(s, (struct msghdr *) &msg, 0);
		if (ret < 0) {
			ssa_log_err(0, "sendmsg RTM_GETADDR failed: %s\n", strerror(errno));
			goto out;
		}

		end = 0;
		while (!end) {
			iov.iov_base = response;
			iov.iov_len = sizeof(*response);

			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_name = &sa;
			msg.msg_namelen = sizeof(sa);

			len = recvmsg(s, &msg, 0);

			for (nh = &response->hdr; NLMSG_OK(nh, len);
			     nh = NLMSG_NEXT(nh, len)) {
				/* End of multipart message */
				if (nh->nlmsg_type == NLMSG_DONE) {
					end = 1;
					break;
				}

				if (nh->nlmsg_type == NLMSG_ERROR) {
					err = NLMSG_DATA(nh);
					ssa_log_err(0, "NLMSG_ERROR %d while handling RTM_GETADDR response\n",
						    err->error);
					end = 1;
					break;
				}

				if (nh->nlmsg_type == RTM_NEWADDR) {
					acm_get_ipaddrs(nh, ipoib_intfs, cb, ctx);
				} else {
					ssa_log_err(0, "unexpected message type %d length %d\n",
						    nh->nlmsg_type, nh->nlmsg_len);
				}
			}
		}
	}

	ret = 0;

out:
	close(s);
	return ret;
}
