/*
 * Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <common.h>
#include <ssa_log.h>

#ifdef ACM
	#define ADDRESS_IP   ACM_ADDRESS_IP
	#define ADDRESS_IP6  ACM_ADDRESS_IP6
	#define ADDRESS_NAME ACM_ADDRESS_NAME
#else
	#define ADDRESS_IP   SSA_ADDR_IP
	#define ADDRESS_IP6  SSA_ADDR_IP6
	#define ADDRESS_NAME SSA_ADDR_NAME
#endif

static uint16_t get_pkey(const char *buf)
{
	char pkey_str[8];
	char *endptr;
	long int tmp;
	uint16_t pkey = DEFAULT_PKEY;

	if (sscanf(buf, "[%*[ \tp]key%*[ \t=]%7s]", pkey_str) == 1) {
		tmp = strtol(pkey_str, &endptr, 16);
		if ((endptr == pkey_str) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp <= 0) ||
		    (tmp == 0x8000) || (tmp > DEFAULT_PKEY))
			ssa_log_warn(SSA_LOG_DEFAULT,
				     "invalid pkey was specified (0x%x),"
				     " assuming default (0x%x)\n",
				     tmp, pkey);
		else
			pkey = (uint16_t) tmp;
	} else {
		ssa_log_warn(SSA_LOG_DEFAULT, "invalid pkey format, assuming "
			     "default (0x%x)\n", pkey);
	}

	return pkey;
}

static int get_addr_record(const char *buf, const char *err_buf,
			   uint16_t pkey, struct host_addr *host_addr)
{
	char gid[INET6_ADDRSTRLEN + 1];
	char addr[INET6_ADDRSTRLEN + 1];
	char buf1[8], buf2[16];
	char *endptr;
	long int tmp;
	int ret;

	ret = sscanf(buf, "%46s%46s%15s%7s", addr, gid, buf2, buf1);
	if (ret < 2 || ret > 4)
		goto err;

	if (inet_pton(AF_INET6, gid, &host_addr->gid) <= 0) {
		ssa_log_err(SSA_LOG_DEFAULT, "%s is not IB GID\n", gid);
		goto err;
	}

	switch (ret) {
	case 2:
		host_addr->qpn = 1;
		host_addr->flags = 0;
		break;
	case 3:
		tmp = strtol(buf2, &endptr, 0);
		if ((endptr == buf2) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp < 0) ||
		    (tmp > 0xFFFFFF)) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid QPN was specified (0x%x) "
				    "GID %s %s", tmp, gid, err_buf);
			goto err;
		}

		host_addr->qpn = (uint32_t) tmp;
		host_addr->flags = DEFAULT_REMOTE_FLAGS;
		break;
	case 4:
		tmp = strtol(buf2, &endptr, 0);
		if ((endptr == buf2) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp < 0) ||
		    (tmp > 0xFFFFFF)) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid QPN was specified (0x%x) "
				    "GID %s %s\n", tmp, gid, err_buf);
			goto err;;
		}

		host_addr->qpn = (uint32_t) tmp;

		tmp = strtol(buf1, &endptr, 0);
		if ((endptr == buf1) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp & ~(REMOTE_FLAGS_MASK))) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid flags were specified (0x"
				    "%x) gid %s %s\n", tmp, gid, err_buf);
			goto err;
		}

		host_addr->flags = (uint8_t) tmp;
		break;
	default:
		break;
	}

	if (inet_pton(AF_INET, addr, host_addr->addr) > 0) {
		host_addr->addr_type = ADDRESS_IP;
	} else if (inet_pton(AF_INET6, addr, host_addr->addr) > 0) {
		host_addr->addr_type = ADDRESS_IP6;
	} else {
		memcpy(host_addr->addr, addr, sizeof(host_addr->addr));
		host_addr->addr_type = ADDRESS_NAME;
	}

	host_addr->pkey = pkey;

	return 0;
err:
	return -1;
}

static int
count_addr_records(FILE *fd, uint64_t *ipv4, uint64_t *ipv6, uint64_t *name)
{
	char gid[INET6_ADDRSTRLEN + 1], addr[INET6_ADDRSTRLEN + 1], s[160];
	struct in6_addr ip_addr, ib_addr;
	int idx;

	if (!fd || !ipv4 || !ipv6 || !name)
		return -1;

	*ipv4 = *ipv6 = *name = 0;

	while (fgets(s, sizeof s, fd)) {
		idx = 0;

		while (isspace(s[idx]))
			idx++;

		if (s[idx] == '#' || s[idx] == '[')
			continue;

		if (sscanf(s + idx, "%46s%46s", addr, gid) != 2)
			continue;

		if (inet_pton(AF_INET6, gid, &ib_addr) <= 0)
			continue;

		if (inet_pton(AF_INET, addr, &ip_addr) > 0)
			(*ipv4)++;
		else if (inet_pton(AF_INET6, addr, &ip_addr) > 0)
			(*ipv6)++;
		else
			(*name)++;
	}

	return 0;
}

struct host_addr *parse_addr(const char *addr_file,
			     uint64_t *ipv4, uint64_t *ipv6,
			     uint64_t *name, uint64_t *invalids)
{
	FILE *fd = NULL;
	struct host_addr *host_addrs = NULL;
	struct host_addr host_addr;
	char s[160], err_buf[64];
	int idx, i = 0, line = 0;
	uint16_t pkey = DEFAULT_PKEY;

	if (!(fd = fopen(addr_file, "r"))) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to open %s\n", addr_file);
		goto out;
        }

	if (count_addr_records(fd, ipv4, ipv6, name)) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "unable to count address records\n");
		goto out;
	}

	if (*ipv4 + *ipv6 + *name == 0)
		goto out;

	host_addrs = malloc((*ipv4 + *ipv6 + *name) * sizeof(*host_addrs));
	if (!host_addrs) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate memory\n");
		goto out;
	}

	rewind(fd);
	while (fgets(s, sizeof s, fd)) {
		line++;
		idx = 0;

		while (isspace(s[idx]))
			idx++;

		if (s[idx] == '#')
			continue;

		if (s[idx] == '[' && s[strlen(s) - 2] == ']') {
			pkey = get_pkey(s + idx);
			continue;
		}

		snprintf(err_buf, sizeof(err_buf), "%s:%d", addr_file, line);

		if (get_addr_record(s + idx, err_buf, pkey, &host_addr))
			continue;

		if (i < *ipv4 + *ipv6 + *name)
			host_addrs[i++] = host_addr;
		else
			ssa_log_warn(SSA_LOG_DEFAULT, "exceeded number of "
				     "address records allocated\n");
	}

	*invalids = (*ipv4 + *ipv6 + *name) - i;

	ssa_log(SSA_LOG_VERBOSE,
		"IPv4 %lu IPv6 %lu NAME %lu invalid records %lu\n",
		*ipv4, *ipv6, *name, *invalids);

out:
	if (fd)
		fclose(fd);
	return host_addrs;
}
