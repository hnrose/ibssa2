/*
 * Copyright 2015 Mellanox Technologies LTD. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <infiniband/ssa_db_helper.h>
#include <infiniband/ssa_db.h>
#include <infiniband/ssa_prdb.h>
#include <ssa_log.h>
#include <common.h>
#include <acm_shared.h>

static char log_file[128]	= "/var/log/hosts2addr.log";

static void print_usage(FILE* file,const char* name)
{
	fprintf(file, "Usage: %s [-m ssadb mode] [-o output directory] hosts file\n", name);
	fprintf(file, "SSA DB output modes:\n");
	fprintf(file, "\tb - Binary (default)\n");
	fprintf(file, "\td - Debug\n");
	fprintf(file, "\th - Human readable (cannot be preloaded later)\n");
}

static int is_file_exist(const char *fname)
{
	FILE *file;

	file = fopen(fname, "r");
	if (file) {
		fclose(file);
		return 1;
	}
	return 0;
}

static uint16_t get_pkey(char *buf)
{
	char pkey_str[8];
	char *endptr;
	long int tmp;
	int ret, invalid_input = 0;
	uint16_t pkey;

	ret = sscanf(buf, "[%*[ \tp]key%*[ \t=]%7s]", pkey_str);
	if (ret == 1) {
		tmp = strtol(pkey_str, &endptr, 16);
		if ((endptr == pkey_str) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp <= 0) ||
		    (tmp == 0x8000) || (tmp > ACM_DEFAULT_DEST_PKEY))
			invalid_input = 1;
		pkey = (uint16_t) tmp;
	} else {
		pkey = ACM_DEFAULT_DEST_PKEY;
	}

	if (invalid_input) {
		ssa_log_warn(SSA_LOG_DEFAULT,
			     "invalid pkey was specified (0x%x),"
			     " assuming default (0x%x)\n",
			     tmp, ACM_DEFAULT_DEST_PKEY);
		pkey = ACM_DEFAULT_DEST_PKEY;
	}

	return pkey;
}

struct lla_attr {
	struct in6_addr	ib_addr;
	uint32_t	qpn;
	uint8_t		flags;
	char		addr[INET6_ADDRSTRLEN + 1];
};

static int get_lla_attr(const char *buf, const char *file, int line,
			struct lla_attr *attr)
{
	char gid[INET6_ADDRSTRLEN + 1], buf1[8], buf2[16];
	char format[120];
	char *endptr;
	long int tmp;
	int ret;

	snprintf(format, sizeof(format), "%%%lus%%46s%%15s%%7s",
		 sizeof(attr->addr));
	ret = sscanf(buf, format, attr->addr, gid, buf2, buf1);
	if (ret < 2 || ret > 4)
		goto err;

	ssa_log(SSA_LOG_VERBOSE, "%s", buf);
	if (inet_pton(AF_INET6, gid, &attr->ib_addr) <= 0) {
		ssa_log_err(SSA_LOG_DEFAULT,
			    "%s is not IB GID\n", gid);
		goto err;
	}

	switch (ret) {
	case 2:
		attr->qpn = 0;
		attr->flags = 0;
		break;
	case 3:
		tmp = strtol(buf2, &endptr, 0);
		if ((endptr == buf2) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp < 0) ||
		    (tmp > 0xFFFFFF)) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid QPN was specified (0x%x) "
				    "gid %s %s:%d",
				    tmp, gid, file, line);
			goto err;
		}

		attr->qpn = (uint32_t) tmp;
		attr->flags = ACM_DEFAULT_DEST_REMOTE_FLAGS;
		break;
	case 4:
		tmp = strtol(buf2, &endptr, 0);
		if ((endptr == buf2) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp < 0) ||
		    (tmp > 0xFFFFFF)) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid QPN was specified (0x%x),"
				    " gid %s %s:%d\n",
				    tmp, gid, file, line);
			goto err;;
		}

		attr->qpn = (uint32_t) tmp;

		tmp = strtol(buf1, &endptr, 0);
		if ((endptr == buf1) || (errno == EINVAL) ||
		    (errno == ERANGE && (tmp == LONG_MIN ||
		     tmp == LONG_MAX)) || (tmp > 0xC0) ||
		    (tmp & 0x3F)) {
			ssa_log_err(SSA_LOG_DEFAULT,
				    "invalid flags were specified (0x"
				    "%x) gid %s %s:%d\n",
				    tmp, gid, file, line);
			goto err;
		}

		attr->flags = (uint8_t) tmp;
		break;
	default:
		break;
	}

	return 0;
err:
	return -1;
}

static int set_lla_addr(struct ssa_db *ssa_db, uint16_t pkey,
			struct lla_attr *attr, struct in6_addr *ip_addr)
{
	struct db_dataset *dataset;
	struct prdb_ipv4 *p_ipv4;
	struct prdb_ipv6 *p_ipv6;
	struct prdb_name *p_name;
	uint64_t set_count, set_size, rec_size;

	if (inet_pton(AF_INET, attr->addr, ip_addr) > 0) {
		dataset = &ssa_db->p_db_tables[PRDB_TBL_ID_IPv4];
		if (!dataset)
			return -1;

		set_count = ntohll(dataset->set_count);
		set_size = ntohll(dataset->set_size);

		p_ipv4 = ssa_db->pp_tables[PRDB_TBL_ID_IPv4] + set_size;
		rec_size = sizeof(*p_ipv4);
		memset(p_ipv4, 0, rec_size);
		p_ipv4->qpn = htonl(attr->qpn);
		p_ipv4->pkey = htons(pkey);
		p_ipv4->flags = attr->flags;
		memcpy(p_ipv4->gid, &attr->ib_addr, sizeof(p_ipv4->gid));
		memcpy(p_ipv4->addr, ip_addr, sizeof(p_ipv4->addr));
	} else if (inet_pton(AF_INET6, attr->addr, ip_addr) > 0) {
		dataset = &ssa_db->p_db_tables[PRDB_TBL_ID_IPv6];
		if (!dataset)
			return -1;

		set_count = ntohll(dataset->set_count);
		set_size = ntohll(dataset->set_size);

		p_ipv6 = ssa_db->pp_tables[PRDB_TBL_ID_IPv6] + set_size;
		rec_size = sizeof(*p_ipv6);
		memset(p_ipv6, 0, rec_size);
		p_ipv6->qpn = htonl(attr->qpn);
		p_ipv6->pkey = htons(pkey);
		p_ipv6->flags = attr->flags;
		memcpy(p_ipv6->gid, &attr->ib_addr, sizeof(p_ipv6->gid));
		memcpy(p_ipv6->addr, ip_addr, sizeof(p_ipv6->addr));
	} else {
		dataset = &ssa_db->p_db_tables[PRDB_TBL_ID_NAME];
		if (!dataset)
			return -1;

		set_count = ntohll(dataset->set_count);
		set_size = ntohll(dataset->set_size);

		p_name = ssa_db->pp_tables[PRDB_TBL_ID_NAME] + set_size;
		rec_size = sizeof(*p_name);
		memset(p_name, 0, rec_size);
		p_name->qpn = htonl(attr->qpn);
		p_name->pkey = htons(pkey);
		p_name->flags = attr->flags;
		memcpy(p_name->gid, &attr->ib_addr, sizeof(p_name->gid));
		strncpy((char *)p_name->addr, attr->addr, sizeof(p_name->addr));
	}

	dataset->set_count = htonll(set_count + 1);
	dataset->set_size = htonll(set_size + rec_size);

	return 0;
}

static struct ssa_db *gen_prdb(const char *hosts_file)
{
	FILE *f = NULL;
	struct ssa_db *ssa_db = NULL;
	char gid[INET6_ADDRSTRLEN + 1], s[160];
	uint64_t num_recs[PRDB_TBL_ID_MAX] = { 0 };
	struct lla_attr attr;
	struct in6_addr ip_addr;
	int idx, line = 0;
	uint16_t pkey = ACM_DEFAULT_DEST_PKEY;

	if (!(f = fopen(hosts_file, "r"))) {
		ssa_log_err(SSA_LOG_DEFAULT, "couldn't open %s\n", hosts_file);
		return NULL;
        }

	while (fgets(s, sizeof s, f)) {
		idx = 0;

		while (isspace(s[idx]))
			idx++;

		if (s[idx] == '#' || s[idx] == '[')
			continue;

		if (sscanf(s + idx, "%46s%46s", attr.addr, gid) != 2)
			continue;

		ssa_log(SSA_LOG_DEFAULT, "%s", s);
		if (inet_pton(AF_INET6, gid, &attr.ib_addr) <= 0) {
			ssa_log_err(SSA_LOG_DEFAULT, "%s is not IB GID\n", gid);
			continue;
		}

		if (inet_pton(AF_INET, attr.addr, &ip_addr) > 0) {
			num_recs[PRDB_TBL_ID_IPv4]++;
		} else if (inet_pton(AF_INET6, attr.addr, &ip_addr) > 0) {
			num_recs[PRDB_TBL_ID_IPv6]++;
		} else {
			num_recs[PRDB_TBL_ID_NAME]++;
		}
	}

	rewind(f);

	ssa_db = ssa_prdb_create(1 /* epoch */, num_recs);
	if (!ssa_db) {
		ssa_log_err(SSA_LOG_DEFAULT, "unable to allocate PRDB\n");
		fclose(f);
		return NULL;
	}

	while (fgets(s, sizeof s, f)) {
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

		if (get_lla_attr(s + idx, hosts_file, line, &attr))
			continue;

		if (set_lla_addr(ssa_db, pkey, &attr, &ip_addr))
			continue;

		ssa_log(SSA_LOG_DEFAULT, "added host %s IB GID %s\n", attr.addr, gid);
	}

	fclose(f);

	return ssa_db;
}

int main(int argc,char *argv[])
{
	enum ssa_db_helper_mode ssa_db_mode = SSA_DB_HELPER_STANDARD;
	char *output_path = NULL, *hosts_file = NULL;
	struct ssa_db *p_ssa_db = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "m:o:h?")) != -1) {
		switch (opt) {
		case 'm':
			if (optarg[0] == 'b') {
				ssa_db_mode = SSA_DB_HELPER_STANDARD;
			} else if (optarg[0] == 'd') {
				ssa_db_mode = SSA_DB_HELPER_DEBUG;
			} else if (optarg[0] == 'h') {
				ssa_db_mode = SSA_DB_HELPER_HUMAN;
			} else {
				print_usage(stdout, argv[0]);
				return 0;
			}
			break;
		case 'o':
			output_path = optarg;
			break;
		case '?':
		case 'h':
			print_usage(stdout, argv[0]);
			return 0;
			break;
		default: /* '?' */
			if(isprint (optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n",
					optopt);
			print_usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (argc == optind ) {
		fprintf(stderr,"Not enough input arguments\n");
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	} else if (argc == (optind + 1)) {
		hosts_file = argv[optind];
	} else {
		fprintf(stderr,"Too mutch input arguments\n");
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!hosts_file || !is_file_exist(hosts_file)) {
		fprintf(stderr, "File does not exist: %s\n", hosts_file);
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!output_path || !strlen(output_path)) {
		fprintf(stderr, "Invalid output path\n");
		exit(EXIT_FAILURE);
	}

	printf("Input hosts file: %s\n", hosts_file);
	printf("Output path: %s\n", output_path);

	ssa_open_log(log_file);
	ssa_set_ssa_signal_handler();

	p_ssa_db = gen_prdb(hosts_file);
	if (!p_ssa_db)
		exit(EXIT_FAILURE);

	ssa_db_save(output_path, p_ssa_db, ssa_db_mode);
	ssa_db_destroy(p_ssa_db);
	ssa_close_log();

	return 0;
}
