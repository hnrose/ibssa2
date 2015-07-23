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
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <infiniband/ssa_db_helper.h>
#include <infiniband/ssa_db.h>
#include <infiniband/ssa_prdb.h>
#include <ssa_log.h>
#include <common.h>

static char log_file[128]	= "/var/log/prdb2hosts.log";
static uint64_t	subnet_prefix	= 0xfe80000000000000;
static uint32_t qpn		= 0x48;
static uint8_t flags		= 0x80;

union gid {
        uint8_t                 raw[16];
        struct {
                uint64_t        subnet_prefix;
                uint64_t        interface_id;
        } global;
};

static void print_usage(FILE* file,const char* name)
{
	fprintf(file, "Usage: %s [-m prdb mode] [-s subnet prefix] [-q QPN] "
		      "[-f flags] [-o hosts output file] prdb directory\n", name);
	fprintf(file, "PRDB input mode:\n");
	fprintf(file, "\tb - Binary (default)\n");
	fprintf(file, "\td - Debug\n");
}

static int is_dir_exist(const char* path)
{
	DIR *dir = opendir(path);

	if (dir) {
		closedir(dir);
		dir = NULL;
		return 1;
	}
	return 0;
}

static int gen_hosts(struct ssa_db *prdb, const char *hosts_file)
{
	FILE *fd;
	struct prdb_pr *tbl, *rec;
	char buf[120], ip[INET6_ADDRSTRLEN];
	uint8_t ipv4[4] = { 1, 1, 1, 1 };
	union gid gid;
	int j;
	uint64_t i, pr_cnt;
	uint16_t lid;

	fd = fopen(hosts_file, "w");
	if (!fd) {
		fprintf(stderr, "unable to open hosts file (%s) for writing\n",
			hosts_file);
		return -1;
	}

	tbl = (struct prdb_pr *) prdb->pp_tables[PRDB_TBL_ID_PR];
	pr_cnt = ntohll(prdb->p_db_tables[PRDB_TBL_ID_PR].set_count);

	fprintf(fd, "#\n");
	fprintf(fd, "# InfiniBand Communication Management Assistant for clusters hosts file\n");
	fprintf(fd, "#\n");
	fprintf(fd, "# Number of records:\t%lu\n", pr_cnt * 3);
	fprintf(fd, "# Subnet prefix used:\t0x%" PRIx64 "\n", subnet_prefix);
	fprintf(fd, "#\n\n");

	gid.global.subnet_prefix = htonll(subnet_prefix);

	for (i = 0; i < pr_cnt; i++) {
		rec = tbl + i;

		lid = ntohs(rec->lid);
		gid.global.interface_id = rec->guid;
		inet_ntop(AF_INET6, gid.raw, buf, sizeof(buf));
		inet_ntop(AF_INET, ipv4, ip, sizeof(ip));

		fprintf(fd, "%s %s 0x%x 0x%x\n", ip, buf, qpn, flags);
		fprintf(fd, "%s %s 0x%x 0x%x\n", buf, buf, qpn, flags);
		fprintf(fd, "host%u %s 0x%x 0x%x\n", lid, buf, qpn, flags);

		for (j = sizeof(ipv4) - 1; j >= 0; j--) {
			if (++ipv4[j])
				break;
		}
	}

	fclose(fd);

	return 0;
}

int main(int argc,char *argv[])
{
	enum ssa_db_helper_mode ssa_db_mode = SSA_DB_HELPER_STANDARD;
	char *input_path = NULL, *hosts_file = NULL;
	struct ssa_db *p_ssa_db = NULL;
	char *endptr;
	unsigned long int tmp;
	int opt;

	while ((opt = getopt(argc, argv, "m:o:s:f:q:h?")) != -1) {
		switch (opt) {
		case 'm':
			if (optarg[0] == 'b') {
				ssa_db_mode = SSA_DB_HELPER_STANDARD;
			} else if (optarg[0] == 'd') {
				ssa_db_mode = SSA_DB_HELPER_DEBUG;
			} else {
				print_usage(stdout, argv[0]);
				return 0;
			}
			break;
		case 'o':
			hosts_file = optarg;
			break;
		case 's':
			tmp = strtoull(optarg, &endptr, 0);
			if (endptr == optarg ||
			    (errno == ERANGE && tmp == ULONG_MAX)) {
				fprintf(stderr,
					"invalid subnet prefix specifed (%s), "
					"using default one 0x%" PRIx64 "\n",
					optarg, subnet_prefix);
			} else {
				subnet_prefix = (uint64_t) tmp;
			}
			break;
		case 'f':
			tmp = strtoull(optarg, &endptr, 0);
			if (endptr == optarg ||
			    (errno == ERANGE && tmp == ULONG_MAX) ||
			    (tmp > 0xC0) || (tmp & 0x3F)) {
				fprintf(stderr,
					"invalid flags specifed (%s), "
					"using default ones 0x%x\n",
					optarg, flags);
			} else {
				flags = (uint8_t) tmp;
			}
			break;
		case 'q':
			tmp = strtoull(optarg, &endptr, 0);
			if (endptr == optarg ||
			    (errno == ERANGE && tmp == ULONG_MAX) ||
			    tmp > 0xFFFFFF) {
				fprintf(stderr,
					"invalid QPN specifed (%s), "
					"using default one 0x%" PRIx32 "\n",
					optarg, qpn);
			} else {
				qpn = (uint32_t) tmp;
			}
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
		fprintf(stderr, "Not enough input arguments\n");
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	} else if (argc == (optind + 1)) {
		input_path = argv[optind];
	} else {
		fprintf(stderr, "Too much input arguments\n");
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!input_path || !is_dir_exist(input_path)) {
		fprintf(stderr, "Input directory does not exist: %s\n", input_path);
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!hosts_file || !strlen(hosts_file)) {
		fprintf(stderr, "Invalid output hosts file specified\n");
		exit(EXIT_FAILURE);
	}

	printf("Input PRDB path: %s\n", input_path);
	printf("Output hosts file: %s\n", hosts_file);

	ssa_open_log(log_file);

	ssa_set_ssa_signal_handler();

	p_ssa_db = ssa_db_load(input_path, ssa_db_mode);
	if (!p_ssa_db)
		exit(EXIT_FAILURE);

	if (gen_hosts(p_ssa_db, hosts_file)) {
		fprintf(stderr, "ERROR - unable to generate hosts file\n");
		exit(EXIT_FAILURE);
	}

	ssa_db_destroy(p_ssa_db);
	ssa_close_log();

	return 0;
}
