/*
 * Copyright 2013 Mellanox Technologies LTD. All rights reserved.
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
#include <time.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <infiniband/ssa_db_helper.h>
#include <infiniband/ssa_db.h>
#include <ssa_log.h>
#include <common.h>

static char log_file[128] = "/var/log/loadsave.log";

static void print_usage(FILE* file,const char* name)
{
	fprintf(file, "Usage: %s [-m ssadb mode] [-o output folder] input folder\n",name);
	fprintf(file, "ssadb modes:\n");
	fprintf(file, "b -Binary (default)\n");
	fprintf(file, "d -Debug\n");
}

static int is_dir_exist(const char* path)
{
	DIR  *dir = opendir(path);
	if (dir) {
		closedir(dir);
		dir = NULL;
		return 1;
	}

	return 0;
}

static void print_memory_usage(const char* prefix)
{
	FILE *pf = NULL;
	char buf[30];

	snprintf(buf, 30, "/proc/%u/statm", (unsigned)getpid());
	pf = fopen(buf, "r");
	if (pf) {
		unsigned size;		/* total program size */
		//unsigned resident;	/* resident set size */
		//unsigned share;		/* shared pages */
		//unsigned text;		/* text (code) */
		//unsigned lib;		/* library */
		//unsigned data;		/* data/stack */
		//unsigned dt;		/* dirty pages (unused in Linux 2.6) */
		fscanf(pf, "%u" /* %u %u %u %u %u"*/, &size/*, &resident, &share, &text, &lib, &data*/);
		printf("%s %u MB mem used\n",prefix, size / (1024));
	}

	fclose(pf);
}

int main(int argc,char *argv[])
{
	int opt;
	char output_path[PATH_MAX] = {};
	char input_path[PATH_MAX] = {};
	struct ssa_db *p_ssa_db = NULL;
	clock_t start, end;
	double cpu_time_used;
	enum ssa_db_helper_mode ssa_db_mode = SSA_DB_HELPER_STANDARD;

	while ((opt = getopt(argc, argv, "m:o:h?")) != -1) {
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
				strncpy(output_path, optarg, PATH_MAX);
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
		strncpy(input_path, argv[optind], PATH_MAX);
	} else {
		fprintf(stderr,"Too mutch input arguments\n");
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!is_dir_exist(input_path)) {
		fprintf(stderr, "Directory does not exist: %s\n", input_path);
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!strlen(output_path)) {
		sprintf(output_path, "%s.output",input_path);
	}

	printf("Input path: %s\n", input_path);
	printf("Output path: %s\n", output_path);

	ssa_open_log(log_file);
	print_memory_usage("Memory usage before the database loading: ");

	start = clock();
	p_ssa_db = (struct ssa_db *) ssa_db_load(input_path, ssa_db_mode);
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	if (NULL != p_ssa_db) {
		printf("A database is loaded successfully.\n");
		printf("Loading cpu time: %.5f sec.\n", cpu_time_used);
		print_memory_usage("Memory usage after the database loading: ");
	} else {
		fprintf(stderr, "Database loading is failed.\n");
		ssa_close_log();
		exit(EXIT_FAILURE);
	}

	start = clock();
	ssa_db_save(output_path, p_ssa_db, ssa_db_mode);
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Saving cpu time: %.5f sec.\n", cpu_time_used);

	ssa_db_destroy(p_ssa_db);
	p_ssa_db = NULL;
	ssa_close_log();

	return 0;
}
