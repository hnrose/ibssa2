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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include <stdint.h>
#include <byteswap.h>

#include <ssa_smdb.h>
#include <ssa_db_helper.h>
#include <ssa_path_record.h>

#define GUIDS_CHUNK 1024

static void print_usage(FILE* file,const char* name)
{
	fprintf(file, "Usage: %s [-h] [-o output file] [-n number | -f file name | -a] [-l | -g]  input folder\n", name);
	fprintf(file, "\t-h\t\t-Print this help\n");
	fprintf(file, "\t-o\t\t-Output file location. If ommited, stdout is used\n");
	fprintf(file, "\t-f\t\t-Input file location. One ID per line\n");
	fprintf(file, "\t-n\t\t-Input ID\n");
	fprintf(file, "\t-a\t\t-Use all possible IDs. It's a default parameter.\n");
	fprintf(file, "\t-l\t\t-Input ID is LID\n");
	fprintf(file, "\t-g\t\t-Input ID is GUID. It's a default parameter\n");
	fprintf(file, "\t-r\t\t-Input IDs in host order\n");
	fprintf(file, "\tinput folder\t-SMDB database\n");
}

static int is_dir_exist(const char* path)
{
	DIR* dir = opendir(path);
	if(dir){
		closedir(dir);
		dir = NULL;
		return 1;
	}
	return 0;
}

static int is_file_exist(const char* path)
{
	FILE *file;
	if (file = fopen(path, "r")){
		fclose(file);
		return 1;
	}
	return 0;
}

static void print_memory_usage(const char* prefix)
{
	char buf[30];
	snprintf(buf, 30, "/proc/%u/statm", (unsigned)getpid());
	FILE* pf = fopen(buf, "r");
	if (pf) {
		unsigned size; //       total program size
		unsigned resident;//   resident set size
		unsigned share;//      shared pages
		unsigned text;//       text (code)
		unsigned lib;//        library
		unsigned data;//       data/stack
		unsigned dt;//         dirty pages (unused in Linux 2.6)
		fscanf(pf, "%u" /* %u %u %u %u %u"*/, &size/*, &resident, &share, &text, &lib, &data*/);
		printf("%s %u MB mem used\n",prefix, size / (1024.0));
	}
	fclose(pf);
}

static size_t get_dataset_count(const struct ssa_db_smdb* p_ssa_db_smdb,
		unsigned int table_id)
{
	const struct db_dataset *p_dataset = &p_ssa_db_smdb->db_tables[table_id];
	return ntohll(p_dataset->set_count);
}

struct input_prm
{
	char db_path[PATH_MAX];
	char dump_path[PATH_MAX];
	char input_path[PATH_MAX];
	be16_t lid;
	be64_t guid;
	short whole_world;
};

static void print_input_prm(const struct input_prm *prm)
{
	printf("SMDB database path: %s\n",prm->db_path);
	printf("Dump to : %s\n",strlen(prm->db_path)? prm->db_path: "stdout");
	if(prm->guid)
		printf("Input GUID. Host: 0x%"PRIx64" Network: 0x%"PRIx64"\n",ntohll(prm->guid),prm->guid);
	else if(prm->lid)
		printf("Input LID. Host: 0x%"PRIx16" Network: 0x%"PRIx16"\n",ntohs(prm->lid),prm->lid);
	else
		printf("Input file path: %s\n",prm->db_path);
	if(prm->whole_world)
		printf("Compute \"whole world\" path records.\n");
}

static void ssa_pr_path_output(const ssa_path_parms_t *p_path_prm, void *prm)
{
	FILE *fd = (FILE*)prm;
	fprintf(fd,"0x%"SCNu16" : %3u : %3u : %3u\n",p_path_prm->to_lid,0,p_path_prm->mtu,p_path_prm->rate);

}

static struct ssa_db_smdb * load_smdb(const char* path)
{
	struct ssa_db_smdb *db_diff = NULL; 
	clock_t start, end;
	double cpu_time_used;

	print_memory_usage("Memory usage before the database loading: ");

	start = clock();
	db_diff= ssa_db_load(path,SSA_DB_HELPER_DEBUG);
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	if(NULL != db_diff){
		printf("A database is loaded successfully.\n");
		printf("Loading cpu time: %.5f sec.\n",cpu_time_used);
		print_memory_usage("Memory usage after the database loading: ");
	}else{
		fprintf(stderr,"Database loading is failed.\n");
	}
	/*
	   start = clock();
	   ssa_db_save(output_path, db_diff,0);
	   end = clock();
	   cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	   printf("Saving cpu time: %.5f sec.\n",cpu_time_used);
	   */
	return db_diff;
}

static void destroy_smdb(struct ssa_db_smdb *db_diff)
{
	ssa_db_smdb_destroy(db_diff);
	printf("smdb database is destroyed\n");
}

static int run_pr_calculation(struct input_prm* p_prm)
{
	short dump_to_stdout = 1;
	FILE* fd_dump = NULL;
	FILE* fd_input = NULL;
	struct ssa_db_smdb * p_db_diff = NULL ;
	be64_t *p_guids = NULL;
	size_t count_guids = 0;

	if(ssa_open_log1(SSA_ACCESS_LAYER_OUTPUT_FILE)){
		fprintf(stderr,"Can't open log file: %s\n",SSA_ACCESS_LAYER_OUTPUT_FILE);
		return -1;
	}

	if(strlen(p_prm->dump_path)>0){
		fd_dump = fopen(p_prm->dump_path,"w");
		if(!fd_dump){
			fprintf(stderr,"Can't open file for writing: %s\n",p_prm->dump_path);
			return -1;
		}
		dump_to_stdout = 0;
	}else{
		fd_dump = stdout ;
		dump_to_stdout = 1;
	}

	p_db_diff = load_smdb(p_prm->db_path);
	if(NULL == p_db_diff)
		goto Exit;

	if(p_prm->lid){
		size_t i =0;
		const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl =
			(struct ep_guid_to_lid_tbl_rec *)p_db_diff->p_tables[SSA_TABLE_ID_GUID_TO_LID];
		const size_t count = get_dataset_count(p_db_diff,SSA_TABLE_ID_GUID_TO_LID);

		for (i = 0; i < count; i++) {
			if (p_prm->lid == p_guid_to_lid_tbl[i].lid){
				p_prm->guid = p_guid_to_lid_tbl[i].guid;
			}
		}
	}

	if(p_prm->guid){
		p_guids =(be64_t *)calloc(1,sizeof(be64_t));
		if(NULL==p_guids){
			fprintf(stderr,"Can't allocate array of guids\n");
			goto Exit;
		}
		p_guids[0] = p_prm->guid;

		count_guids = 1;
	}
	else if(p_prm->whole_world){
		size_t i =0;
		const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl =
			(struct ep_guid_to_lid_tbl_rec *)p_db_diff->p_tables[SSA_TABLE_ID_GUID_TO_LID];
		const size_t count = get_dataset_count(p_db_diff,SSA_TABLE_ID_GUID_TO_LID);

		p_guids =(be64_t *)calloc(count,sizeof(be64_t));
		if(NULL==p_guids){
			fprintf(stderr,"Can't allocate array of guids\n");
			goto Exit;
		}
		count_guids = count;

		for (i = 0; i < count; i++) 
			p_guids[i] = p_guid_to_lid_tbl[i].guid;

	}else{
		be64_t id = 0;
		be64_t tmp[GUIDS_CHUNK]={};
		size_t i =0 ;

		if(strlen(p_prm->input_path)>0){
			fd_input = fopen(p_prm->input_path,"r");
			if(!fd_input){
				fprintf(stderr,"Can't open file for reading: %s\n",p_prm->input_path);
				goto Exit;
			}

			while(1==fscanf(fd_input,"0x%"PRIx64"",&id)){
				tmp[i++] = id ;
				if(i==GUIDS_CHUNK){
					p_guids =(be64_t *)realloc(p_guids,(count_guids+GUIDS_CHUNK)*sizeof(be64_t));
					memcpy(p_guids+count_guids,tmp,GUIDS_CHUNK*sizeof(be64_t));
					count_guids+=GUIDS_CHUNK;
				}	
			}
		}
	}

	{
		size_t i = 0;
		for (i = 0; i < count_guids; i++) {
			be64_t guid = p_guids[i];
			ssa_pr_status_t res = SSA_PR_SUCCESS ;

			ssa_log(SSA_LOG_ALL,"Input guid: host order -  0x%-16"PRIx64" network order - 0x%-16"PRIx64"\n",ntohll(guid),guid);	
			res = ssa_pr_half_world(p_db_diff,guid,NULL,NULL);
			if(SSA_PR_SUCCESS != res){
				fprintf(stderr,"Path record algorithm is failed. Input guid: host order -  0x%"PRIx64" network order - 0x%"PRIx64"\n",ntohll(guid),guid);
				goto Exit;
			}
		}
	}
	/*
		   if(p_prm->guid){
		   ssa_pr_status_t res = ssa_pr_half_world(p_db_diff,p_prm->guid,NULL);
		   if(SSA_PR_SUCCESS != res){
		   fprintf(stderr,"Path record algorithm is failed. Input guid: host order -  0x%"PRIx64" network order - 0x%"PRIx64,ntohll(p_prm->guid),p_prm->guid);
		   goto Exit;
		   }
		   */
Exit:
if(NULL != p_db_diff)
	destroy_smdb(p_db_diff);

	if(!dump_to_stdout && fd_dump){
		fclose(fd_dump);
		fd_dump = NULL;
	}
if(fd_input){
	fclose(fd_input);
	fd_input = NULL;
}
if(NULL!=p_guids){
	free(p_guids);
	p_guids = NULL;
}
ssa_close_log1();
return 0;
}

int main(int argc,char *argv[])
{
	int opt;
	int index =0;
	struct input_prm prm;
	char dump_path[PATH_MAX]={};
	char input_path[PATH_MAX]={};
	char db_path[PATH_MAX]={};

	short use_output_opt = 0;
	short use_all_opt = 0;
	short use_file_opt = 0;
	short use_single_id_opt = 0;
	short use_guid_opt = 0;
	short use_lid_opt = 0;
	short use_host_order_opt = 0;
	short err_opt = 0;

	uint64_t id = 0; 
	char id_string_val[PATH_MAX] = {};

	memset(&prm,'\0',sizeof(prm));

	while ((opt = getopt(argc, argv, "rglan:f:o:h?")) != -1) {
		switch (opt) {
			case 'o':
				use_output_opt = 1;
				strncpy(dump_path,optarg,PATH_MAX);
				break;
			case 'a':
				use_all_opt = 1;
				prm.whole_world = 1;
				err_opt = use_file_opt || use_single_id_opt;
				break;
			case 'n':
				use_single_id_opt = 1;
				err_opt = use_file_opt || use_all_opt;
				if(!err_opt){
					strncpy(id_string_val,optarg,PATH_MAX);
				}
				break;
			case 'f':
				use_file_opt = 1;
				err_opt = use_single_id_opt || use_all_opt;
				break;
			case 'l':
				use_lid_opt = 1;
				err_opt = use_guid_opt;
				break;
			case 'g':
				use_guid_opt = 1;
				err_opt = use_lid_opt;
				break;
			case 'r':
				use_host_order_opt = 1;
				break;
			case '?':
			case 'h':
				print_usage(stdout,argv[0]);
				return 0;
				break;
			default: /* '?' */
				if(isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
				print_usage(stderr,argv[0]);
				exit(EXIT_FAILURE);
		}
		if(err_opt){
			fprintf (stderr, "Incompatible options.\n");
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (argc == optind ) {
		fprintf(stderr,"Not enough input arguments\n");
		print_usage(stderr,argv[0]);
		exit(EXIT_FAILURE);
	}else if(argc == (optind+1)){
		strncpy(db_path,argv[optind],PATH_MAX);
	}else{
		fprintf(stderr,"Too mutch input arguments\n");
		print_usage(stderr,argv[0]);
		exit(EXIT_FAILURE);
	}

	if(!use_file_opt && !use_single_id_opt)
		/*It's a default option*/
		use_all_opt = 1;

	prm.whole_world = use_all_opt;

	if(!use_lid_opt && !use_guid_opt)
		/*It's a default option*/
		use_guid_opt = 1;

	if(use_single_id_opt){
		int res = 0 ;

		if(strlen(id_string_val)>2 && '0'==id_string_val[0] && 'x'==id_string_val[1])
			res = sscanf(id_string_val,"0x%"PRIx64,&id);
		else
			res = sscanf(id_string_val,"%"PRIx64,&id);

		if(res!=1){
			fprintf(stderr,"String : %s can't be converted to numeric value.\n",id_string_val);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}

		if(use_host_order_opt)
			id = use_guid_opt? ntohll(id):ntohs(id);

		if(use_guid_opt)
			prm.guid = (be64_t)id;
		else
			prm.lid = (be16_t)id;
	}

	if(!is_dir_exist(db_path)){
		fprintf(stderr,"Directory does not exist: %s\n",db_path);
		print_usage(stderr,argv[0]);
		exit(EXIT_FAILURE);
	}else
		strncpy(prm.db_path,db_path,PATH_MAX);

	if(use_output_opt){
		if(is_file_exist(dump_path))
			fprintf(stderr,"Dump file will be replaced: %s\n",dump_path);
		strncpy(prm.dump_path,dump_path,PATH_MAX);
	}

	if(use_file_opt)
		if(!is_dir_exist(input_path)){
			fprintf(stderr,"Directory does not exist: %s\n",input_path);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}else
			strncpy(prm.input_path,input_path,PATH_MAX);

	print_input_prm(&prm);
	if(!run_pr_calculation(&prm))
		printf("Path record calculation is succeeded\n");
	else
		printf("Path record calculation is failed\n");

	return 0;
}
