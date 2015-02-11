/*
 * Copyright 2004-2015 Mellanox Technologies LTD. All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <byteswap.h>

#include <ssa_db.h>
#include <ssa_smdb.h>
#include <ssa_prdb.h>
#include <ssa_db_helper.h>
#include <infiniband/ssa_path_record.h>


#define PRTVECTOR_AUTOGROW_MASK 0x01
#define PRTVECTOR_AUTOFREE_MASK 0x02

typedef struct {
	void **data;
	size_t size;
	size_t count;
	uint64_t prm;
} ptrvector_t;

static ptrvector_t *ptrvector_create(size_t size, int autogrow, int autodelete)
{
	ptrvector_t *tmp = (ptrvector_t *)malloc(sizeof(ptrvector_t));
	if(tmp) {
		tmp->data = calloc(size, sizeof(void*));
		if(!tmp->data) {
			free(tmp);
			return NULL;
		}
		tmp->size = size;
		tmp->count = 0;
		tmp->prm = 0;
		if(autogrow)
			tmp->prm |= PRTVECTOR_AUTOGROW_MASK;
		if(autodelete)
			tmp->prm |= PRTVECTOR_AUTOFREE_MASK ;
	}
	return tmp;
}

static void ptrvector_destroy(ptrvector_t *vec)
{
	if(vec) {
		if(vec->prm & PRTVECTOR_AUTOFREE_MASK) {
			size_t i;
			for(i = 0; i < vec->count; i++)
					free(vec->data[i]);
		}
		free(vec->data);
		vec->size = 0;
		vec->count = 0;
	}
	free(vec);
}

static int ptrvector_grow(ptrvector_t *vec, size_t extend)
{
	size_t new_size;
	void **data;

	if(!vec)
		return 1;

	new_size = vec->size + extend;
	data = (void*)realloc(vec->data,new_size * sizeof(void*));
	if(!data)
		return 1;

	vec->size = new_size;
	vec->data = data;

	return 0;
}

static int ptrvector_get(ptrvector_t *vec, size_t idx,void **element)
{
	if(!vec || idx >= vec->count)
		return 1;
	*element = vec->data[idx];
	return 0;
}

static int ptrvector_set(ptrvector_t *vec, size_t idx, void *element)
{
	if(!vec || idx >= vec->count)
		return 1;

	vec->data[idx] = element;
	return 0;
}

static int ptrvector_pushback(ptrvector_t *vec,void *element)
{
	size_t idx;

	if(!vec || !(vec->prm | PRTVECTOR_AUTOGROW_MASK))
		return 1;

	idx = vec->count;

	if(idx >= vec->size) {
		size_t new_size;
		int ret;

		if(!vec->size) {
			new_size = idx + 1;
		}
		else {
			int n = (idx + 1) / vec->size;
			new_size = (n + 1) * vec->size;
		}

		ret = ptrvector_grow(vec,new_size - vec->size);
		if(ret)
			return ret;
	}

	vec->data[idx] = element;
	vec->count++;

	return 0;
}


static char log_file[PATH_MAX] = "/var/log/pr_pair.log";

static void print_usage(FILE *file,const char *name)
{
	int i = 0;

	fprintf(file,"Usage: %s [-h] [-o output file | -O output folder] [-n number | -f file name | -a] [-l | -g] [-L file name] [-v number] input folder\n", name);
	fprintf(file,"\t-h\t\t-Print this help\n");
	fprintf(file,"\t-o\t\t-Output file location. If ommited, stdout is used\n");
	fprintf(file,"\t-O\t\t-PRDB location\n");
	fprintf(file,"\t-f\t\t-Input file location. One ID per line\n");
	fprintf(file,"\t-n\t\t-Input ID\n");
	fprintf(file,"\t-a\t\t-Use all possible IDs. It's a default parameter.\n");
	fprintf(file,"\t-l\t\t-Input ID is LID\n");
	fprintf(file,"\t-g\t\t-Input ID is GUID. It's a default parameter\n");
	fprintf(file,"\t-L\t\t-Access Layer log file path. If ommited, stdout is used.\n");
	fprintf(file,"\t-v\t\t-Log verbosity level. Default value is 1\n");
	fprintf(file,"\t\t\t\t# Indicates the amount of detailed data written to the log file.  Log levels\n");
	fprintf(file,"\t\t\t\t# should be one of the following values:\n");
	fprintf(file,"\t\t\t\t\t# bit 0 - basic configuration & errors\n");
	fprintf(file,"\t\t\t\t\t# bit 1 - verbose configuration & errors\n");
	fprintf(file,"\t\t\t\t\t# bit 2 - verbose operation\n");
	fprintf(file,"\t\t\t\t\t# bit 5 - verbose PathRecord computation\n");
	fprintf(file,"\tinput folder\t-SMDB database\n");
}

static int is_dir_exist(const char* path)
{
	DIR *dir = opendir(path);

	if(dir) {
		closedir(dir);
		dir = NULL;
		return 1;
	}
	return 0;
}

static int is_file_exist(const char *path)
{
	FILE *file;

	if (file = fopen(path, "r")) {
		fclose(file);
		return 1;
	}
	return 0;
}

static void print_memory_usage(const char* prefix)
{
	char buf[30] = {};

	snprintf(buf,30,"/proc/%u/statm",(unsigned)getpid());
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
	pf = NULL;
}

static size_t get_dataset_count(const struct ssa_db *p_ssa_db_smdb,
		unsigned int table_id)
{
	const struct db_dataset *p_dataset = &p_ssa_db_smdb->p_db_tables[table_id];
	return ntohll(p_dataset->set_count);
}

struct input_prm
{
	char smdb_path[PATH_MAX];
	char dump_path[PATH_MAX];
	char prdb_path[PATH_MAX];
	char input_path[PATH_MAX];
	char log_path[PATH_MAX];
	uint64_t id;
	uint8_t whole_world;
	uint8_t is_guid;
	uint8_t log_verbosity;
};


static void print_input_prm(const struct input_prm *prm)
{
	printf("Log path: %s\n",prm->log_path);
	if(prm->log_verbosity >= 0) {
		printf("Log verbosity: %d\n", prm->log_verbosity);
	} else {
		printf("Log verbosity: --- The parameter is wrong ---");
	}
	if(strlen(prm->prdb_path))
		printf("PRDB path : %s\n",prm->prdb_path);
	else
		printf("Dump PR log to : %s\n",strlen(prm->dump_path)? prm->dump_path: "stdout");

	printf("SMDB database path: %s\n",prm->smdb_path);
	if(prm->id) {
		if(prm->is_guid) {
			printf("Input GUID: 0x%"PRIx64"\n",prm->id);
			return;
		} else {
			printf("Input LID: 0x%"PRIx16"\n",prm->id);
			return;
		}
	} else if(strlen(prm->input_path)) {
		printf("Input file with IDs: %s\n",prm->input_path);
	}

	if(prm->whole_world) {
		printf("Compute \"whole world\" path records.\n");
		return;
	}
}

static ptrvector_t  *init_pr_path_container()
{
	return ptrvector_create(1000,1,1);
}
/*
static gint path_compare(gconstpointer a,gconstpointer b)
{
	ssa_path_parms_t *p_path_a = *(ssa_path_parms_t **)a;
	ssa_path_parms_t *p_path_b = *(ssa_path_parms_t **)b;

	uint16_t from_lid_a = ntohs(p_path_a->from_lid);
	uint16_t from_lid_b = ntohs(p_path_b->from_lid);
	uint16_t to_lid_a = ntohs(p_path_a->to_lid);
	uint16_t to_lid_b = ntohs(p_path_b->to_lid);
	int diff_from = from_lid_a - from_lid_b;
	int diff_to = to_lid_a - to_lid_b;

	return diff_from ? diff_from : diff_to;
}
*/
static const struct ep_port_tbl_rec* find_port(const struct ssa_db* p_ssa_db_smdb,
		const be16_t lid)
{
	size_t i = 0;
	const struct ep_port_tbl_rec  *p_port_tbl =
		(const struct ep_port_tbl_rec*)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_PORT];
	const size_t count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_PORT);

	for (i = 0; i < count; i++){
		if(p_port_tbl[i].port_lid==lid)
			return p_port_tbl+i;
	}
	return NULL;
}

static const struct ep_guid_to_lid_tbl_rec *find_guid_to_lid_rec_by_lid(const struct ssa_db* p_ssa_db_smdb,
		const be16_t lid)
{
	size_t i =0;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl =
		(struct ep_guid_to_lid_tbl_rec *)p_ssa_db_smdb->pp_tables[SSA_TABLE_ID_GUID_TO_LID];
	const size_t count = get_dataset_count(p_ssa_db_smdb,SSA_TABLE_ID_GUID_TO_LID);

	for (i = 0; i < count; i++) {
		if (lid == p_guid_to_lid_tbl[i].lid)
			return p_guid_to_lid_tbl+i;
	}
	return NULL;
}

static void dump_pr(ptrvector_t *path_arr,struct ssa_db *p_smdb,FILE *fd)
{
	size_t i = 0;
	uint16_t prev_lid = 0;
	short first_line = 1;
	ssa_path_parms_t *p_path_prm = NULL;
	int ret = 0;

	// TODO: implement sorting
//	g_ptr_array_sort(path_arr,path_compare);

	for (i = 0; i < path_arr->count; i++) {
		ret = ptrvector_get(path_arr,i,(void**)&p_path_prm);
		if(ret)
			break;

		if(prev_lid != p_path_prm->from_lid) {
			const struct ep_port_tbl_rec *p_port_rec = find_port(p_smdb,p_path_prm->from_lid);
			const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_rec = find_guid_to_lid_rec_by_lid(p_smdb,p_path_prm->from_lid);

			assert(p_port_rec && p_guid_to_lid_rec );

			prev_lid = p_path_prm->from_lid;
			if(first_line)
				first_line = 0;
			else
				fprintf(fd,"\n");

			fprintf(fd,"%s 0x%016"PRIx64", base LID %"SCNu16", port %u\n",!p_guid_to_lid_rec->is_switch?"Channel Adapter":"Switch",
					ntohll(p_guid_to_lid_rec->guid),ntohs(p_guid_to_lid_rec->lid),p_port_rec->port_num);
			fprintf(fd,"# LID  : SL : MTU : RATE\n");
		}
		fprintf(fd,"0x%04X"" : %-2d : %-3d : %-4d\n",ntohs(p_path_prm->to_lid),0,p_path_prm->mtu,p_path_prm->rate);
	}
	fprintf(fd,"\n");
}

static int ssa_pr_path_output(const ssa_path_parms_t *p_path_prm, void *prm)
{
	ssa_path_parms_t *p_my_path = NULL;
	ptrvector_t *path_arr = (ptrvector_t *)prm;

	p_my_path = (void*)malloc(sizeof *p_my_path);

	memcpy(p_my_path,p_path_prm,sizeof(*p_my_path));
	ptrvector_pushback(path_arr,p_my_path);

	return 0;
}

static struct ssa_db *load_smdb(const char *path)
{
	struct ssa_db *db_diff = NULL;
	clock_t start, end;
	double cpu_time_used;

	print_memory_usage("Memory usage before the database loading: ");

	start = clock();
	db_diff = ssa_db_load(path,SSA_DB_HELPER_DEBUG);
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	if(NULL != db_diff) {
		printf("A database is loaded successfully.\n");
		printf("Loading cpu time: %.5f sec.\n",cpu_time_used);
		print_memory_usage("Memory usage after the database loading: ");
	} else {
		fprintf(stderr,"Database loading is failed.\n");
	}

	return db_diff;
}

static void destroy_smdb(struct ssa_db *db_diff)
{
	ssa_db_destroy(db_diff);
	printf("smdb database is destroyed.\n");
}

static size_t read_ids_from_file(const char *path,ptrvector_t *arr)
{
	FILE* fd = NULL;
	size_t count = 0;
	uint64_t id = 0;

	if(0 == strlen(path))
		goto Exit;

	fd = fopen(path,"r");
	if(!fd) {
		fprintf(stderr,"Can't open file for reading: %s\n",path);
		goto Exit;
	}

	while(1 == fscanf(fd,"0x%"PRIx64"\n",&id)) {
		ptrvector_pushback(arr,(void*)id);
		count++;
	}

Exit:
	if(!fd) {
		fclose(fd);
		fd = NULL;
	}
	return count;
}

static int compare_ints(uint64_t a,uint64_t b)
{
	return a - b;
}

static size_t get_input_guids(const struct input_prm *p_prm,
		struct ssa_db *p_db,
		ptrvector_t* p_arr)
{
	size_t i, count;
	const struct ep_guid_to_lid_tbl_rec *p_guid_to_lid_tbl;

	assert(p_prm && p_arr && p_db);

	if(p_prm->is_guid) {
		/*There is only one guid*/
		ptrvector_pushback(p_arr,(void*)p_prm->id);
		return 1;
	} else if(p_prm->whole_world) {
		p_guid_to_lid_tbl =
			(struct ep_guid_to_lid_tbl_rec *)p_db->pp_tables[SSA_TABLE_ID_GUID_TO_LID];
		count = get_dataset_count(p_db,SSA_TABLE_ID_GUID_TO_LID);

		for (i = 0; i < count; i++) {
			uint64_t id = ntohll(p_guid_to_lid_tbl[i].guid);
			ptrvector_pushback(p_arr,(void*)id);
		}
	} else if(strlen(p_prm->input_path)>0) {
		const size_t tmp = read_ids_from_file(p_prm->input_path,p_arr);

		if(0 == tmp) {
			fprintf(stderr,"Can't read ids from file: %s",p_prm->input_path);
			return 0;
		}
	}

	// TODO: implement duplicates removing
	//g_array_sort(p_arr, (GCompareFunc)compare_ints);
	//remove_duplicates(p_arr);

	return 0;
}

static int run_pr_calculation(struct input_prm* p_prm)
{
	short dump_to_stdout = 0;
	short dump_to_prdb = 1;
	FILE *fd_dump = NULL;
	struct ssa_db *p_db_diff = NULL;
	void *p_context = NULL;
	be64_t *p_guids = NULL;
	size_t count_guids = 0;
	ptrvector_t *path_arr = NULL;
	ptrvector_t *guids_arr = NULL;
	size_t i = 0;
	int res = 0;
	ssa_pr_status_t pr_res = SSA_PR_SUCCESS;
	struct ssa_db *p_prdb = NULL;


	dump_to_prdb = strlen(p_prm->prdb_path);
	if(!dump_to_prdb) {
		if(strlen(p_prm->dump_path) > 0) {
			fd_dump = fopen(p_prm->dump_path,"w");
			if(!fd_dump) {
				fprintf(stderr,"Can't open file for writing: %s\n",p_prm->dump_path);
				return -1;
			}
			dump_to_stdout = 0;
		} else {
			fd_dump = stdout;
			dump_to_stdout = 1;
		}
	}

	p_db_diff = load_smdb(p_prm->smdb_path);
	if(NULL == p_db_diff){
		fprintf(stderr,"Can't create smdb database from: %s .",p_prm->smdb_path);
		res = -1;
		goto Exit;
	}

	guids_arr = ptrvector_create(10000,1,0);
	if(NULL == guids_arr) {
		fprintf(stderr,"Can't create an array for guids.\n");
		res = -1;
		goto Exit;
	}

	path_arr = init_pr_path_container();
	if(NULL == path_arr) {
		fprintf(stderr,"Can't create a storage for path records.\n");
		res = -1;
		goto Exit;
	}

	p_context = ssa_pr_create_context();
	if(NULL == p_context) {
		fprintf(stderr,"Can't create path record calculation context\n");
		res = -1;
		goto Exit;
	}

	if(dump_to_prdb) {
		get_input_guids(p_prm,p_db_diff,guids_arr);
		if(guids_arr->count) {
			be64_t guid;
			if(ptrvector_get(guids_arr,0,(void**)&guid))
			{
				fprintf(stderr,"Can't obtain a guid\n");
				goto Exit;
			}
			guid = htonll(guid);
			res = ssa_pr_compute_half_world(p_db_diff,p_context,guid,&p_prdb);
			if(res != SSA_PR_SUCCESS) {
				fprintf(stderr,"Path record computation failed. prdb database was not created\n");
				goto Exit;
			}
		} else {
			fprintf(stderr,"Path record computation failed. There is no input GUID\n");
			goto Exit;
		}
	}

	if(!p_prm->whole_world) {
		get_input_guids(p_prm,p_db_diff,guids_arr);
		for(i = 0; i < guids_arr->count && SSA_PR_SUCCESS == res; ++i) {
			be64_t guid;
			ptrvector_get(guids_arr,i,(void**)&guid);
			guid = htonll(guid);

			pr_res = ssa_pr_half_world(p_db_diff,p_context,guid,ssa_pr_path_output,path_arr);
		}
	} else {
		pr_res = ssa_pr_whole_world(p_db_diff,p_context,ssa_pr_path_output,path_arr);
	}

	if(SSA_PR_SUCCESS != pr_res) {
		fprintf(stderr,"Path record algorithm is failed.\n");
		res = -1;
		goto Exit;
	}

	if(!dump_to_prdb) {
		printf("%u path records found\n",path_arr->count);
		dump_pr(path_arr,p_db_diff,fd_dump);
	} else {
		ssa_db_save(p_prm->prdb_path,p_prdb,SSA_DB_HELPER_DEBUG);
		fprintf(stdout,"prdb database is created\n");
		ssa_db_destroy(p_prdb);
		p_prdb = NULL;
	}

Exit:
	if(p_context ) {
		ssa_pr_destroy_context(p_context);
		p_context = NULL;
	}
	if(p_db_diff) {
		destroy_smdb(p_db_diff);
		p_db_diff = NULL;
	}
	if(!dump_to_stdout && fd_dump) {
		fclose(fd_dump);
		fd_dump = NULL;
	}
	if(p_guids) {
		free(p_guids);
		p_guids = NULL;
	}
	if(path_arr) {
		ptrvector_destroy(path_arr);
		path_arr = NULL;
	}
	if(guids_arr) {
		ptrvector_destroy(guids_arr);
		guids_arr = NULL;
	}
	if(p_prdb) {
		ssa_db_destroy(p_prdb);
		p_prdb = NULL;
	}
	return res;
}

int main(int argc,char *argv[])
{
	int opt = 0;
	int index = 0;
	struct input_prm prm;
	char dump_path[PATH_MAX] = {};
	char input_path[PATH_MAX] = {};
	char smdb_path[PATH_MAX] = {};
	char prdb_path[PATH_MAX] = {};
	char log_path[PATH_MAX] = {};
	short use_output_opt = 0;
	short use_all_opt = 0;
	short use_file_opt = 0;
	short use_single_id_opt = 0;
	short use_guid_opt = 0;
	short use_lid_opt = 0;
	short use_log_opt = 0;
	short use_verbosity_opt =0;
	short use_prdb_dump = 0;
	short err_opt = 0;
	uint64_t id = 0;
	char id_string_val[PATH_MAX] = {};
	char verbosity_string_val[PATH_MAX] = {};
	int rt = 0;
	static struct option long_options[] = {
		{0, 0, 0, 0 }
	};
	int option_index = 0;

	memset(&prm,'\0',sizeof(prm));

	ssa_set_ssa_signal_handler();


	while ((opt = getopt_long(argc, argv, "glan:f:o:O:hL:v:?", long_options, &option_index)) != -1) {
		switch (opt) {
			case 'O':
				use_prdb_dump  = 1;
				strncpy(prdb_path,optarg,PATH_MAX);
				err_opt = use_file_opt  || use_all_opt ;
				break;
			case 'o':
				use_output_opt = 1;
				strncpy(dump_path,optarg,PATH_MAX);
				break;
			case 'L':
				use_log_opt  = 1;
				strncpy(log_path,optarg,PATH_MAX);
				break;
			case 'a':
				use_all_opt = 1;
				prm.whole_world = 1;
				err_opt = use_file_opt || use_single_id_opt || use_prdb_dump;
				break;
			case 'n':
				use_single_id_opt = 1;
				err_opt = use_file_opt || use_all_opt;
				if(!err_opt){
					strncpy(id_string_val,optarg,PATH_MAX);
				}
				break;
			case 'v':
				use_verbosity_opt  = 1;
				strncpy(verbosity_string_val,optarg,PATH_MAX);
				break;
			case 'f':
				use_file_opt = 1;
				err_opt = use_single_id_opt || use_all_opt || use_prdb_dump;
				strncpy(input_path,optarg,PATH_MAX);
				break;
			case 'l':
				use_lid_opt = 1;
				err_opt = use_guid_opt;
				break;
			case 'g':
				use_guid_opt = 1;
				err_opt = use_lid_opt;
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
		if(err_opt) {
			fprintf (stderr, "Incompatible options.\n");
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (argc == optind ) {
		fprintf(stderr,"Not enough input arguments\n");
		print_usage(stderr,argv[0]);
		exit(EXIT_FAILURE);
	}else if(argc == (optind+1)) {
		strncpy(smdb_path,argv[optind],PATH_MAX);
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

	if(use_single_id_opt) {
		int res = 0;

		if (use_guid_opt) {
			if(strlen(id_string_val) > 2 && '0' == id_string_val[0] && 'x' == id_string_val[1])
				res = sscanf(id_string_val,"0x%"PRIx64,&id);
			else
				res = sscanf(id_string_val,"%"PRIx64,&id);
		} else
			res = sscanf(id_string_val,"%u",&id);

		if(res != 1) {
			fprintf(stderr,"String : %s can't be converted to numeric value.\n",id_string_val);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}

		prm.id = id;
		prm.is_guid = use_guid_opt;
	}

	if(use_verbosity_opt && strlen(verbosity_string_val)) {
		int res = 0;
		int verbosity = -1;

		res = sscanf(verbosity_string_val,"%d",&verbosity);

		if(res != 1) {
			fprintf(stderr,"String : %s can't be converted to numeric value.\n"
					,verbosity_string_val);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}

		if(verbosity < 0) {
			fprintf(stderr,"Vebosity paramater has wrong value: %d.\n",verbosity);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		}
		prm.log_verbosity = verbosity;
	} else {
		prm.log_verbosity = 1;
	}

	if(strlen(log_path)) {
		if(is_file_exist(log_path)) {
			fprintf(stderr,"Log file will be replaced: %s\n",log_path);
			strncpy(prm.log_path,log_path,PATH_MAX);
		}
	} else {
		strncpy(prm.log_path,"stderr",PATH_MAX);
	}

	ssa_open_log(prm.log_path);
	ssa_set_log_level(prm.log_verbosity);

	if(!is_dir_exist(smdb_path)) {
		fprintf(stderr,"Directory does not exist: %s\n",smdb_path);
		print_usage(stderr,argv[0]);
		exit(EXIT_FAILURE);
	} else {
		strncpy(prm.smdb_path,smdb_path,PATH_MAX);
	}

	prm.dump_path[0] = '\0';
	prm.prdb_path[0] = '\0';
	if(use_prdb_dump) {
		if(!is_dir_exist(prdb_path)) {
			fprintf(stderr,"Directory does not exist: %s\n",prdb_path);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		} else {
			strncpy(prm.prdb_path,prdb_path,PATH_MAX);
		}
	} else {
		if(use_output_opt && strcmp(dump_path,"stdout")) {
			if(is_file_exist(dump_path))
				fprintf(stderr,"Dump file will be replaced: %s\n",dump_path);
			strncpy(prm.dump_path,dump_path,PATH_MAX);
		}
	}

	if(use_file_opt)
		if(!is_file_exist(input_path)) {
			fprintf(stderr,"File does not exist: %s\n",input_path);
			print_usage(stderr,argv[0]);
			exit(EXIT_FAILURE);
		} else {
			strncpy(prm.input_path,input_path,PATH_MAX);
		}

	print_input_prm(&prm);

	rt = run_pr_calculation(&prm);

	ssa_close_log ();

	return rt;
}
