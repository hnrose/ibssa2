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
#include <linux/limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>


int is_dir_exist(const char* path)
{
	DIR* dir = opendir(path);
	if(dir){
		closedir(dir);
		dir = NULL;
		return 1;
	}
	return 0;
}

int print_memory_usage(FILE* out,const char* prefix)
{
	char buf[30]={};
	int res =0;

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
		res = fprintf(out,"%s %u MB mem used\n",prefix, size / (1024.0));
	}
	fclose(pf);
	return res;
}

int print_filename(FILE* out, FILE* fp,const char *msg)
{
	int fno=0;
	ssize_t r=0;
	int MAXSIZE = 0xFFF;
	char proclnk[0xFFF]={};
	char filename[0xFFF]={};
	int res = 0;

	if (fp != NULL)
	{
		fno = fileno(fp);
		sprintf(proclnk, "/proc/self/fd/%d", fno);
		r = readlink(proclnk, filename, MAXSIZE);
		if (r < 0)
		{
			printf("failed to readlink\n");
			exit(1);
		}
		filename[r] = '\0';
		res = fprintf(out,"fp -> fno -> filename: %p -> %d -> %s : %s\n",
				fp, fno, filename,msg);
	}
	return res;
}

