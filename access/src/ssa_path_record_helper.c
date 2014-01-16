/*
 * Copyright 2004-2014 Mellanox Technologies LTD. All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <time.h>
#include <iba/ib_types.h>
#include "ssa_path_record_helper.h"

/*
 * ib_path_compare_rates and ordered_rates are copied from OpenSM SA source.
 */

static int ordered_rates[] = {
	0, 0,	/*  0, 1 - reserved */
	1,	/*  2 - 2.5 Gbps */
	3,	/*  3 - 10  Gbps */
	6,	/*  4 - 30  Gbps */
	2,	/*  5 - 5   Gbps */
	5,	/*  6 - 20  Gbps */
	8,	/*  7 - 40  Gbps */
	9,	/*  8 - 60  Gbps */
	11,	/*  9 - 80  Gbps */
	12,	/* 10 - 120 Gbps */
	4,	/* 11 -  14 Gbps (17 Gbps equiv) */
	10,	/* 12 -  56 Gbps (68 Gbps equiv) */
	14,	/* 13 - 112 Gbps (136 Gbps equiv) */
	15,	/* 14 - 168 Gbps (204 Gbps equiv) */
	7,	/* 15 -  25 Gbps (31.25 Gbps equiv) */
	13,	/* 16 - 100 Gbps (125 Gbps equiv) */
	16,	/* 17 - 200 Gbps (250 Gbps equiv) */
	17	/* 18 - 300 Gbps (375 Gbps equiv) */
};

static int ib_path_compare_rates(const int rate1,const int rate2)
{
	int orate1 = 0, orate2 = 0;

	SSA_ASSERT(rate1 >= IB_MIN_RATE && rate1 <= IB_MAX_RATE);
	SSA_ASSERT(rate2 >= IB_MIN_RATE && rate2 <= IB_MAX_RATE);

	if (rate1 <= IB_MAX_RATE)
		orate1 = ordered_rates[rate1];
	if (rate2 <= IB_MAX_RATE)
		orate2 = ordered_rates[rate2];
	if (orate1 < orate2)
		return -1;
	if (orate1 == orate2)
		return 0;
	return 1;
}

/*
 *  calculate_rate_cmp_table - calculates and print a static
 *  lookup table for rate comparision
 */
static void calculate_rate_cmp_table()
{
	int i = 0, j = 0;
	const int n = 19;

	printf("\n");
	for (i = 0; i < n; ++i) {
		for (j = 0; j < n; ++j) {
			printf("%d %c", ib_path_compare_rates(i, j),
			       j == n -1 ? '\n' : ',' );
		}
	}
	printf("\n");
}

/*
 * check_rate_cmp_table - verifies SA's and a new fast version of
 * rate comparison function
 */
static void check_rate_cmp_table()
{
	int i = 0, j = 0;
	const int n = 19;

	for (i = 0; i < n; ++i) {
		for (j = 0; j < n; ++j) {
			if (ib_path_compare_rates(i, j) !=
			    ib_path_compare_rates_fast(i, j)) {
				fprintf(stderr,
					"rates_cmp_table is wrong i = %d, j = %d,"
					" ib_path_compare_rates = %d, ib_path_compare_rates_fast = %d\n",
					i, j,
					ib_path_compare_rates(i, j),
					ib_path_compare_rates_fast(i, j));
				return;
			}
		}
	}
	printf("rates_cmp_table is good\n");
}

/*
 * According to profiling results, ib_path_compare_rates takes about
 * 7% of the overall path record computation time.
 * rates_cmp_table is a static lookup table with precomputed results
 * of ib_path_compare. It is used as a performance optimization in
 * the path records algorithm.
 */
int rates_cmp_table[19][19] = {
	0, 0, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0, 0, -1, -1, -1, -1, -1, 1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 0, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 0, 1, 1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, -1, 1, 0, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 0, -1, -1, -1, 1, -1, -1, -1, 1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 0, -1, -1, 1, -1, -1, -1, 1, -1, 1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 0, -1, 1, 1, -1, -1, 1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, -1, -1, 1, -1, -1, -1,
	1, 1, 1, 1, -1, 1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 0, -1, -1, 1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, -1, 1, 1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, 1, -1, -1, -1, 0, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 0, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0 };

int ssa_pr_log_level = SSA_PR_ERROR_LEVEL;
FILE *ssa_pr_log_fd = NULL;

const char *get_time()
{
	static char buffer[64] = {};
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", timeinfo);

	return buffer;
}
