/*
 * Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <err.h>
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <ssa_log.h>

#define MAX_BACKTRACE_FRAMES 100

extern FILE *flog;
extern void get_thread_id(char *buff, int size);
extern char *month_str[];

static pthread_spinlock_t signal_handler_lock;

static int ssa_print_backtrace(int start_frame, FILE *flog);

static char exe_path[PATH_MAX];

#if defined(__linux__)
int get_exe_path()
{
	return readlink("/proc/self/exe", exe_path, sizeof(exe_path)) > 0 ? 0 : -1;
}
#else
#define get_exe_path(var) (1)
#endif

static void ssa_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	char thread_name[20];
	struct timeval tv;
	time_t tim;
	struct tm result;
	int ret;
	(void) context;

	ssa_set_log_level(0);

	gettimeofday(&tv, NULL);
	tim = tv.tv_sec;
	localtime_r(&tim, &result);
	get_thread_id(thread_name, sizeof thread_name);

	ret = pthread_spin_trylock(&signal_handler_lock);
	if (ret == EBUSY)
		return;

	fprintf(flog, "%s %02d %02d:%02d:%02d %06d [%.16s]: signal %d received\n",
		(result.tm_mon < 12 ? month_str[result.tm_mon] : "???"),
		result.tm_mday, result.tm_hour, result.tm_min,
		result.tm_sec, (unsigned int)tv.tv_usec, thread_name, sig);

	switch(sig) {
		case SIGSEGV:
			break;
		case SIGINT:
			break;
		case SIGFPE:
			switch(siginfo->si_code) {
				case FPE_INTDIV:
					break;
				case FPE_INTOVF:
					break;
				case FPE_FLTDIV:
					break;
				case FPE_FLTOVF:
					break;
				case FPE_FLTUND:
					break;
				case FPE_FLTRES:
					break;
				case FPE_FLTINV:
					break;
				case FPE_FLTSUB:
					break;
				default:
					break;
			}
			break;
		case SIGILL:
			switch(siginfo->si_code) {
				case ILL_ILLOPC:
					break;
				case ILL_ILLOPN:
					break;
				case ILL_ILLADR:
					break;
				case ILL_ILLTRP:
					break;
				case ILL_PRVOPC:
					break;
				case ILL_PRVREG:
					break;
				case ILL_COPROC:
					break;
				case ILL_BADSTK:
					break;
				default:
					break;
			}
			break;
		case SIGTERM:
			break;
		case SIGABRT:
			/*
			 * The signal is usually sent by abort() function.
			 * Return avoids recursion
			 */
			return;
			break;
		default:
			break;
	}
	/*
	 * Frame 0 - ssa_signal_handler
	 * Frame 1 - ssa_print_backtrace
	 */
	ssa_print_backtrace(2, flog);
	/*
	 * abort() will cause a core dump and exit application.
	 * Leave it to the default signal handler to process SIGABRT.
	 */
	signal(SIGABRT, SIG_DFL);
	abort();
}

#if defined(HAVE_ADDR2LINE) || defined(HAVE_GSTACK)
static int run_cmd(const char *cmd, char *buf, int n)
{
	FILE *stream;
	int rt, size = 0;

	stream = popen(cmd, "r");
	if (!stream)
		return 0;

	if (feof(stream))
		goto out;

	size = fread(buf, 1, n, stream);
	if (!size)
		goto out;

out:
	rt = pclose(stream);
	if (rt || !size)
		return 0;
	return size;
}
#endif

#ifdef HAVE_ADDR2LINE
static int run_add2line(const char *appl_name, const void *addr, int frame,
			FILE *flog)
{
	char cmd[1024] = {};
	char out[1024] = {};
	int i = 0, rt;
	char *line = NULL, *name = NULL , *source = NULL;

	if (!flog)
		return 0;

	sprintf(cmd,"%s -s -f -i  -e %.256s %p 2>/dev/null",
		ADDR2LINE_PATH, appl_name, addr);

	rt = run_cmd(cmd, out , 1024);
	if (!rt)
		return 1;

	line = strtok(strdup(out), "\n");
	while (line) {
		if (0 == i)
			name = line;
		else if (1 == i)
			source = line;
		line  = strtok(NULL, "\n");
		i++;
	}

	/*
	 * Skip garbage from addr2line output
	 */
	if (name[0] == '?' && name[1] == '?')
		return 1;

	fprintf(flog, "#%-3d0x%016lx in %s () from %s\n",
		frame, (unsigned long) addr, name, source);

	return 0;
}

static int parse_backtrace_line(const char *bt_line, int frame, FILE *flog)
{
	const char *start_function = NULL;
	const char *start_offset = NULL;
	const char *start_address = NULL;
	const char *p;
	char *module = NULL;
	char *address = NULL;
	char *function = NULL;
	char *offset = NULL;
	int ret;

	for (p = bt_line; *p ; p++) {
		switch (*p) {
		case '(':
			start_function = p + 1;
			break;
		case '[':
			start_address = p + 1;
			break;
		case '+':
			start_offset = p + 1;
			break;
		};
	}

	sscanf(bt_line, "%m[^(]", &module);

	if (start_function)
		sscanf(start_function, "%m[^+)]", &function);
	if (start_offset)
		sscanf(start_offset, "%m[^)]", &offset);
	if (start_address)
		sscanf(start_address, "%m[^]\n]", &address);

	if (module && address) {
		if (!strcmp(program_invocation_short_name, module))
			ret = run_add2line(exe_path, address, frame, flog);
		else
			ret = run_add2line(module, address, frame, flog);
	} else {
		ret = -1;
	}

	free(address);
	free(offset);
	free(function);
	free(module);

	return ret;
}
#else
#define run_add2line(var1, var2, var3, var4) (1)
#define parse_backtrace_line(var1, var2, var3) (1)
#endif


#ifdef HAVE_GSTACK
static int ssa_print_backtrace_with_gstack(FILE *flog)
{
	char cmd[1024] = {};
	char output[1024] = {};
	pid_t pid;
	int rt;

	if (!flog)
		return 0;

	pid = getpid();

	snprintf(cmd, sizeof(cmd) - 1, "%s %d 2>/dev/null", GSTACK_PATH, pid);
	rt = run_cmd(cmd, output, 1024);
	if (rt)
		fprintf(flog,
			"backtrace obtained with gstack for process %d:\n"
			"==== [gstack BACKTRACE] ====\n"
			"%s\n"
			"==== [gstack  BACKTRACE] ====\n\n",
			pid, output);

	return 0;
}
#else
#define ssa_print_backtrace_with_gstack(X) (1)
#endif

static int ssa_print_backtrace(int start_frame, FILE *flog)
{
	int rt, i, backtrace_size = 0;
	char **strings = NULL;
	void *backtrace_buffer[MAX_BACKTRACE_FRAMES];
	char thread_name[20];

	if (!flog)
		return 0;

	get_thread_id(thread_name, sizeof thread_name);

	backtrace_size = backtrace(backtrace_buffer, MAX_BACKTRACE_FRAMES);
	strings = backtrace_symbols(backtrace_buffer, backtrace_size);
	fprintf(flog,
		"backtrace obtained with system backtrace function for process %d thread (%s):\n"
		"==== [BACKTRACE] ====\n", getpid(), thread_name);

	/* start_frame allows skipping non-informative frames such as signal_handler */
	for (i = start_frame; i < (backtrace_size - 2); ++i) {
		if (parse_backtrace_line(strings[i], i, flog))
			fprintf(flog, "#%-3d%s\n", i, strings[i]);
	}
	fprintf(flog, "==== [BACKTRACE] ====\n\n");

	if (strings)
		free(strings);

	rt = ssa_print_backtrace_with_gstack(flog);

	return rt;
}

int ssa_set_ssa_signal_handler()
{
	struct sigaction action;
	int ret;
#if 0
	/*
	 *  addr2line utility doesn't work with alternative stack
	 */
	stack_t our_stack;

	our_stack.ss_sp = (void *) malloc(SIGSTKSZ);
	our_stack.ss_size = SIGSTKSZ;
	our_stack.ss_flags = 0;

	if (sigaltstack(&our_stack, NULL) != 0)
		return 1;
#endif
	ret = pthread_spin_init(&signal_handler_lock, 0);
	if (ret)
		return ret;

	ret = get_exe_path();
	if (ret)
		return ret;

	action.sa_sigaction = ssa_signal_handler;
	sigemptyset(&action.sa_mask);

	action.sa_flags = SA_SIGINFO | SA_ONSTACK;

	if (sigaction(SIGSEGV, &action, NULL) != 0)
		return 1;
	if (sigaction(SIGFPE,  &action, NULL) != 0)
		return 1;
	if (sigaction(SIGILL,  &action, NULL) != 0)
		return 1;

	return 0;
}

#ifdef _SSA_SIGNAL_HANDLER_TESTER_
int foo2()
{
	int *ptr = NULL;
	*ptr = 12;
	return 1;
}

int foo1()
{
	foo2();
	return 1;
}

int foo()
{
	foo1();
	return 1;
}

void *incr(void *ptr)
{
	int *ptr_x = (int *)ptr;

	while (1) {
		(*ptr_x)++;
		if (*ptr_x % 100)
			foo();
	}

	return NULL;
}

int main(int argc, char **argv)
{
	char cmd[1024] = {};
	char output[1024] = {};
	int x = 0, y =0;
	pthread_t inc_x_thread, inc_y_thread;

	ssa_set_ssa_signal_handler();

	printf("You have to delete core dump\n");

	printf("Current call stack:\n");
	ssa_print_backtrace(0, stderr);
	/* create a thread which executes inc_x(&x) */
	if (pthread_create(&inc_x_thread, NULL, incr, &x)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;

	}

	/* create a thread which executes inc_x(&x) */
	if (pthread_create(&inc_y_thread, NULL, incr, &x)) {
		fprintf(stderr, "Error creating thread\n");
		return 1;
	}

	printf("\n");
	printf("Call stack from segmentation handler \n");

	if (pthread_join(inc_x_thread, NULL)) {
		fprintf(stderr, "Error joining thread\n");
		return 2;
	}

	if (pthread_join(inc_y_thread, NULL)) {
		fprintf(stderr, "Error joining thread\n");
		return 2;
	}

	return 0;
}
#elif defined(_SSA_RUN_CMD_TESTER)
int main (int argc, char **argv)
{
	int rt, i, size = 0;
	char *cmd;
	char output[1024] = {};

	if (argc == 1)
		return 0;

	for (i = 1; i < argc; ++i)
		size += (strlen(argv[i]) + 1);

	cmd = (char *) malloc(size + 1);

	for (i = 1; i < argc; ++i) {
		strcat(cmd, argv[i]);
		strcat(cmd, " ");
	}

	printf("Command line : %s\n", cmd);
	rt = run_cmd(cmd, output, 1024);
	if (!rt)
		fprintf(stderr, "Execution failed\n");
	else
		printf("%s\n", output);

	free(cmd);

	return 0;
}
#endif
