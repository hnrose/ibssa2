#--
# Copyright (c) 2004-2010 Mellanox Technologies LTD. All rights reserved.
#
# This software is available to you under the terms of the
# OpenIB.org BSD license included below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#--

# Makefile.am -- Process this file with automake to produce Makefile.in


SUBDIRS = .

INCLUDE_DIRS = -I../include -I../include/infiniband \
	       -I$(prefix)/include/ \
	       -I$(prefix)/include/infiniband

# Support debug mode through config variable
DBG =
if DEBUG
DBG += -DDEBUG
DBG += -g
endif

AM_CPPFLAGS = $(INCLUDE_DIRS) $(DBG) -Wall -Werror -g

COV =
if COVERAGE
AM_CPPFLAGS += -fprofile-arcs -ftest-coverage -I config
COV += -lgcov
endif


LDADD = ${COV}


includedir = @includedir@/infiniband/


bin_PROGRAMS = pr_pair



# Quiter for the server
pr_pair_SOURCES = ./pr_pair.c \
		  ./ssa_path_record.c  ./ssa_path_record_data.c \
		  ./ssa_path_record_helper.c ./ssa_db.c ./ssa_prdb.c \
		  ./ssa_smdb.c ./ssa_db_helper.c ./ssa_log.c \
		  ./ssa_signal_handler.c
pr_pair_CPPFLAGS =  $(INCLUDE_DIRS) -I$(includedir)  $(DEPS_CFLAGS)  -g -D_GNU_SOURCE
pr_pair_LDFLAGS = -lpthread

#pr_pair_LDADD =  $(GLIB_LIBS)
