#--
# Copyright (c) 2015 Mellanox Technologies LTD. All rights reserved.
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

# Support debug mode through config variable
DBG =
if DEBUG
DBG += -DDEBUG
DBG += -g
endif


AM_CFLAGS  = -I. -I../include $(DBG) -Wall -Werror -D_GNU_SOURCE


bin_PROGRAMS = hosts2prdb
hosts2prdb_SOURCES = ./ssa_db.c ./ssa_db_helper.c ./hosts2prdb.c \
		     ./ssa_log.c ./ssa_signal_handler.c ./ssa_prdb.c \
		     ./ssa_runtime_counters.c ./common.c
hosts2prdb_LDFLAGS = -lpthread
