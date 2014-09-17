#--
# Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
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


INCLUDES = -I. -I../include


# Support debug mode through config variable
DBG =
if DEBUG
DBG += -DDEBUG
DBG += -g
endif


AM_CFLAGS  = $(DBG) -Wall -Werror -D_GNU_SOURCE


bin_PROGRAMS = loadsave
loadsave_SOURCES = ./ssa_db.c ./ssa_db_helper.c ./loadsave.c ./ssa_log.c
loadsave_LDFLAGS = -lpthread
