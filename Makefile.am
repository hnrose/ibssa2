#--
# Copyright (c) 2011-2013 Mellanox Technologies LTD. All rights reserved.
# #
# # This software is available to you under the OpenIB.org BSD license below:
# #
# #     Redistribution and use in source and binary forms, with or
# #     without modification, are permitted provided that the following
# #     conditions are met:
# #
# #      - Redistributions of source code must retain the above
# #        copyright notice, this list of conditions and the following
# #        disclaimer.
# #
# #      - Redistributions in binary form must reproduce the above
# #        copyright notice, this list of conditions and the following
# #        disclaimer in the documentation and/or other materials
# #        provided with the distribution.
# #
# # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# # SOFTWARE.
# #
# #
# #--
#
SUBDIRS = . tests 

INCLUDES = -I. -I.. -I$(SSA_SRC)/ -I$(OSM_PATH)/local/include -I$(OSM_PATH)/local/include/infiniband -I$(OSM_DBHELPER_PATH)  


# Support debug mode through config variable
DBG =
if DEBUG
DBG += -DDEBUG
DBG += -g
endif


AM_CPPFLAGS = $(DBG) -Wall -Werror -g 


COV =
if COVERAGE
AM_CPPFLAGS += -fprofile-arcs -ftest-coverage -I config
COV += -lgcov
endif


LDADD = ${COV}	


includedir = @includedir@/infiniband/


lib_LTLIBRARIES = libssaaccesslayer.la


# Quiter for the server
libssaaccesslayer_la_SOURCES = ./src/ssa_path_record_helper.c ./src/ssa_path_record.c \
							   ./src/ssa_path_record_data.c
libssaaccesslayer_la_LDFLAGS = -export-dynamic -lm \
									$(GLIB_LIBS) -lglib-2.0  
libssaaccesslayer_la_CPPFLAGS =  $(INCLUDES) -I$(includedir) $(DEPS_CFLAGS) $(GLIB_CFLAGS) -g 



