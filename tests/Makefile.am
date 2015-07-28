#--
# Copyright (c) 2013-2015 Mellanox Technologies LTD. All rights reserved.
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
# # Makefile.am -- Process this file with automake to produce Makefile.in

SUBDIRS = loadsave pr_pair utils
EXTRA_DIST = include/ssa_log.h include/common.h include/osd.h \
	     include/dlist.h include/ssa_ctrl.h \
	     include/ssa_path_record_data.h include/ssa_path_record_helper.h \
	     include/infiniband/ssa_db.h include/infiniband/ssa.h \
	     include/infiniband/ssa_mad.h include/infiniband/ssa_db_helper.h \
	     include/infiniband/ssa_smdb.h include/infiniband/ssa_prdb.h \
	     include/infiniband/ssa_path_record.h include/infiniband/ssa_smdb_api.h \
	     include/infiniband/osm_headers.h \
	     ssa_tests.spec.in autogen.sh

dist-hook: ssa_tests.spec
	cp ssa_tests.spec $(distdir)
