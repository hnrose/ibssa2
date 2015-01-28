lib_LTLIBRARIES = src/libopensmssa.la

ACLOCAL_AMFLAGS = -I config
AM_CFLAGS = -I$(srcdir)/include -I$(includedir) \
	    -I$(prefix)/include/infiniband \
	    -g -Wall -D_GNU_SOURCE -Wno-deprecated-declarations \
	     $(GLIB_CFLAGS) -DSYSCONFDIR=\"$(sysconfdir)\" \
	    -DRDMADIR=\"@rdmadir@\"

src_libopensmssa_la_CFLAGS = $(AM_CFLAGS) -DACCESS

if HAVE_LD_VERSION_SCRIPT
    libopensmssa_version_script = -Wl,--version-script=$(srcdir)/libopensmssa.map
else
    libopensmssa_version_script =
endif

src_libopensmssa_la_SOURCES = src/core.c src/ssa.c src/ssa_db.c src/ssa_db_helper.c \
			      src/ssa_database.c src/ssa_extract.c src/ssa_smdb.c \
			      src/ssa_comparison.c src/ssa_log.c \
			      src/ssa_path_record.c  src/ssa_path_record_data.c \
			      src/ssa_path_record_helper.c src/ssa_prdb.c \
			      src/ssa_signal_handler.c
src_libopensmssa_la_LDFLAGS = -version-info 1 -export-dynamic \
		$(libopensmssa_version_script)
src_libopensmssa_la_DEPENDENCIES = $(srcdir)/libopensmssa.map
src_libopensmssa_la_LIBADD = -lrdmacm -lpthread -L$(libdir) -losmcomp \
		$(GLIB_LIBS)

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/libopensmssa.map include/osd.h include/dlist.h \
	     include/ssa_log.h include/common.h include/ssa_ctrl.h \
	     include/ssa_path_record_data.h include/ssa_path_record_helper.h \
	     include/infiniband/osm_headers.h include/infiniband/ssa_mad.h \
	     include/infiniband/ssa_extract.h include/infiniband/ssa_comparison.h \
	     include/infiniband/ssa_db_helper.h include/infiniband/ssa_database.h \
	     include/infiniband/ssa_smdb.h include/infiniband/ssa_db.h \
	     include/infiniband/ssa.h include/infiniband/ssa_path_record.h \
	     include/infiniband/ssa_smdb_api.h include/infiniband/ssa_prdb.h \
	     libopensmssa.spec.in ibssa_core_opts.cfg autogen.sh \
	     ssa_release_notes.txt

dist-hook: libopensmssa.spec
	cp libopensmssa.spec $(distdir)
