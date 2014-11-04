INCLUDES = -I$(srcdir)/include -I$(includedir) \
	   -I$(prefix)/include/infiniband

lib_LTLIBRARIES = src/libopensmssa.la

ACLOCAL_AMFLAGS = -I config
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -Wno-deprecated-declarations \
		$(GLIB_CFLAGS) -DSYSCONFDIR=\"$(sysconfdir)\" \
		-DRDMADIR=\"@rdmadir@\" \
		$(GLIB_CFLAGS)

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
src_libopensmssa_la_LIBADD = -lrdmacm -L$(libdir) -losmcomp \
		$(GLIB_LIBS)

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/libopensmssa.map $(srcdir)/src/*.h \
	     include/osd.h include/dlist.h \
	     include/ssa_log.h include/common.h include/ref_count.h \
	     libopensmssa.spec.in ibssa_core_opts.cfg

dist-hook: libopensmssa.spec
	cp libopensmssa.spec $(distdir)
