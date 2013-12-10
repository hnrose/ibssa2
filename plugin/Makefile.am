INCLUDES = -I$(srcdir)/include -I$(includedir)

lib_LTLIBRARIES = src/libopensmssa.la

ACLOCAL_AMFLAGS = -I config
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -Wno-deprecated-declarations \
		$(GLIB_CFLAGS) -DSYSCONFDIR=\"$(sysconfdir)\" \
		-DRDMADIR=\"@rdmadir@\"

src_libopensmssa_la_CFLAGS = $(AM_CFLAGS) -DACCESS
#src_libopensmssa_la_CFLAGS = $(AM_CFLAGS) -DCORE_INTEGRATION
#src_libopensmssa_la_CFLAGS = $(AM_CFLAGS) -DCORE_INTEGRATION -DACCESS
#src_libopensmssa_la_CFLAGS = $(AM_CFLAGS) -DSSA_PLUGIN_VERBOSE_LOGGING

if HAVE_LD_VERSION_SCRIPT
    libopensmssa_version_script = -Wl,--version-script=$(srcdir)/libopensmssa.map
else
    libopensmssa_version_script =
endif

src_libopensmssa_la_SOURCES = src/core.c src/ssa.c src/ssa_db.c src/ssa_db_helper.c \
			      src/ssa_database.c src/ssa_extract.c src/ssa_smdb.c \
			      src/ssa_comparison.c
src_libopensmssa_la_LDFLAGS = -version-info 1 -export-dynamic \
		$(libopensmssa_version_script)
src_libopensmssa_la_DEPENDENCIES = $(srcdir)/libopensmssa.map \
		$(GLIB_LIBS)
#src_libopensmssa_la_LIBADD = -lrdmacm -L$(libdir) -losmcomp
src_libopensmssa_la_LIBADD = -lrdmacm -L$(libdir) -losmcomp -lssaaccesslayer

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/libopensmssa.map $(srcdir)/src/*.h

dist-hook: libopensmssa.spec
	cp libopensmssa.spec $(distdir)
