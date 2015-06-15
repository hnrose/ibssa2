ACLOCAL_AMFLAGS = -I config
AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir) -I$(prefix)/include \
	      -I$(prefix)/include/infiniband
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\" \
	     $(GLIB_CFLAGS)

sbin_PROGRAMS = svc/ssadmin
svc_ssadmin_SOURCES = src/admin.c src/libadmin.c src/common.c
svc_ssadmin_CFLAGS = $(AM_CFLAGS)
svc_ssadmin_LDADD = -lrdmacm -lpthread -L$(libdir) $(GLIB_LIBS)

ssadmin_includedir = $(includedir)/infiniband

man_MANS = \
	man/ssadmin.1

EXTRA_DIST = \
	     ssadmin.spec.in $(man_MANS) autogen.sh \
	     ssa_release_notes.txt

dist-hook: ssadmin.spec
	cp ssadmin.spec $(distdir)

