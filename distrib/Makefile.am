INCLUDES = -I$(srcdir)/include -I$(srcdir) -I$(prefix)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\"

sbin_PROGRAMS = svc/ibssa
svc_ibssa_SOURCES = src/distrib.c src/ssa.c src/ssa_db.c \
		    src/ssa_db_helper.c src/ssa_log.c
#svc_ibssa_CFLAGS = $(AM_CFLAGS) -DACCESS -DINTEGRATION -DACCESS_INTEGRATION
#svc_ibssa_CFLAGS = $(AM_CFLAGS) -DCORE_INTEGRATION
svc_ibssa_CFLAGS = $(AM_CFLAGS) -DACCESS
svc_ibssa_LDADD = -lrdmacm -L$(libdir) -lssaaccesslayer

ibssa_includedir = $(includedir)/infiniband

EXTRA_DIST = include/osd.h include/dlist.h \
	     include/ssa_log.h include/common.h

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)

