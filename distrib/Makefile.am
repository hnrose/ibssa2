INCLUDES = -I$(srcdir)/include -I$(ACCESS_SRC)/include \
	   -I$(ACCESS_SRC)/include/infiniband

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\"

sbin_PROGRAMS = svc/ibssa
svc_ibssa_SOURCES = src/distrib.c src/ssa.c src/ssa_db.c src/ssa_db_helper.c
svc_ibssa_CFLAGS = $(AM_CFLAGS) -DINTEGRATION -DACCESS_INTEGRATION
svc_ibssa_LDADD = -lrdmacm -L$(ACCESS_SRC)/.libs -lssaaccesslayer

ibssa_includedir = $(includedir)/infiniband

EXTRA_DIST = include/osd.h include/dlist.h include/common.h

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)

