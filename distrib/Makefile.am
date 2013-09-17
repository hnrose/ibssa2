INCLUDES = -I$(srcdir)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\"

sbin_PROGRAMS = svc/ibssa_distrib
svc_ibssa_distrib_SOURCES = src/distrib.c src/ssa.c
svc_ibssa_distrib_CFLAGS = $(AM_CFLAGS) -L/usr/local/lib 
svc_ibssa_distrib_LDADD = -lrdmacm

ibssa_distribincludedir = $(includedir)/infiniband

EXTRA_DIST = include/osd.h include/dlist.h include/common.h

dist-hook: ibssa_distrib.spec
	cp ibssa_distrib.spec $(distdir)

