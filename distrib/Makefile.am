INCLUDES = -I$(srcdir)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\"

sbin_PROGRAMS = svc/ibssa
svc_ibssa_SOURCES = src/distrib.c src/ssa.c
svc_ibssa_CFLAGS = $(AM_CFLAGS) -L/usr/local/lib 
svc_ibssa_LDADD = -lrdmacm

ibssa_includedir = $(includedir)/infiniband

EXTRA_DIST = include/osd.h include/dlist.h include/common.h

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)

