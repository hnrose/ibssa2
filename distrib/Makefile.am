INCLUDES = -I$(srcdir)/include -I$(srcdir) -I$(prefix)/include \
	   -I$(prefix)/include/infiniband

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\"

sbin_PROGRAMS = svc/ibssa
svc_ibssa_SOURCES = src/distrib.c src/ssa.c src/ssa_db.c \
		    src/ssa_db_helper.c src/ssa_log.c \
		    src/ssa_path_record.c  src/ssa_path_record_data.c \
		    src/ssa_path_record_helper.c src/ssa_prdb.c \
		    src/ssa_signal_handler.c
#svc_ibssa_CFLAGS = $(AM_CFLAGS) -DACCESS -DINTEGRATION -DACCESS_INTEGRATION
#svc_ibssa_CFLAGS = $(AM_CFLAGS) -DCORE_INTEGRATION
svc_ibssa_CFLAGS = $(AM_CFLAGS) -DACCESS
svc_ibssa_LDADD = -lrdmacm -L$(libdir)

ibssa_includedir = $(includedir)/infiniband

EXTRA_DIST = include/osd.h include/dlist.h \
	     include/ssa_log.h include/common.h include/ref_count.h \
	     ibssa.spec.in ibssa_opts.cfg

install-exec-hook:
	install -D -m 755 ibssa.init $(DESTDIR)$(sysconfdir)/init.d/ibssa;
	install -D -m 644 ibssa_logrotate /etc/logrotate.d/ibssa;

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)

