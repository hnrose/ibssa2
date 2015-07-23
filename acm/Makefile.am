AM_CPPFLAGS = -I$(srcdir)/include -I$(includedir)
AM_CFLAGS = -g -Wall -DACM -D_GNU_SOURCE -DSYSCONFDIR=\"$(sysconfdir)\" \
	    -DBINDIR=\"$(bindir)\" -DRDMADIR=\"@rdmadir@\" $(GLIB_CFLAGS)

bin_PROGRAMS = util/ib_acme
sbin_PROGRAMS = svc/ibacm
svc_ibacm_SOURCES = src/acm.c src/ssa.c src/ssa_db.c src/ssa_db_helper.c \
		    src/ssa_log.c src/ssa_signal_handler.c \
		    src/ssa_runtime_counters.c \
		    src/common.c src/acm_util.c src/acm_neigh.c
util_ib_acme_SOURCES = src/acme.c src/libacm.c src/parse.c
svc_ibacm_CFLAGS = $(AM_CFLAGS)
util_ib_acme_CFLAGS = $(AM_CFLAGS)
svc_ibacm_LDADD = -lrdmacm -lpthread -L$(libdir) $(GLIB_LIBS)

ibacmincludedir = $(includedir)/infiniband

ibacminclude_HEADERS = include/infiniband/acm.h

man_MANS = \
	man/ib_acme.1 \
	man/ibacm.1 \
	man/ibacm.7

EXTRA_DIST = src/acm_util.h src/acm_mad.h src/libacm.h ibacm.init.in \
	     include/osd.h include/dlist.h \
	     include/ssa_log.h include/common.h include/acm_shared.h \
	     include/ssa_ctrl.h include/acm_neigh.h include/infiniband/ssa.h \
	     include/infiniband/ssa_mad.h include/infiniband/ssa_db.h \
	     include/infiniband/ssa_db_helper.h include/infiniband/ssa_prdb.h \
	     include/infiniband/ssa_path_record.h include/infiniband/ssa_ipdb.h \
	     ibacm.spec.in $(man_MANS) ibacm_opts.cfg ibacm_addr.data \
	     ibacm_hosts.data ibacm_logrotate \
	     autogen.sh ssa_release_notes.txt

install-exec-hook:
	install -D -m 755 ibacm.init $(DESTDIR)$(sysconfdir)/init.d/ibacm;

dist-hook: ibacm.spec
	cp ibacm.spec $(distdir)
