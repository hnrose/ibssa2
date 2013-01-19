SUBDIRS = plugin ibssautil

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/ibssa.spec.in \
		 $(srcdir)/include/*.h \
		 $(srcdir)/config

install-exec-hook:
	$(top_srcdir)/config/install-sh -m 755 -d $(DESTDIR)/$(sysconfdir)/ibssa
	$(top_srcdir)/config/install-sh -c -m 444 $(top_srcdir)/plugin/etc/opensmssa.conf $(DESTDIR)/$(sysconfdir)/ibssa
	$(top_srcdir)/config/install-sh -m 755 -d $(DESTDIR)/$(localstatedir)/log

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)
