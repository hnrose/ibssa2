SUBDIRS = plugin

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/ibssa.spec.in \
		 $(srcdir)/include/*.h \
		 $(srcdir)/config

dist-hook: ibssa.spec
	cp ibssa.spec $(distdir)

