
INCLUDES = -I$(srcdir)/../include

sbin_PROGRAMS = src/ibssautil

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS = -g
endif

src_ibssautil_SOURCES = src/ibssaclient.c \
				src/ibssautil.c
src_ibssautil_CFLAGS = -Wall $(DBGFLAGS) -D_XOPEN_SOURCE=600 -D_BSD_SOURCE=1 -Wno-deprecated-declarations $(GLIB_CFLAGS)
src_ibssautil_LDFLAGS = -L$(libdir) -libumad $(GLIB_LIBS)

# headers are distributed as part of the include dir
EXTRA_DIST = $(srcdir)/src/*.h

