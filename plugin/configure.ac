dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.63)
AC_INIT([libopensmssa], [0.0.9], linux-rdma@vger.kernel.org)
AC_CONFIG_SRCDIR([src/core.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

dnl Checks for programs
AC_PROG_CC
AC_PROG_LIBTOOL

AC_ARG_WITH([valgrind],
    AC_HELP_STRING([--with-valgrind],
                   [Enable valgrind annotations - default NO]))

if test "$with_valgrind" != "" && test "$with_valgrind" != "no"; then
        AC_DEFINE([INCLUDE_VALGRIND], 1,
                  [Define to 1 to enable valgrind annotations])
        if test -d $with_valgrind; then
                CPPFLAGS="$CPPLFAGS -I$with_valgrind/include"
        fi
fi

AC_ARG_ENABLE(libcheck, [  --disable-libcheck      do not test for presence of ib libraries],
[       if test "$enableval" = "no"; then
                disable_libcheck=yes
        fi
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_CHECK_SIZEOF(long)

dnl Define input options for running mode
AC_ARG_ENABLE(simulator,
	AS_HELP_STRING([--enable-simulator],
		       [enable running on simulated fabric [default=disable]]),
	with_sim="true", with_sim="false")

if test "x$with_sim" == xtrue; then
	AC_DEFINE([SIM_SUPPORT], [], ["running in simulator mode"])
	AC_MSG_NOTICE([simulator mode is enabled])
else
	AC_MSG_NOTICE([simulator mode is disabled by default])
fi

AC_ARG_ENABLE(simulated_smdb,
	AS_HELP_STRING([--enable-simulated-smdb],
		       [enable using simulated smdb [default=disable]]),
	with_simulated_smdb="true", with_simulated_smdb="false")

if test "x$with_simulated_smdb" == xtrue; then
	AC_DEFINE([SIM_SUPPORT_SMDB], [], ["using simulated smdb"])
	AC_MSG_NOTICE([simulated smdb mode is enabled])
else
	AC_MSG_NOTICE([simulated smdb mode is disabled by default])
fi

AC_ARG_ENABLE(fake-acm,
	AS_HELP_STRING([--enable-fake-acm],
		       [enable using fake ACM clients [default=disable]]),
	with_fake_acm="true", with_fake_acm="false")

if test "x$with_fake_acm" == xtrue; then
	AC_DEFINE([SIM_SUPPORT_FAKE_ACM], [], ["using fake ACM clients in access"])
	AC_MSG_NOTICE([fake ACM mode is enabled])
else
	AC_MSG_NOTICE([fake ACM mode is disabled by default])
fi

AC_ARG_ENABLE(verbose_logging,
	AS_HELP_STRING([--enable-verbose-logging],
		       [enable verbose logging mode [default=disable]]),
	with_verbose_logging="true", with_verbose_logging="false")

if test "x$with_verbose_logging" == xtrue; then
	AC_DEFINE([SSA_PLUGIN_VERBOSE_LOGGING], [], ["using verbose logging"])
	AC_MSG_NOTICE([verbose logging mode is enabled])
else
	AC_MSG_NOTICE([verbose logging mode is disabled by default])
fi

dnl check pkg-config
AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])
AS_IF([test "x$PKG_CONFIG" = "xno"],[
   AC_MSG_WARN([
   *** The pkg-config script could not be found. Make sure it is
   *** in your path, or set the PKG_CONFIG environment variable
   *** to the full path to pkg-config.])
])

dnl Check for libraries
if test "$disable_libcheck" != "yes"; then
AC_CHECK_LIB(ibverbs, ibv_get_device_list, [],
    AC_MSG_ERROR([ibv_get_device_list() not found.  libopensmssa requires libibverbs.]))
AC_CHECK_LIB(rdmacm, rselect, [],
    AC_MSG_ERROR([rselect() not found.  libopensmssa requires librdmacm.]))
AC_CHECK_LIB(ibumad, umad_register, [],
    AC_MSG_ERROR([umad_register() not found.  libibumad is required.]))
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.2])
AC_CHECK_LIB(gthread-2.0, g_thread_init, [],
    AC_MSG_ERROR([g_thread_init() not found.  libgthread-2.0 is required.]))
fi

dnl Check for gcc atomic intrinsics
AC_MSG_CHECKING(compiler support for atomics)
AC_TRY_LINK([int i = 0;],
    [ return __sync_add_and_fetch(&i, 1) != __sync_sub_and_fetch(&i, 1); ],
    [ AC_MSG_RESULT(yes) ],
    [
        AC_MSG_RESULT(no)
        AC_DEFINE(DEFINE_ATOMICS, 1, [Set to 1 to implement atomics])
    ])

dnl Check for pthread_setname_np function
AC_CHECK_FUNC(pthread_setname_np,
    AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP, [1], [Define if using pthread_setname_np]))

dnl Checks for header files.
AC_HEADER_STDC
dnl OpenSM headers are in $includedir/infiniband
OSM_INC="`eval echo ${includedir}/infiniband`"
OSM_INC="`echo $OSM_INC | sed 's/^NONE/$ac_default_prefix/'`"
CFLAGS="$CFLAGS -I`eval echo $OSM_INC`"
CPPFLAGS="$CPPFLAGS -I`eval echo $OSM_INC`"

if test "$disable_libcheck" != "yes"; then
AC_CHECK_HEADER(opensm/osm_event_plugin.h, [], 
	AC_MSG_ERROR([opensm/osm_event_plugin.h not found.  opensm event plugin support required.]))

AC_CHECK_HEADER(rdma/rsocket.h, [],
	AC_MSG_ERROR([<rdma/rsocket.h> not found.  Is librdmacm installed?]))

AC_CHECK_MEMBER(struct umad_hdr.base_version, [],
    AC_MSG_ERROR([struct umad_hdr not found.  A newer version of libibumad is required.]),
    [#include <infiniband/umad_types.h>])

if test "$with_valgrind" != "" && test "$with_valgrind" != "no"; then
AC_CHECK_HEADER(valgrind/memcheck.h, [],
    AC_MSG_ERROR([valgrind requested but <valgrind/memcheck.h> not found.]))
fi
fi

dnl Define package version
commit="`git log -n 1 --pretty=format:"%h" 2> /dev/null`"
if test "$commit" == "" ; then
	ver="${PACKAGE_VERSION}"
else
	ver="${PACKAGE_VERSION}_${commit}"
	git diff-index --quiet HEAD -- ../ > /dev/null 2>&1
	if test "$?" == "1" ; then
		ver="${ver}_dirty"
	fi
fi
AC_DEFINE_UNQUOTED([IB_SSA_VERSION], ["$ver"], [ibssa package version])

dnl We use --version-script with ld if possible
AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")

AC_ARG_VAR(ibdir, [Directory for configuration files])
if test "x$rdmadir" = "x"; then
    AC_SUBST(rdmadir, rdma)
fi

AC_PATH_PROGS([ADDR2LINE], [addr2line])
if test "x${ADDR2LINE}" = x
then
	echo "WARN: addr2line missing!"
else
AC_DEFINE_UNQUOTED(ADDR2LINE_PATH, ["$ADDR2LINE"], [Path to addr2line])
AC_DEFINE(HAVE_ADDR2LINE, [1], [Define if using addr2line])
fi

AC_PATH_PROGS([GSTACK], [gstack])
if test "x${GSTACK}" = x
then
	AC_PATH_PROGS([GSTACK], [pstack])
fi
if test "x${GSTACK}" = x
then
	echo "WARN: gstack missing!"
else
AC_DEFINE_UNQUOTED(GSTACK_PATH, ["$GSTACK"], [Path to gstack])
AC_DEFINE(HAVE_GSTACK, [1], [Define if using gstack])
fi

AC_CONFIG_FILES([Makefile libopensmssa.spec])
AC_OUTPUT
