AC_INIT([ssa], [0.0.9])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_CONFIG_FILES([Makefile])

AC_ARG_ENABLE(build-tests,
	AS_HELP_STRING([--enable-build-tests],
		       [enable build tests [default=disable]]),
	with_build_tests="true", with_build_tests="false")

AC_CONFIG_SUBDIRS([acm admin distrib plugin])
if test "x$with_build_tests" == xtrue; then
	AC_MSG_NOTICE([tests building is enabled])
	AC_CONFIG_SUBDIRS([tests])
fi
AM_CONDITIONAL([TESTS], [test "x$with_build_tests" = xtrue])
AC_OUTPUT
