#--
# Copyright (c) 2013-2014 Mellanox Technologies LTD. All rights reserved.
#
# This software is available to you under the OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#--

dnl Process this file with autoconf to produce a configure script.

AC_INIT([ssa_tests],[1.0])
AC_CONFIG_SRCDIR([])
AC_CONFIG_MACRO_DIR(config)

dnl use local config dir for extras
AC_CONFIG_AUX_DIR(config)

dnl Defines the Language - we need gcc linker ...
#AC_LANG_CPLUSPLUS
AC_LANG_C

dnl we use auto cheader
AM_CONFIG_HEADER(config.h)

dnl Auto make
AM_INIT_AUTOMAKE

dnl Provides control over re-making of all auto files
dnl We also use it to define swig dependencies so end
dnl users do not see them.
AM_MAINTAINER_MODE

dnl Required for cases make defines a MAKE=make ??? Why
AC_PROG_MAKE_SET

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CC
AC_PROG_CXX

dnl We will use libtool for making ...
AC_PROG_LIBTOOL

dnl For making dist we need not check any lib dependency
dnl
dnl AC_ARG_ENABLE(libcheck,
dnl [  --enable-libcheck    Enable Dependency Checking],
dnl [case "${enableval}" in
dnl   yes) libcheck=true ;;
dnl   no)  libcheck=false ;;
dnl   *) AC_MSG_ERROR(bad value ${enableval} for --enable-libcheck) ;; esac],[libcheck=true])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h inttypes.h limits.h stdint.h stdlib.h string.h sys/time.h syslog.h unistd.h])
dnl Define an input config option to control debug compile
AC_ARG_ENABLE(debug,
			  [  --enable-debug    Turn on debugging],
			  [case "${enableval}" in
			     yes) debug=true ;;
				   no)  debug=false ;;
				     *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
				 esac],[debug=false])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)


dnl Define an input config option to control code coverage compile
AC_ARG_ENABLE(coverage,
			  [  --enable-coverage    Compile with gcov flags to enable code coverage collection],
			  [case "${enableval}" in
			     yes) coverage=true ;;
				   no)  coverage=false ;;
				     *) AC_MSG_ERROR(bad value ${enableval} for --enable-coverage) ;;
				 esac],[coverage=false])
AM_CONDITIONAL(COVERAGE, test x$coverage = xtrue)

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

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday localtime_r memset mkdir strcasecmp])

dnl Check for pthread_setname_np function
AC_CHECK_FUNC(pthread_setname_np,
    AC_DEFINE(HAVE_PTHREAD_SET_NAME_NP, [1], [Define if using pthread_setname_np]))

AC_CONFIG_FILES([ssa_tests.spec])

dnl Create the following Makefiles
AC_OUTPUT(Makefile loadsave/Makefile pr_pair/Makefile)
