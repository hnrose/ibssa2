#!/bin/dash

if [ "$1" = "" ]; then
   echo "$0 <dir>"
   echo "   Build plugin against a master management build installed in <dir>"
   echo "   Remove \"Makfile\" to force rebuild" 
   exit 1
fi

if [ ! -f Makefile ]; then
   prefix=$1
   libdir=$prefix/lib
   ./autogen.sh && ./configure --prefix=$prefix --libdir=$libdir
   rc=$?
   if [ $rc != 0 ]; then
   	exit $rc
   fi
fi

make install
exit $?

