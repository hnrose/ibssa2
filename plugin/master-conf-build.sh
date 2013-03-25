#!/bin/dash

if [ "$1" = "" ] || [ "$1" = "-h" ]; then
   echo "$0 <dir>"
   echo "   Build plugin against a master management build installed in <dir>"
   echo "   Remove \"Makfile\" to force rebuild" 
   exit 1
fi

if [ ! -f Makefile ]; then
   prefix=$1
   libdir=$prefix/lib
   export LDFLAGS="-L$prefix/lib"
   export CPPFLAGS="-I$prefix/include -I$prefix/include/infiniband"
   ./autogen.sh && ./configure --prefix=$prefix --libdir=$libdir
   rc=$?
   if [ $rc != 0 ]; then
   	exit $rc
   fi
fi

make install
exit $?

