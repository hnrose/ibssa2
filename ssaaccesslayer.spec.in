#--
# Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
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

%define _enable_debug --enable-debug

Summary: SSA Acess Layer
Name: ssaaccesslayer
Version: 1.0
Release: 1
License: GPLv2 or BSD
#Url:
Group: System Environment/Libraries
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-build
#Requires: ssa plugin
Vendor: OpenFabrics

%description
SSA Access Layer

%prep
%setup -n %{name}-%{version}

%build
%{configure} %{configure_options}


#export CFLAGS="$RPM_OPT_FLAGS"
%{__make}


%install
%{__make} install DESTDIR=$RPM_BUILD_ROOT
rm -f ${RPM_BUILD_ROOT}/%{_libdir}/libssaaccesslayer.a
rm -f ${RPM_BUILD_ROOT}/%{_libdir}/libssaaccesslayer.la


%clean
rm -rf ${RPM_BUILD_ROOT}
rm -rf ${RPM_BUILD_DIR}/%{name}-%{version}


%files
%defattr(-,root,root)
#%doc COPYING
%{_libdir}/libssaaccesslayer.so*
# END Files


%changelog
* Initial package
