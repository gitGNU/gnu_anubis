#!/bin/sh
#
# This file is part of GNU Anubis.
# Copyright (C) 2001-2014 The Anubis Team.
#
# GNU Anubis is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option)
# any later version.
#
# GNU Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
#

cat <<EOF
Summary: An SMTP message submission daemon.
Name: anubis
Version: $1
Release: 1%{?dist}
License: GPLv3+
URL: http://www.gnu.org/software/anubis/
Source: ftp://ftp.gnu.org/gnu/anubis/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Group: System Environment/Daemons
Requires: gnutls >= 1.0.18
Requires: libgsasl >= 0.2.3
Requires: gpgme >= 1.0.0
Requires: guile >= 1.6
Requires: gdbm
Requires: pcre
Requires: mysql-libs
BuildRequires: gettext
BuildRequires: gnutls-devel >= 1.0.18
BuildRequires: libgsasl-devel >= 0.2.3
BuildRequires: gpgme-devel >= 1.0.0
BuildRequires: guile-devel >= 1.6
BuildRequires: gdbm-devel
BuildRequires: pcre-devel
BuildRequires: mysql-devel
BuildRequires: emacs

Prereq: /sbin/chkconfig /usr/sbin/useradd /usr/sbin/userdel

%description
GNU Anubis is an SMTP message submission daemon. It represents an
intermediate layer between mail user agent (MUA) and mail transport
agent (MTA), receiving messages from the MUA, applying to them a set
of predefined changes and finally inserting modified messages into an
MTA routing network. The set of changes applied to a message is
configurable on a system-wide and per-user basis. The built-in
configuration language used for defining sets of changes allows for
considerable flexibility and is easily extensible.

%define _initdir /etc/init.d
%define _unprivileged anubis.unprivileged

%prep
%setup -q

%build
CFLAGS="\$RPM_OPT_FLAGS" ./configure --prefix=%{_prefix} \\
			 --with-mysql --with-pcre
make

%check
make check

%install
rm -rf \$RPM_BUILD_ROOT
mkdir -p \$RPM_BUILD_ROOT
mkdir -p \$RPM_BUILD_ROOT%{_initdir}
make DESTDIR=\$RPM_BUILD_ROOT install
install -m 0755 ./scripts/redhat.init \$RPM_BUILD_ROOT%{_initdir}/anubis
%find_lang %{name}

%clean
rm -rf \$RPM_BUILD_ROOT

%pre
rm -f %{_infodir}/anubis.info*
rm -f %{_mandir}/man1/anubis.1*
/usr/sbin/useradd -s /dev/null %{_unprivileged} >/dev/null 2>&1 || :

%post
/sbin/install-info %{_infodir}/anubis.info.gz %{_infodir}/dir

%preun
%{_initdir}/anubis stop >/dev/null 2>&1
/sbin/chkconfig --del anubis >/dev/null 2>&1
/sbin/install-info --delete %{_infodir}/anubis.info.gz %{_infodir}/dir

%postun
/usr/sbin/userdel -r %{_unprivileged} >/dev/null 2>&1 || :

%files -f %{name}.lang
%defattr(-,root,root,-)
%doc COPYING AUTHORS THANKS README INSTALL NEWS ChangeLog TODO
%{_bindir}/anubisusr
%{_bindir}/msg2smtp.pl
%{_sbindir}/anubis
%{_sbindir}/anubisadm
%{_mandir}/man1/anubis.1*
%{_infodir}/*
%{_datadir}/anubis/*
%{_datadir}/emacs/site-lisp/anubis*
%attr(0755,root,root) %config %{_initdir}/anubis

%changelog
* Tue Feb 23 2009  Wojciech Polak
- Major update.

* Tue Dec 03 2002  Wojciech Polak
- removed default system configuration file.

* Fri Nov 01 2002  Wojciech Polak
- updated to GNU. Now it's GNU Anubis!

# EOF

