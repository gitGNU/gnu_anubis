##
## Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001-2014 The Anubis Team.
##
## GNU Anubis is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 3 of the License, or (at your
## option) any later version.
##
## GNU Anubis is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
##

ACLOCAL_AMFLAGS = -I m4 -I am -I gint
SUBDIRS = build lib gint src po doc scripts examples guile contrib \
	  elisp testsuite

AM_DISTCHECK_CONFIGURE_FLAGS =\
 --with-gsasl\
 --with-mysql\
 --with-postgres\
 --with-pam\
 --with-tcp-wrappers\
 --with-socks-proxy\
 --with-pcre

.PHONY: make-ChangeLog
make-ChangeLog:
	if test -d .git; then                                           \
	  perl $(top_srcdir)/build/gitlog-to-changelog --since=2008-12-16 | \
            sed '/<unknown>$$/d' | fmt -s > $(distdir)/cl-t;            \
	  echo >> $(distdir)/cl-t;                                      \
	  cat ChangeLog-CVS-old >> $(distdir)/cl-t;                     \
	  rm -f $(distdir)/ChangeLog;                                   \
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;                      \
	fi

dist-hook: make-ChangeLog

.PHONY: ChangeLog
ChangeLog:
	if test -d .git && test -f ChangeLog-CVS-old; then              \
	  perl $(top_srcdir)/build/gitlog-to-changelog --since=2008-12-16 | \
            sed '/<unknown>$$/d' | fmt -s > ChangeLog;                  \
	  echo >> ChangeLog;                                            \
	  cat ChangeLog-CVS-old >> ChangeLog;                           \
        fi

## EOF

