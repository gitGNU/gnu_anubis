## This file is part of GNU Anubis.
## Copyright (C) 2003 The Anubis Team.
##
## GNU Anubis is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## GNU Anubis is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with GNU Anubis; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##
## GNU Anubis is released under the GPL with the additional exemption that
## compiling, linking, and/or using OpenSSL is allowed.
##

EXTRA_DIST = \
 std.pat\
 add1.pat\
 add2.pat\
 add3.pat\
 add-body.pat\
 del1.pat\
 del2.pat\
 del3.pat\
 del4.pat\
 empty.pat\
 gpgcrypt.pat\
 gpgsign.pat\
 mime1.pat\
 mime2.pat\
 mult.pat\
 remail.pat\
 rot-13.pat\
 std.pat\
 add.in\
 del.in\
 empty.in\
 entire.in\
 gpg.in\
 remail.in\
 std.in\
 simple.in

RCFILES = \
 add.rc\
 del.rc\
 empty.rc\
 entire.rc\
 gpg.rc\
 remail.rc\
 simple.rc\
 std.rc

noinst_DATA = $(RCFILES) 
CLEANFILES = $(RCFILES)
DISTCLEANFILES = *.log

del.rc: del.in
empty.rc: empty.in
entire.rc: entire.in
gpg.rc: gpg.in
simple.rc: simple.in
std.rc: std.in

SUFFIXES=.in .rc

.in.rc:
	m4 -DTOP_SRCDIR=`cd $(top_srcdir); pwd` -DTESTDIR=`cd ..; pwd` $< > $@
