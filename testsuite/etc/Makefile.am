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
 empty.pat\
 modify.pat\
 mult.pat\
 std.pat\
 empty.in\
 std.in\
 simple.in

noinst_DATA = empty.rc std.rc simple.rc
CLEANFILES = empty.rc std.rc simple.rc
DISTCLEANFILES = *.log

empty.rc: empty.in
std.rc: std.in
simple.rc: simple.in

SUFFIXES=.in .rc

.in.rc:
	m4 -DTESTDIR=`cd ..; pwd` $< > $@
