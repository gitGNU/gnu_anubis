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
 add1.pat\
 add2.pat\
 add3.pat\
 add-body.pat\
 add-body-file.pat\
 del1.pat\
 del2.pat\
 del3.pat\
 del4.pat\
 empty.pat\
 gpgcrypt.pat\
 gpgsign.pat\
 mime1.pat\
 mime2.pat\
 mod-body.pat\
 mod-header.pat\
 mult.pat\
 remail.pat\
 rot-13.pat\
 std.pin\
 tlsoneway.pat\
 trigger.pat\
 add.in\
 del.in\
 empty.in\
 entire.in\
 gpg.in\
 mod-body.in\
 mod-header.in\
 remail.in\
 std.in\
 simple.in\
 tlsoneway.in\
 trigger.in

RCFILES = \
 add.rc\
 del.rc\
 empty.rc\
 entire.rc\
 gpg.rc\
 mod-body.rc\
 mod-header.rc\
 remail.rc\
 simple.rc\
 std.rc\
 tlsoneway.rc\
 trigger.rc

noinst_DATA = $(RCFILES) std.pat
CLEANFILES = $(RCFILES) std.pat
DISTCLEANFILES = *.log

del.rc: del.in
empty.rc: empty.in
entire.rc: entire.in
gpg.rc: gpg.in
mod-body.rc: mod-body.in
mod-header.rc: mod-header.in
simple.rc: simple.in
std.rc: std.in
trigger.rc: trigger.in

std.pat: std.pin

SUFFIXES=.in .rc .pin .pat

.in.rc:
	m4 -DTOP_SRCDIR=`cd $(top_srcdir); pwd` \
           -DTESTDIR=`cd ..; pwd` @M4_DEFS@ $< > $@

.pin.pat:
	m4 -DTOP_SRCDIR=`cd $(top_srcdir); pwd` \
           -DTESTDIR=`cd ..; pwd` \
           @M4_DEFS@ $< > $@
