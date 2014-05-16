##
## This file is part of GNU Anubis.
## Copyright (C) 2003-2014 The Anubis Team.
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

EXTRA_DIST = \
 add1.pat\
 add2.pat\
 add3.pat\
 add-body.pat\
 add-body-file.pat\
 cond.pat\
 del1.pat\
 del2.pat\
 del3.pat\
 del4.pat\
 empty.pat\
 gpgcrypt.pat\
 gpgsign.pat\
 gpgse.pat\
 interface.in.in\
 mime1.pat\
 mime2.pat\
 mod-body.pat\
 mod-header.pat\
 mult.pat\
 net.rc\
 no-backref.pat\
 paolo.in\
 paolo.pat\
 remail.pat\
 rot-13.pat\
 std.pin\
 target.in.in\
 tlsoneway.pat\
 trigger.pat\
 add.in\
 cond.in\
 del.in\
 empty.in\
 entire.in\
 gpg.in\
 mod-body.in\
 mod-header.in\
 no-backref.in\
 remail.in\
 std.in\
 simple.in\
 tlsoneway.in\
 trigger.in

RCFILES = \
 add.rc\
 cond.rc\
 del.rc\
 empty.rc\
 entire.rc\
 gpg.rc\
 interface.in.rc\
 mod-body.rc\
 mod-header.rc\
 no-backref.rc\
 paolo.rc\
 remail.rc\
 simple.rc\
 std.rc\
 target.in.rc\
 tlsoneway.rc\
 trigger.rc

noinst_DATA = $(RCFILES) std.pat
CLEANFILES = $(RCFILES) std.pat
DISTCLEANFILES = *.log target.rc interface.rc anubis.pid anubis.trace *.tmp anubis.out user.rc

$(RCFILES) std.pat: Makefile
cond.rc: cond.in
del.rc: del.in
empty.rc: empty.in
entire.rc: entire.in
interface.in.rc: interface.in.in
gpg.rc: gpg.in
mod-body.rc: mod-body.in
mod-header.rc: mod-header.in
simple.rc: simple.in
std.rc: std.in
target.in.rc: target.in.in 
trigger.rc: trigger.in 
paolo.rc: paolo.in
std.pat: std.pin

SUFFIXES=.in .rc .pin .pat

.in.rc:
	$(AM_V_GEN) m4 -DTOP_SRCDIR=`cd $(top_srcdir); pwd` \
           -DTESTDIR=`cd ..; pwd` @M4_DEFS@ $< > $@

.pin.pat:
	$(AM_V_GEN) m4 -DTOP_SRCDIR=`cd $(top_srcdir); pwd` \
           -DTESTDIR=`cd ..; pwd` \
           @M4_DEFS@ $< > $@
