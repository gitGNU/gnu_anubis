##
## doc/Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001, 2002, 2003, 2004, 2005 The Anubis Team.
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

man_MANS = anubis.1
EXTRA_DIST = $(man_MANS) pixie-dixie.pl.txt gendocs_template 

RENDITION=DISTRIB
MAKEINFOFLAGS=-D$(RENDITION)
info_TEXINFOS = anubis.texi
anubis_TEXINFOS = fdl.texi mime.texi pixie-dixie.texi rendition.texi

clean-local:
	rm -rf manual

GENDOCS=gendocs.sh

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -E

# Make sure you set TEXINPUTS
# Usual value is:
# /usr/share/texmf/pdftex/plain/misc:/usr/share/texmf/pdftex/config
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t @finalout" \
	$(GENDOCS) $(PACKAGE) '$(PACKAGE_NAME) manual'
