##
## doc/Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001, 2002, 2003, 2004 The Anubis Team.
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
EXTRA_DIST = $(man_MANS) pixie-dixie.pl.txt

RENDITION=DISTRIB
MAKEINFOFLAGS=-D$(RENDITION)
info_TEXINFOS = anubis.texi
anubis_TEXINFOS = fdl.texi pixie-dixie.texi rendition.texi
CLEANFILES = tmp-*

tmp-anubis.texi: $(info_TEXINFOS) $(anubis_TEXINFOS)
	$(MAKEINFO) -D$(RENDITION) -Etmp-anubis.tmp -otmp-anubis.info \
	 -I$(srcdir) anubis.texi
	rm -f tmp-anubis.sed tmp-anubis.info*
	test $(RENDITION) = DISTRIB \
	  || echo >>tmp-anubis.sed 's/^@set DISTRIB/@set $(RENDITION)/'
	test $(RENDITION) = PUBLISH \
	  || echo >>tmp-anubis.sed '/^@smallbook/d'
	sed -f tmp-anubis.sed tmp-anubis.tmp > tmp-anubis.texi
	rm -f tmp-anubis.sed tmp-anubis.tmp

anubis.dvi: tmp-anubis.texi
	TEXINPUTS=$(top_srcdir)/build:$$TEXINPUTS \
	 MAKEINFO='$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -I $(srcdir)' \
	 $(TEXI2DVI) tmp-anubis.texi
	mv tmp-anubis.dvi $@

DVIPDF=${SHELL} `cd $(top_srcdir); pwd`/build/missing --run dvipdf

# Override the default rule. Texinfo is currently unable to cope with
# our docs.
anubis.pdf: anubis.dvi
	$(DVIPDF) anubis.dvi


## EOF

