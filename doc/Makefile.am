##
## doc/Makefile.am
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
	$(GENDOCS) --texi2html $(PACKAGE) '$(PACKAGE_NAME) manual'

# Checking
check-format:
	@if test -n "`cat $(info_TEXINFOS) $(anubis_TEXINFOS) | tr -d -c '\t'`"; then \
		echo "Sources contain tabs; run make untabify"; \
		false; \
	fi

check-refs:
	@for file in $(info_TEXINFOS) $(anubis_TEXINFOS); \
	do \
	  sed -e = $$file | \
           sed -n 'N;/@FIXME-.*ref/{s/\(^[0-9][0-9]*\).*@FIXME-.*ref{\([^}]*\)}.*/'$$file':\1: \2/gp}'; \
	done > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unresolved cross-references:"; \
	  cat $@-t;\
	  rm $@-t; \
	else \
	  rm -f $@-t; \
	fi

check-fixmes:
	@for file in $(info_TEXINFOS) $(anubis_TEXINFOS); \
	do \
	  sed -e = $$file | \
           sed -n 'N;/@FIXME{/{s/\(^[0-9][0-9]*\).*@FIXME{\([^}]*\).*/'$$file':\1: \2/gp}'; \
	done > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unresolved FIXMEs:"; \
	  cat $@-t; \
	  rm $@-t; \
	  false; \
	else \
          rm -f $@-t; \
	fi

check-writeme:
	@grep -Hn @WRITEME $(info_TEXINFOS) $(anubis_TEXINFOS) > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Empty nodes:"; \
	  cat $@-t; \
	  rm $@-t; \
	  false;\
	else \
          rm $@-t; \
	fi

check-unrevised:
	@grep -Hn @UNREVISED $(info_TEXINFOS) $(anubis_TEXINFOS) > $@-t; \
	if [ -s $@-t ]; then \
	  echo "Unrevised nodes:"; \
	  cat $@-t; \
	  rm $@-t; \
	  false;\
	else \
          rm $@-t; \
	fi

all-check-docs: check-format check-refs check-fixmes check-writeme \
                check-unrevised

check-docs: 
	@$(MAKE) -k all-check-docs

master-menu:
	@emacs -batch -l mastermenu.el -f make-master-menu $(info_TEXINFOS)

untabify:
	@emacs -batch -l untabify.el $(info_TEXINFOS) $(anubis_TEXINFOS)

final: untabify master-menu
