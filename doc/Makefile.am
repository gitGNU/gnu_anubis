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
EXTRA_DIST = $(man_MANS) pixie-dixie.pl.txt index.html.in

RENDITION=DISTRIB
MAKEINFOFLAGS=-D$(RENDITION)
info_TEXINFOS = anubis.texi
anubis_TEXINFOS = fdl.texi pixie-dixie.texi rendition.texi
CLEANFILES = tmp-* tmp2-*

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

PROJECT=$(PACKAGE_TARNAME)
BASE_URL="http://www.gnu.org/software/$(PROJECT)/manual/"
TEXI2HTML=${SHELL} `cd $(top_srcdir); pwd`/build/missing --run texi2html
INFO=${SHELL} `cd $(top_srcdir); pwd`/build/missing --run info
DVIPDF=${SHELL} `cd $(top_srcdir); pwd`/build/missing --run dvipdf

clean-local:
	rm -rf $(WEBDOC) $(WEB_HTML_STAMPS)

html: html_mono.stamp html_node.stamp html_chapter.stamp

tmp2-$(PROJECT).texi: Makefile tmp-$(PROJECT).texi
	echo '/@copying/,/@end copying/{H;x;s/@copying//;s/@end copying//;x;}' > tmp2.sed
	echo '/@insertcopying/{x;h;}' >> tmp2.sed
	echo 's/\(.\)@ifset/\1\' >> tmp2.sed
	echo '@ifset/' >> tmp2.sed
	echo 's,/@/,/,g' >> tmp2.sed
	sed -f tmp2.sed tmp-$(PROJECT).texi > tmp2-$(PROJECT).texi
	rm -f tmp2.sed

html_node.stamp: tmp2-$(PROJECT).texi
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_node; then mkdir html_node; fi; \
	cd html_node; \
	$$texi2html -menu -split_node -prefix $(PROJECT) ../tmp2-$(PROJECT).texi; \
	cd ..; \
	touch html_node.stamp

html_chapter.stamp: tmp2-$(PROJECT).texi
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_chapter; then mkdir html_chapter; fi; \
	cd html_chapter; \
	$$texi2html -menu -split_chapter -prefix $(PROJECT) ../tmp2-$(PROJECT).texi; \
	cd ..; \
	touch html_chapter.stamp

html_mono.stamp: tmp2-$(PROJECT).texi
	texi2html="$(TEXI2HTML)";\
	if ! test -d html_mono; then mkdir html_mono; fi; \
	cd html_mono; \
	$$texi2html -menu -monolithic -prefix $(PROJECT) ../tmp2-$(PROJECT).texi; \
	cd ..; \
	touch html_mono.stamp

ps: $(PROJECT).ps

$(PROJECT).ps: $(PROJECT).dvi
	$(DVIPS) -o$(PROJECT).ps $(PROJECT).dvi

# Override the default rule. The texinfo <= 4.5 is unable to cope with
# tar docs.
$(PROJECT).pdf: $(PROJECT).dvi
	$(DVIPDF) $(PROJECT).dvi

text: $(PROJECT).text

$(PROJECT).text: Makefile $(PROJECT).info
	$(INFO) --node=Top --subnodes --out $(PROJECT).text -f ./$(PROJECT).info

$(PROJECT).info.tar.gz: Makefile
	rm -f $(PROJECT).info.tar.gz
	tar cf $(PROJECT).info.tar $(PROJECT).info*
	gzip -f $(PROJECT).info.tar

$(PROJECT).dvi.gz: Makefile $(PROJECT).dvi
	gzip -c $(PROJECT).dvi > $(PROJECT).dvi.gz

$(PROJECT).ps.gz: Makefile $(PROJECT).ps
	gzip -c $(PROJECT).ps > $(PROJECT).ps.gz

$(PROJECT).pdf.gz: Makefile $(PROJECT).pdf
	gzip -c $(PROJECT).pdf > $(PROJECT).pdf.gz

$(PROJECT).texi.tar.gz: Makefile $(info_TEXINFOS) $(tar_TEXINFOS)
	tar cfz $(PROJECT).texi.tar.gz $(info_TEXINFOS) $(tar_TEXINFOS)

WEB_HTML=\
 html_mono\
 html_node\
 html_chapter

WEB_HTML_STAMPS=$(patsubst %,%.stamp,$(WEB_HTML))

WEB_BIN=\
 $(PROJECT).info.tar.gz\
 $(PROJECT).dvi.gz\
 $(PROJECT).pdf.gz\
 $(PROJECT).ps.gz\
 $(PROJECT).texi.tar.gz\
 $(PROJECT).text

WEBDOC=$(WEB_HTML) $(WEB_BIN) 

webdocdir: $(WEB_HTML_STAMPS) $(WEB_BIN) index.html
	if ! test -d $(WEBDOCDIR); then mkdir $(WEBDOCDIR); fi; \
	here=`cd $(srcdir) && pwd`; \
	webdocdir=`cd $(WEBDOCDIR) && pwd`; \
	for file in $(WEB_HTML) index.html; do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$webdocdir/$$file; \
	  else \
	    test -f $$webdocdir/$$file \
	    || ln $$here/$$file $$webdocdir/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$webdocdir/$$file || :; \
	  fi; \
	done; \
	if ! test -d $(WEBDOCDIR)/other; then mkdir $(WEBDOCDIR)/other; fi;\
	for file in $(WEB_BIN); do \
	  if test -d $$here/$$file; then \
	    cp -pr $$here/$$file $$webdocdir/other/$$file; \
	  else \
	    test -f $$webdocdir/other/$$file \
	    || ln $$here/$$file $$webdocdir/other/$$file 2> /dev/null \
	    || cp -p $$here/$$file $$webdocdir/other/$$file || :; \
	  fi; \
	done

index.html: index.html.in $(WEBDOC)
	@echo "s^%BASE_URL%^$(BASE_URL)^;" > .webdoc
	@echo "s/%DATE%/`date`/;" >> .webdoc
	@echo "s/%UPDATED%/`date +'%B %d, %Y'`/;" >> .webdoc
	@echo "s/%PACKAGE_NAME%/$(PACKAGE_NAME)/" >> .webdoc
	@echo "s/%PACKAGE%/$(PACKAGE)/" >> .webdoc
	@echo "s/%VERSION%/$(VERSION)/" >> .webdoc
	@for file in `sed -n 's,.*"other/%PACKAGE%\(.*\)".*,$(PACKAGE)\1,pg;s,.*"\(.*\)%PACKAGE%\(.*\)".*,\1$(PACKAGE)\2,pg' index.html.in`; \
	do\
		ls -sk $$file; \
	done |\
         $(AWK) -vPACKAGE=$(PACKAGE) \
                'BEGIN { len = length(PACKAGE) } \
                 { gsub("\\.", "_", $$2); \
                   if (match($$2,"/")) \
                       $$2=substr($$2,RSTART+1); \
                   print "s/%" toupper(substr($$2,len+2)) "_SIZE%/" $$1 "/;" }' >> .webdoc
	sed -f .webdoc index.html.in > index.html
	rm -f .webdoc

webdocname=$(PACKAGE)-$(VERSION)-doc
WEBDOCDIR=$(webdocname)

webdoc: 
	$(MAKE) RENDITION=PUBLISH WEBDOCDIR=$(top_builddir)/doc/$(webdocname) webdocdir
	cd $(top_builddir)/doc &&\
	tar cfz $(webdocname).tar.gz $(webdocname) &&\
	rm -r $(webdocname)

## End of webdoc
