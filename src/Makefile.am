##
## src/Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001, 2002, 2003 The Anubis Team.
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

sbin_PROGRAMS = anubis
anubis_LDADD = @LIBOBJS@ @LIBINTL@ $(GUILE_LIBS)
anubis_SOURCES = main.c extern.h headers.h mem.c mem.h env.c errs.c \
	log.c list.c list.h misc.c regex.c exec.c net.c proxy.c daemon.c \
	auth.c map.c message.c esmtp.c tunnel.c rc.c rcfile-gram.c \
	rcfile-lex.c rcfile-gram.h rcfile.h guile.c files.c help.c quit.c

YLWRAP = $(SHELL) $(top_srcdir)/build/ylwrap
AM_YFLAGS = -dtv
EXTRA_DIST = rcfile.y rcfile.l snprintf.c obstack.c obstack.h \
	getopt.h gettext.h

BUILT_SOURCES= \
  rcfile-gram.c rcfile-gram.h \
  rcfile-lex.c

rcfile-lex.c: $(srcdir)/rcfile.l rcfile-gram.h
	$(YLWRAP) "$(LEX) $(AM_LEXFLAGS) $(LEXFLAGS)" \
                  $(srcdir)/rcfile.l lex.yy.c rcfile-lex.c \
                  -- -yy rc_yy

rcfile-gram.c rcfile-gram.h: $(srcdir)/rcfile.y
	$(YLWRAP) "$(YACC) $(AM_YFLAGS) $(YFLAGS)" $(srcdir)/rcfile.y \
	          y.tab.c rcfile-gram.c y.tab.h rcfile-gram.h \
                  y.output y.output \
                  -- -yy rc_yy

localedir = $(datadir)/locale

DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\"
INCLUDES = @INCLUDES@

## EOF

