##
## src/Makefile.am
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

adm_sbin_programs = anubisadm 
adm_bin_programs = anubisusr
sbin_PROGRAMS = anubis @ANUBIS_SBIN_ADM@
bin_PROGRAMS = @ANUBIS_BIN_ADM@
EXTRA_PROGRAMS = $(adm_bin_programs) $(adm_sbin_programs)

noinst_LIBRARIES = libanubisdb.a
anubis_LDADD = ./libanubisdb.a $(top_builddir)/lib/libanubis.a\
 @LIBINTL@ $(GUILE_LIBS) @LIBGNUTLS_LIBS@ @GSASL_LIBS@ 

anubis_SOURCES = \
 auth.c \
 authmode.c \
 daemon.c \
 env.c \
 errs.c \
 esmtp.c \
 exec.c \
 extern.h \
 gpg.c \
 gsasl_srv.c \
 guile.c \
 headers.h \
 help.c \
 log.c \
 main.c \
 map.c \
 message.c \
 mime.c \
 misc.c \
 net.c \
 quit.c \
 rcfile.c \
 rcfile.h \
 rcfile-gram.c \
 rcfile-gram.h \
 rcfile-lex.c \
 regex.c \
 socks.c \
 transmode.c \
 tunnel.c \
 xdatabase.c 

anubisadm_SOURCES = anubisadm.c
anubisadm_LDADD = ./libanubisdb.a $(top_builddir)/lib/libanubis.a @LIBINTL@
anubisusr_SOURCES = anubisusr.c
anubisusr_LDADD = ./libanubisdb.a $(top_builddir)/lib/libanubis.a @LIBINTL@ @LIBGNUTLS_LIBS@ @GSASL_LIBS@ 

libanubisdb_a_SOURCES = \
 anubisdb.c \
 dbtext.c \
 gdbm.c \
 gsasl.c \
 list.c \
 list.h \
 mem.c \
 mem.h \
 mysql.c \
 pgsql.c \
 ssl.c \
 sql.h \
 sql.c \
 stream.c \
 tls.c \
 url.c 

YLWRAP = $(SHELL) $(top_srcdir)/build/ylwrap
AM_YFLAGS = -dtv
EXTRA_DIST = rcfile.y rcfile.l 

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
INCLUDES = @INCLUDES@ @LIBGNUTLS_CFLAGS@ -I$(top_srcdir)/lib \
	-I$(top_srcdir)/intl 

## EOF

