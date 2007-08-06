##
## This file is part of GNU Anubis.
## Copyright (C) 2003, 2007 The Anubis Team.
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

GPGFILES = secring.gpg pubring.gpg
noinst_DATA = @ANUBIS_GPGFILES@ text.db

EXTRA_DIST = pubring.asc secring.asc anubis.pem append.txt users
CLEANFILES = *.gpg random_seed *~ text.db

pubring.gpg secring.gpg: $(srcdir)/pubring.asc $(srcdir)/secring.asc
	$(GPG) --homedir . --import < $(srcdir)/pubring.asc
	$(GPG) --homedir . --allow-secret-key-import --import < $(srcdir)/secring.asc

text.db: $(srcdir)/users
	sed -e "`../findport -fs^USER^%u^`;s^ETCDIR^`cd ../etc;pwd`^" $(srcdir)/users > text.db
