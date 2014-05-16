#!/bin/sh
#
# keygen.sh
#
# This file is part of GNU Anubis.
# Copyright (C) 2001-2014 The Anubis Team.
#
# GNU Anubis is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option)
# any later version.
#
# GNU Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
#

#
# This script creates a private key and a certificate using OpenSSL.
#

PEM="anubis.pem"

rm -f ${PEM} ${PEM}.1 ${PEM}.2
openssl req -newkey rsa:1024 -nodes -keyout ${PEM}.1 -x509 \
-days 365 -out ${PEM}.2
cat ${PEM}.1 >${PEM}
echo "" >>${PEM}
cat ${PEM}.2 >>${PEM}
rm -f ${PEM}.1 ${PEM}.2
exit 0

# EOF

