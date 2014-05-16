# This file is part of GNU Anubis testsuite.
# Copyright (C) 2003-2014 The Anubis Team.
#
# GNU Anubis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Anubis; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

:TEST GPG Signing & Encryption
:MODE SPAWN
:OPTIONS --stdio
:RCFILE gpg.rc
:RETCODE 0
:PATTERN
:EXPECT 220
HELO localhost		
:EXPECT 250
MAIL FROM:<polak@gnu.org>
:EXPECT 250
RCPT TO:<gray@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <polak@gnu.org>
To: <gray@gnu.org>
:DEL Subject: gpg-se test@@se:anubis:anubis
:ADD Subject: gpg-se test
:ADD X-GPG-Comment1: Encrypted for anubis
:ADD X-GPG-Comment2: Signed by anubis

:DEL If you can read this, then it is working.
:ADD -re -----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

:TEST
:MODE CAT
:OPTIONS $gpg_prog --homedir $ANUBIS_DATA_DIR --decrypt 
:PATTERN
-re .*encrypted with 1024-bit ELG-E key, ID E793A998, created 2003-02-20.*"GNU Anubis Team \(Anubis\) <anubis-dev@gnu.org>".*If you can read this, then it is working..*Signature made .* using DSA key ID DCE73402.*gpg: Good signature from "GNU Anubis Team \(Anubis\) <anubis-dev@gnu.org>".*Primary key fingerprint: 9D80 A493 F6C8 B63C FD84  E882 0DD5 03FB DCE7 3402
:END PATTERN
:END TEST
