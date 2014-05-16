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

:TEST GPG Clear Signing
:MODE SPAWN
:OPTIONS --stdio
:RCFILE gpg.rc
:RETCODE 0
:PATTERN
:EXPECT 220
HELO localhost		
:EXPECT 250
MAIL FROM:<gray@gnu.org>
:EXPECT 250
RCPT TO:<polak@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <gray@gnu.org>
To: <polak@gnu.org>
:DEL Subject: Signing messages@@sign:anubis
:ADD Subject: Signing messages
:ADD X-GPG-Comment: Signed by anubis

:ADD -----BEGIN PGP SIGNED MESSAGE-----
:ADD Hash: SHA1
:ADD 
If you can read this, then it is working.
:ADD -re -----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

:TEST
:MODE CAT
:OPTIONS $gpg_prog --homedir $ANUBIS_DATA_DIR --verify
:PATTERN
-re .*Signature made .* using DSA key ID DCE73402.*gpg: Good signature from "GNU Anubis Team \(Anubis\) <anubis-dev@gnu.org>".*Primary key fingerprint: 9D80 A493 F6C8 B63C FD84  E882 0DD5 03FB DCE7 3402
:END PATTERN
:END TEST
