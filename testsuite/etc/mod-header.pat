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

:TEST Modifying the message header
:MODE SPAWN
:OPTIONS --stdio
:RCFILE mod-header.rc
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
:DEL Subject: Hybrid Theory
:ADD Subject: Meteora
:DEL X-Mailer: Fake MTA
:ADD X-Old-Mailer: Fake MTA
:DEL X-LP-InTheEnd: rocks
:ADD X-LP-Faint: rules!

I can't feel the way I did before
Don't turn your back on me
I won't be ignored
Time won't heal this damage anymore
Don't turn your back on me
I won't be ignored
.
:EXPECT 250
MAIL FROM:<polak@gnu.org>
:EXPECT 250
RCPT TO:<gray@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <polak@gnu.org>
To: <gray@gnu.org>
:DEL Subject: Renegades of Funk
:ADD Subject: [RATM & music] Renegades of Funk

No matter how hard you try,
you can't stop us now!
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST
