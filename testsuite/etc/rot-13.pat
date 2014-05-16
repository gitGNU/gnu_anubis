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

:TEST ROT-13 support 
:MODE SPAWN
:OPTIONS --stdio
:RCFILE remail.rc
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
:DEL Subject: rot-13 test@@rot-13 subject
:ADD Subject: ebg-13 grfg
X-Comment: Anubis testsuite

In /users3 did Kubla Khan
A stately pleasure dome decree,
Where /bin, the sacred river ran
Through Test Suites measureless to Man
Down to a sunless C.
.
:EXPECT 250
MAIL FROM:<gray@gnu.org>
:EXPECT 250
RCPT TO:<polak@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <gray@gnu.org>
To: <polak@gnu.org>
:DEL Subject: rot-13 test@@rot-13 body
:ADD Subject: rot-13 test
X-Comment: Anubis testsuite

:DEL In /users3 did Kubla Khan
:DEL A stately pleasure dome decree,
:DEL Where /bin, the sacred river ran
:DEL Through Test Suites measureless to Man
:DEL Down to a sunless C.
:ADD Va /hfref3 qvq Xhoyn Xuna
:ADD N fgngryl cyrnfher qbzr qrperr,
:ADD Jurer /ova, gur fnperq evire ena
:ADD Guebhtu Grfg Fhvgrf zrnfheryrff gb Zna
:ADD Qbja gb n fhayrff P.
.
:EXPECT 250
MAIL FROM:<gray@gnu.org>
:EXPECT 250
RCPT TO:<polak@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <gray@gnu.org>
To: <polak@gnu.org>
:DEL Subject: rot-13 test@@rot-13 body subject
:ADD Subject: ebg-13 grfg
X-Comment: Anubis testsuite

:DEL In /users3 did Kubla Khan
:DEL A stately pleasure dome decree,
:DEL Where /bin, the sacred river ran
:DEL Through Test Suites measureless to Man
:DEL Down to a sunless C.
:ADD Va /hfref3 qvq Xhoyn Xuna
:ADD N fgngryl cyrnfher qbzr qrperr,
:ADD Jurer /ova, gur fnperq evire ena
:ADD Guebhtu Grfg Fhvgrf zrnfheryrff gb Zna
:ADD Qbja gb n fhayrff P.
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

