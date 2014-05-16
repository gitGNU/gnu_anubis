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

:TEST Adding header
:MODE SPAWN
:OPTIONS --stdio
:RCFILE simple.rc
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
Subject: The Tao of Programming, Part I
:ADD X-Part-Number: I

        A manager went to his programmers and told them: "As regards to your
work hours: you are going to have to come in at nine in the morning and leave
at five in the afternoon."  At this, all of them became angry and several
resigned on the spot.
        So the manager said: "All right, in that case you may set your own
working hours, as long as you finish your projects on schedule."  The
programmers, now satisfied, began to come in a noon and work to the wee
hours of the morning.
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST
