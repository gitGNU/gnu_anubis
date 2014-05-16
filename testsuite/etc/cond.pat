# This file is part of GNU Anubis testsuite.
# Copyright (C) 2004-2014 The Anubis Team.
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

:TEST Testing conditional statements
:MODE SPAWN
:OPTIONS --stdio
:RCFILE cond.rc
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
Subject: Be like water
:ADD X-Processed-By: Anubis
:ADD X-Comment1: Rule1 OK
:ADD X-Comment2: Rule2 OK
:ADD X-Comment3: Rule3 OK

"Empty your mind, be formless. Shapeless, like water.
If you put water into a cup, it becomes the cup.
You put water into a bottle and it becomes the bottle.
You put it in a teapot it becomes the teapot.
Now, water can flow or it can crash. Be water my friend."

                                        -- Bruce Lee
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST
