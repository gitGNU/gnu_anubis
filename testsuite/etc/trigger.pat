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

:TEST Trigger mechanism
:MODE SPAWN
:OPTIONS --stdio
:RCFILE trigger.rc
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
:DEL Subject: COME AS YOU ARE@@trigger1
:ADD Subject: COME AS YOU ARE
:ADD X-Trigger-Test: is the true path to nirvana...

Come as you are, as you were
As I want you to to be.
As a friend, as a friend
As an old enemy
Take your time
Hurry up, the choice is yours
Don't be late.
Take a rest, as a friend
As an old memoria...

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
:DEL Subject: YOU KNOW YOU'RE RIGHT@@trigger2 TEEN SPIRIT
:ADD Subject: YOU KNOW YOU'RE RIGHT
:ADD X-Trigger-Test: SMELLS LIKE TEEN SPIRIT

With the lights out, it's less dangerous
Here we are now, entertain us
I feel stupid, and contagious
Here we are now, entertain us

.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

