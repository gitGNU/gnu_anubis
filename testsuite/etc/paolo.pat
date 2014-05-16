# This file is part of GNU Anubis testsuite.
# Copyright (C) 2005-2014 The Anubis Team.
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

# Anubis coredumped on `modify body' statements that shrunk the input
# strings.
# Reference: Reported by Paolo <oopla@users.sourceforge.net>. Messages
# causing coredump and relevant configuration files were sent privately
# to <gray@mirddin.farlep.net> on 2 Jan 2005 under message ID
# <20050101214820.GC6075@pp>

:TEST Removing substrings from the body
:MODE SPAWN
:OPTIONS --stdio
:RCFILE paolo.rc
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
Subject: Removing substrings from the body

:DEL X-Anomy: This string is removed entirely
:ADD 
This line is left untouched
:DEL This X-Paren(garbage)lineX-Paren(text) has some garX-Paren(or more)bage removed
:ADD This line has some garbage removed

Regards,
Sergey
.
QUIT
:EXPECT 221
:END PATTERN
:END TEST
