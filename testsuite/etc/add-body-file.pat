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

:TEST Appending a text file to the message body
:MODE SPAWN
:OPTIONS --stdio
:RCFILE add.rc
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
Subject: The Show Must Go On
X-Order: Append file

Empty spaces -- what are we living for
Abandoned places -- I guess we know the score
On and on, does anybody know what we are looking for...
Another hero, another mindless crime
:ADD Behind the curtain, in the pantomime
:ADD Hold the line, does anybody want to take it anymore
:ADD The show must go on,
:ADD The show must go on...
.
QUIT
:EXPECT 221
:END PATTERN
:END TEST
