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

:TEST Remailer support
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
:DEL Subject: Testing remailer support@@remail:comp.os.unix/2:00
:ADD Subject: Testing remailer support

:ADD ::
:ADD Anon-To: gray@localhost
:ADD Anon-Post-To: comp.os.unix 
:ADD Latent-Time: +2:00
:ADD ##
:ADD X-Processed-By: GNU Anubis & Remailer-I
:ADD 
USENET would be a better laboratory is there were
more labor and less oratory.
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

