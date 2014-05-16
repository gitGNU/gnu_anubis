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

:TEST Removing headers from several messages 
:MODE SPAWN
:OPTIONS --stdio
:RCFILE del.rc
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
MAIL FROM:<gray@gnu.org>
:EXPECT 250
RCPT TO:<polak@gnu.org>
:EXPECT 250
DATA
:EXPECT 354
From: <gray@gnu.org>
To: <polak@gnu.org>
:DEL X-Subject: Test of header removal. Message 2.
Subject: The Tao of Programming, Part II
:DEL X-Part-Number: II

        A master was explaining the nature of the Tao to one of his novices,
"The Tao is embodied in all software -- regardless of how insignificant,"
said the master.
        "Is the Tao in a hand-held calculator?" asked the novice.
        "It is," came the reply.
        "Is the Tao in a video game?" continued the novice.
        "It is even in a video game," said the master.
        "And is the Tao in the DOS for a personal computer?"
        The master coughed and shifted his position slightly.  "The lesson is
over for today," he said.
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
Subject: The Tao of Programming, Part III

        A novice asked the Master: "Here is a programmer that never designs,
documents, or tests his programs.  Yet all who know him consider him one of
the best programmers in the world.  Why is this?"
        The Master replies: "That programmer has mastered the Tao.  He has
gone beyond the need for design; he does not become angry when the system
crashes, but accepts the universe without concern.  He has gone beyond the
need for documentation; he no longer cares if anyone else sees his code.  He
has gone beyond the need for testing; each of his programs are perfect within
themselves, serene and elegant, their purpose self-evident.  Truly, he has
entered the mystery of the Tao."
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST
