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

:TEST Process a MIME encoded message (read-entire-body is set)
:MODE SPAWN
:OPTIONS --stdio
:RCFILE entire.rc
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
Received: from Mirddin.farlep.net (localhost [127.0.0.1]) 
	by Mirddin.farlep.net with ESMTP id g6CLhIb05086
	for <gray@mirddin.farlep.net>; Sat, 13 Jul 2002 00:43:18 +0300
Message-Id: <200207122143.g6CLhIb05086@Mirddin.farlep.net>
To: Foo Bar <foobar@nonexistent.net>
Subject: Simple MIME
MIME-Version: 1.0
Content-Type: multipart/mixed;
      boundary="----- =_aaaaaaaaaa0"
Content-ID: <5082.1026510189.0@Mirddin.farlep.net>
Date: Sat, 13 Jul 2002 00:43:18 +0300
From: Sergey Poznyakoff <gray@Mirddin.farlep.net>

------- =_aaaaaaaaaa0
Content-Type: text/plain; name="msg.1"; charset="us-ascii"
Content-ID: <5082.1026510189.1@Mirddin.farlep.net>
Content-Description: How doth

How doth the little crocodile
Improve his shining tail,
And pour the waters of the Nile
On every golden scale!

`How cheerfully he seems to grin,
How neatly spread his claws,
And welcome little fishes in
With gently smiling jaws!

------- =_aaaaaaaaaa0
Content-Type: application/octet-stream; name="msg.21"
Content-ID: <5082.1026510189.2@Mirddin.farlep.net>
Content-Description: Father William Part I
Content-Transfer-Encoding: base64

YFlvdSBhcmUgb2xkLCBGYXRoZXIgV2lsbGlhbSwnIHRoZSB5b3VuZyBtYW4gc2FpZCwKYEFuZCB5
b3VyIGhhaXIgaGFzIGJlY29tZSB2ZXJ5IHdoaXRlOwpBbmQgeWV0IHlvdSBpbmNlc3NhbnRseSBz
dGFuZCBvbiB5b3VyIGhlYWQtLQpEbyB5b3UgdGhpbmssIGF0IHlvdXIgYWdlLCBpdCBpcyByaWdo
dD8nCgpgSW4gbXkgeW91dGgsJyBGYXRoZXIgV2lsbGlhbSByZXBsaWVkIHRvIGhpcyBzb24sCmBJ
IGZlYXJlZCBpdCBtaWdodCBpbmp1cmUgdGhlIGJyYWluOwpCdXQsIG5vdyB0aGF0IEknbSBwZXJm
ZWN0bHkgc3VyZSBJIGhhdmUgbm9uZSwKV2h5LCBJIGRvIGl0IGFnYWluIGFuZCBhZ2Fpbi4nCgo=

------- =_aaaaaaaaaa0--
.
:EXPECT 250
QUIT
:EXPECT 221
:END PATTERN
:END TEST

