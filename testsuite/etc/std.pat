# This file is part of GNU Anubis testsuite.
# Copyright (C) 2003 The Anubis Team.
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
# along with GNU Anubis; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

:TEST parse
:MODE EXEC
:OPTIONS --check-config
:RCFILE std.rc
:RETCODE 0
:PATTERN
BEGIN SECTION CONTROL
  ASGN: logfile = anubis.log
  ASGN: remote-mta = localhost:25
  ASGN: ssl = yes
END SECTION CONTROL
BEGIN SECTION ALL
  ASGN: gpg-passphrase = PASSWORD
  ASGN: remove = ^Lines:
END SECTION ALL
BEGIN SECTION RULE
  COND: ^To:.*<?USERNAME@localhost>?
  IFTRUE:
    ASGN: modify = ^(.*)<?(USERNAME@)(.*)>?(.*) >> \1\2\3.ORG\4
  END COND
  COND: AND (^Subject: (.*),NOT (^Subject: URGENT))
  IFTRUE:
    ASGN: add = X-Comment: This message is not URGENT (\1).
    ASGN: add = X-Comment: GNU's Not Unix! (\1)
  END COND
  COND: ^X-Mailer: (.*)
  IFTRUE:
    ASGN: add = X-Comment: My love \1
    ASGN: modify = ^X-Mailer: >> X-Mailer: The lousy mailer \1
  END COND
  RULE: ^gpgd:(.*)
  BODY
    ASGN: add = X-GPG-Comment: Encrypted for \1
    ASGN: gpg-encrypt = \1
  END RULE
  COND: ^Subject: signature
  IFTRUE:
    ASGN: signature-file-append = yes
  END COND
  COND: ^Subject: clearmsg
  IFTRUE:
    ASGN: body-clear-append = src/hi.txt
    ASGN: external-body-processor = /usr/bin/formail
  END COND
  COND: ^Subject: external
  IFTRUE:
    ASGN: external-body-processor = /usr/bin/formail
  END COND
  COND: ^gpg-encrypt
  IFTRUE:
    ASGN: gpg-encrypt = USERNAME
  END COND
  COND: ^gpg-sign
  IFTRUE:
    ASGN: gpg-sign = yes
  END COND
  COND: ^Subject: gpg-all
  IFTRUE:
    ASGN: gpg-encrypt = USERNAME
    ASGN: gpg-sign = yes
  END COND
  COND: ^Subject: gpg-encrypt
  IFTRUE:
    ASGN: gpg-encrypt = USERNAME-1,USERNAME-2,USERNAME-3
  END COND
  COND: ^Subject: gpg-sign
  IFTRUE:
    ASGN: gpg-sign = yes
  END COND
  COND: ^ALL
  IFTRUE:
    ASGN: body-append = misc/notatki.txt
    ASGN: gpg-encrypt = USERNAME
    ASGN: gpg-sign = PASSWORD
    ASGN: rot13-subject = yes
    ASGN: ROT13-BODY = yes
  END COND
  COND: ^Subject: rot13-all
  IFTRUE:
    ASGN: rot13-subject = yes
    ASGN: rot13-body = yes
  END COND
  COND: ^Subject: rot13-body
  IFTRUE:
    ASGN: rot13-body = yes
  END COND
  COND: ^Subject: rot13-subject
  IFTRUE:
    ASGN: rot13-subject = yes
  END COND
  COND: ^Subject: rm-rrt
  IFTRUE:
    ASGN: rm-rrt = USERNAME@localhost
  END COND
  COND: ^Subject: rm-post
  IFTRUE:
    ASGN: rm-post = alt.unix
  END COND
  COND: ^Subject: rm-gpg
  IFTRUE:
    ASGN: rm-rrt = USERNAME@localhost
    ASGN: rm-gpg = USERNAME
  END COND
  COND: ^Subject: rm-all
  IFTRUE:
    ASGN: rm-rrt = USERNAME@tokyo.net
    ASGN: rm-header = EXTRA-Z1: TEST
  END COND
  COND: ^Subject: body-append
  IFTRUE:
    ASGN: body-append = misc/notatki.txt
  END COND
  COND: ^Subject: ALL
  IFTRUE:
    ASGN: body-append = misc/notatki.txt
    ASGN: gpg-encrypt = USERNAME
    ASGN: gpg-sign = PASSWORD
    ASGN: rot13-subject = yes
    ASGN: rot13-body = yes
  END COND
END SECTION RULE
:END PATTERN
:END TEST
